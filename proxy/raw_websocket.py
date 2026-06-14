import os
import ssl
import base64
import struct
import asyncio
import socket as _socket

from typing import List, Optional, Tuple
from .config import proxy_config


_st_BB = struct.Struct('>BB')
_st_BBH = struct.Struct('>BBH')
_st_BBQ = struct.Struct('>BBQ')
_st_BB4s = struct.Struct('>BB4s')
_st_BBH4s = struct.Struct('>BBH4s')
_st_BBQ4s = struct.Struct('>BBQ4s')
_st_H = struct.Struct('>H')
_st_Q = struct.Struct('>Q')

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


class WsHandshakeError(Exception):
    def __init__(self, status_code: int, status_line: str,
                 headers: Optional[dict] = None, location: Optional[str] = None):
        self.status_code = status_code
        self.status_line = status_line
        self.headers = headers or {}
        self.location = location
        super().__init__(f"HTTP {status_code}: {status_line}")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)


# Pre-allocated mask key — WS mask only needs to be unpredictable on the wire;
# the payload is already AES-CTR encrypted so a fixed mask is safe and saves
# one os.urandom() syscall per frame on the hot path.
_MASK_KEY = os.urandom(4)
_MASK_KEY_INT = int.from_bytes(_MASK_KEY, 'big')


try:
    import tg_ws_proxy_rs
    _rust_xor_mask = tg_ws_proxy_rs.xor_mask
except ImportError:
    _rust_xor_mask = None


def _xor_mask(data: bytes, mask: bytes) -> bytes:
    """XOR data with a 4-byte repeating mask key (WS RFC 6455).

    Uses compiled Rust module if available, otherwise falls back to fast struct-based Python XOR.
    """
    if _rust_xor_mask is not None:
        return _rust_xor_mask(data, mask)

    n = len(data)
    if not n:
        return data
    # Unpack mask as one uint32
    m32 = struct.unpack('>I', mask)[0]
    out = bytearray(n)
    # Process 4 bytes at a time
    full, rem = divmod(n, 4)
    off = 0
    for _ in range(full):
        v = struct.unpack_from('>I', data, off)[0] ^ m32
        struct.pack_into('>I', out, off, v)
        off += 4
    # Handle remainder (0–3 bytes)
    for i in range(rem):
        out[off + i] = data[off + i] ^ mask[i]
    return bytes(out)


def set_sock_opts(transport, buffer_size):
    sock = transport.get_extra_info('socket')
    if sock is None:
        return
    
    try:
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass
    
    try:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, buffer_size)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF, buffer_size)
    except OSError:
        pass


class RawWebSocket:
    __slots__ = ('reader', 'writer', '_closed')

    OP_BINARY = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._closed = False

    @staticmethod
    async def connect(host: str, domain: str, timeout: float = 10.0,
                      path: str = '/apiws') -> 'RawWebSocket':
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=_ssl_ctx,
                                    server_hostname=domain),
            timeout=min(timeout, 10))
        
        set_sock_opts(writer.transport, proxy_config.buffer_size)

        ws_key = base64.b64encode(os.urandom(16)).decode()

        req = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {domain}\r\n'
            f'Upgrade: websocket\r\n'
            f'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Key: {ws_key}\r\n'
            f'Sec-WebSocket-Version: 13\r\n'
            f'Sec-WebSocket-Protocol: binary\r\n'
            f'\r\n'
        )
        writer.write(req.encode())
        await writer.drain()

        response_lines: list[str] = []
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(),
                                              timeout=timeout)
                if line in (b'\r\n', b'\n', b''):
                    break
                response_lines.append(
                    line.decode('utf-8', errors='replace').strip())
        except asyncio.TimeoutError:
            writer.close()
            raise

        if not response_lines:
            writer.close()
            raise WsHandshakeError(0, 'empty response')

        first_line = response_lines[0]
        parts = first_line.split(' ', 2)
        try:
            status_code = int(parts[1]) if len(parts) >= 2 else 0
        except ValueError:
            status_code = 0

        if status_code == 101:
            return RawWebSocket(reader, writer)

        headers: dict[str, str] = {}
        for hl in response_lines[1:]:
            if ':' in hl:
                k, v = hl.split(':', 1)
                headers[k.strip().lower()] = v.strip()

        writer.close()
        raise WsHandshakeError(status_code, first_line, headers,
                                location=headers.get('location'))

    async def send(self, data: bytes) -> None:
        """Write one binary WS frame; drain is managed by the bridge loop."""
        if self._closed:
            raise ConnectionError("WebSocket closed")
        self.writer.write(self._build_frame(self.OP_BINARY, data, mask=True))

    async def send_batch(self, parts: List[bytes]) -> None:
        """Write multiple binary WS frames in one go without intermediate drains."""
        if self._closed:
            raise ConnectionError("WebSocket closed")
        # Concatenate all frames into a single write call to minimise syscalls
        buf = bytearray()
        for part in parts:
            buf += self._build_frame(self.OP_BINARY, part, mask=True)
        self.writer.write(bytes(buf))

    async def recv(self) -> Optional[bytes]:
        while not self._closed:
            opcode, payload = await self._read_frame()

            if opcode == self.OP_CLOSE:
                self._closed = True
                try:
                    self.writer.write(self._build_frame(
                        self.OP_CLOSE,
                        payload[:2] if payload else b'', mask=True))
                    await self.writer.drain()
                except Exception:
                    pass
                return None

            if opcode == self.OP_PING:
                try:
                    self.writer.write(
                        self._build_frame(self.OP_PONG, payload, mask=True))
                    await self.writer.drain()
                except Exception:
                    pass
                continue

            if opcode == self.OP_PONG:
                continue

            if opcode in (0x1, 0x2):
                return payload
            continue
        return None

    async def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.writer.write(
                self._build_frame(self.OP_CLOSE, b'', mask=True))
            await self.writer.drain()
        except Exception:
            pass
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    @staticmethod
    def _build_frame(opcode: int, data: bytes, mask: bool = False) -> bytes:
        length = len(data)
        fb = 0x80 | opcode
        if not mask:
            if length < 126:
                return _st_BB.pack(fb, length) + data
            if length < 65536:
                return _st_BBH.pack(fb, 126, length) + data
            return _st_BBQ.pack(fb, 127, length) + data
        # Reuse the module-level mask key — payload is already AES-CTR encrypted
        mask_key = _MASK_KEY
        masked = _xor_mask(data, mask_key)
        if length < 126:
            return _st_BB4s.pack(fb, 0x80 | length, mask_key) + masked
        if length < 65536:
            return _st_BBH4s.pack(fb, 0x80 | 126, length, mask_key) + masked
        return _st_BBQ4s.pack(fb, 0x80 | 127, length, mask_key) + masked

    async def _read_frame(self) -> Tuple[int, bytes]:
        hdr = await self.reader.readexactly(2)
        opcode = hdr[0] & 0x0F
        length = hdr[1] & 0x7F
        if length == 126:
            length = _st_H.unpack(await self.reader.readexactly(2))[0]
        elif length == 127:
            length = _st_Q.unpack(await self.reader.readexactly(8))[0]
        if hdr[1] & 0x80:
            mask_key = await self.reader.readexactly(4)
            payload = await self.reader.readexactly(length)
            return opcode, _xor_mask(payload, mask_key)
        payload = await self.reader.readexactly(length)
        return opcode, payload