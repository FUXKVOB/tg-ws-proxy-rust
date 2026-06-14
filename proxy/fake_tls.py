from __future__ import annotations

import asyncio
import hmac
import hashlib
import os
import random
import struct
import time
import logging

from typing import Optional, Tuple
from .stats import stats


log = logging.getLogger('tg-mtproto-proxy')

TLS_RECORD_HANDSHAKE = 0x16
TLS_RECORD_CCS = 0x14
TLS_RECORD_APPDATA = 0x17

TLS_VERSION_10 = b'\x03\x01'
TLS_VERSION_12 = b'\x03\x03'
TLS_VERSION_13 = b'\x03\x04'

TIMESTAMP_TOLERANCE = 120

TLS_APPDATA_MAX = 16384


_CCS_FRAME = b'\x14\x03\x03\x00\x01\x01'

# --- TLS ClientHello / ServerHello structure offsets ---
# Layout after TLS record header (5 bytes) + hs type+len (3 bytes) + version (2 bytes):
#   [0..31]  random (32 bytes)
#   [32]     session_id_length (1 byte, value 0x20 = 32)
#   [33..64] session_id (32 bytes)
#   [65..67] cipher_suite + compression (3 bytes: 0x13 0x01 0x00)
#   [68..69] extensions_length (2 bytes)
#   [70..73] supported_versions ext header (4 bytes: 0x00 0x33 0x00 0x24)
#   [74..77] key_share ext header (4 bytes: 0x00 0x1d 0x00 0x20)
#   [78..109] key_share public key (32 bytes)
#   [110..115] psk_key_exchange_modes ext (6 bytes: 0x00 0x2b 0x00 0x02 0x03 0x04)

_TLS_RECORD_HDR_LEN = 5      # 0x16 0x03 0x03 <2-byte len>
_TLS_HS_HDR_LEN = 4          # type(1) + len(3)
_TLS_VERSION_LEN = 2         # 0x03 0x03
_TLS_RANDOM_OFFSET = _TLS_RECORD_HDR_LEN + _TLS_HS_HDR_LEN + _TLS_VERSION_LEN  # = 11
_TLS_RANDOM_LEN = 32
_TLS_SESSION_ID_LEN_OFFSET = _TLS_RANDOM_OFFSET + _TLS_RANDOM_LEN             # = 43
_TLS_SESSION_ID_OFFSET = _TLS_SESSION_ID_LEN_OFFSET + 1                       # = 44
_TLS_SESSION_ID_LEN = 32
_TLS_CIPHERSUITE_LEN = 3     # 0x13 0x01 0x00
_TLS_EXT_LEN_OFFSET = _TLS_SESSION_ID_OFFSET + _TLS_SESSION_ID_LEN + _TLS_CIPHERSUITE_LEN  # = 79
_TLS_EXT_HEADER_LEN = 2
_TLS_SUPPORTED_VERSIONS_OFF = _TLS_EXT_LEN_OFFSET + _TLS_EXT_HEADER_LEN       # = 81
_TLS_SUPPORTED_VERSIONS_HDR_LEN = 4  # 0x00 0x33 0x00 0x24
_TLS_KEY_SHARE_EXT_OFF = _TLS_SUPPORTED_VERSIONS_OFF + _TLS_SUPPORTED_VERSIONS_HDR_LEN  # = 85
_TLS_KEY_SHARE_HDR_LEN = 4   # 0x00 0x1d 0x00 0x20
_TLS_PUBKEY_OFF = _TLS_KEY_SHARE_EXT_OFF + _TLS_KEY_SHARE_HDR_LEN             # = 89
_TLS_PUBKEY_LEN = 32

_TLS_SH_RANDOM_OFF = _TLS_RANDOM_OFFSET     # = 11  (same layout as ClientHello)
_TLS_SH_SESSID_OFF = _TLS_SESSION_ID_OFFSET # = 44
_TLS_SH_PUBKEY_OFF = _TLS_PUBKEY_OFF        # = 89

_SERVER_HELLO_TEMPLATE = bytearray(
    b'\x16\x03\x03\x00\x7a'            # TLS record header
    b'\x02\x00\x00\x76'                # ServerHello type + length
    b'\x03\x03'                         # TLS 1.2
    + b'\x00' * _TLS_RANDOM_LEN        # server random
    + bytes([_TLS_SESSION_ID_LEN])      # session_id_length = 32
    + b'\x00' * _TLS_SESSION_ID_LEN    # session_id
    + b'\x13\x01\x00'                  # cipher suite TLS_AES_128_GCM + null compression
    + b'\x00\x2e'                      # extensions length
    + b'\x00\x33\x00\x24\x00\x1d\x00\x20'  # supported_versions + key_share headers
    + b'\x00' * _TLS_PUBKEY_LEN        # ephemeral public key
    + b'\x00\x2b\x00\x02\x03\x04'      # psk_key_exchange_modes
)


def verify_client_hello(data: bytes, secret: bytes) -> Optional[Tuple[bytes, bytes, int]]:
    n = len(data)
    # Minimum: 5 (record hdr) + 4 (hs type+len) + 2 (version) + 32 (random) = 43
    min_random_end = _TLS_RANDOM_OFFSET + _TLS_RANDOM_LEN
    if n < min_random_end:
        return None
    if data[0] != TLS_RECORD_HANDSHAKE:
        return None
    if data[5] != 0x01:
        return None

    client_random = bytes(data[_TLS_RANDOM_OFFSET:_TLS_RANDOM_OFFSET + _TLS_RANDOM_LEN])

    zeroed = bytearray(data)
    zeroed[_TLS_RANDOM_OFFSET:_TLS_RANDOM_OFFSET + _TLS_RANDOM_LEN] = b'\x00' * _TLS_RANDOM_LEN

    expected = hmac.new(secret, bytes(zeroed), hashlib.sha256).digest()

    if not hmac.compare_digest(expected[:28], client_random[:28]):
        return None

    ts_xor = bytes(client_random[28 + i] ^ expected[28 + i] for i in range(4))
    timestamp = struct.unpack('<I', ts_xor)[0]

    now = int(time.time())
    if abs(now - timestamp) > TIMESTAMP_TOLERANCE:
        return None

    session_id = b'\x00' * _TLS_SESSION_ID_LEN
    if n >= _TLS_SESSION_ID_OFFSET + _TLS_SESSION_ID_LEN and data[_TLS_SESSION_ID_LEN_OFFSET] == _TLS_SESSION_ID_LEN:
        session_id = bytes(data[_TLS_SESSION_ID_OFFSET:_TLS_SESSION_ID_OFFSET + _TLS_SESSION_ID_LEN])

    return client_random, session_id, timestamp


def build_server_hello(secret: bytes, client_random: bytes, session_id: bytes) -> bytes:
    sh = bytearray(_SERVER_HELLO_TEMPLATE)
    sh[_TLS_SH_SESSID_OFF:_TLS_SH_SESSID_OFF + _TLS_SESSION_ID_LEN] = session_id
    sh[_TLS_SH_PUBKEY_OFF:_TLS_SH_PUBKEY_OFF + _TLS_PUBKEY_LEN] = os.urandom(_TLS_PUBKEY_LEN)

    ccs = _CCS_FRAME
    encrypted_size = random.randint(1900, 2100)
    encrypted_data = os.urandom(encrypted_size)
    app_record = b'\x17\x03\x03' + struct.pack('>H', encrypted_size) + encrypted_data

    response = bytes(sh) + ccs + app_record

    hmac_input = client_random + response
    server_random = hmac.new(secret, hmac_input, hashlib.sha256).digest()

    final = bytearray(response)
    final[_TLS_SH_RANDOM_OFF:_TLS_SH_RANDOM_OFF + _TLS_RANDOM_LEN] = server_random

    return bytes(final)


def wrap_tls_record(data: bytes) -> bytes:
    parts = []
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + TLS_APPDATA_MAX]
        parts.append(
            b'\x17\x03\x03'
            + struct.pack('>H', len(chunk))
            + chunk
        )
        offset += len(chunk)
    return b''.join(parts)


class FakeTlsStream:
    __slots__ = ('_reader', '_writer', '_read_buf', '_read_left')

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer
        self._read_buf = bytearray()
        self._read_left = 0

    async def readexactly(self, n: int) -> bytes:
        while len(self._read_buf) < n:
            payload = await self._read_tls_payload()
            if not payload:
                raise asyncio.IncompleteReadError(bytes(self._read_buf), n)
            self._read_buf.extend(payload)
        result = bytes(self._read_buf[:n])
        del self._read_buf[:n]
        return result

    async def read(self, n: int) -> bytes:
        if self._read_buf:
            chunk = bytes(self._read_buf[:n])
            del self._read_buf[:n]
            return chunk
        payload = await self._read_tls_payload()
        if not payload:
            return b''
        if len(payload) > n:
            self._read_buf.extend(payload[n:])
            return payload[:n]
        return payload

    async def _read_tls_payload(self) -> bytes:
        if self._read_left > 0:
            data = await self._reader.read(self._read_left)
            if not data:
                return b''
            self._read_left -= len(data)
            return data

        while True:
            hdr = await self._reader.readexactly(5)
            rtype = hdr[0]
            rec_len = struct.unpack('>H', hdr[3:5])[0]

            if rtype == TLS_RECORD_CCS:
                if rec_len > 0:
                    await self._reader.readexactly(rec_len)
                continue

            if rtype != TLS_RECORD_APPDATA:
                return b''

            data = await self._reader.read(min(rec_len, 65536))
            if not data:
                return b''
            remaining = rec_len - len(data)
            if remaining > 0:
                self._read_left = remaining
            return data

    def write(self, data: bytes) -> None:
        self._writer.write(wrap_tls_record(data))

    async def drain(self) -> None:
        await self._writer.drain()

    def close(self) -> None:
        self._writer.close()

    async def wait_closed(self) -> None:
        await self._writer.wait_closed()

    def get_extra_info(self, name, default=None):
        return self._writer.get_extra_info(name, default)

    @property
    def transport(self):
        return self._writer.transport

    def is_closing(self):
        return self._writer.is_closing()


async def proxy_to_masking_domain(reader, writer, initial_data: bytes,
                                    domain: str, label: str) -> None:
    try:
        up_reader, up_writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443), timeout=10)
    except Exception as exc:
        log.warning("[%s] masking: cannot connect to %s:443: %s",
                  label, domain, repr(exc))
        return

    log.debug("[%s] masking -> %s:443", label, domain)
    stats.connections_masked += 1

    try:
        if initial_data:
            up_writer.write(initial_data)
            await up_writer.drain()

        async def _relay(src, dst):
            try:
                while True:
                    chunk = await src.read(16384)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError, OSError,
                    asyncio.CancelledError):
                pass
            finally:
                try:
                    dst.close()
                    await dst.wait_closed()
                except Exception:
                    pass

        await asyncio.gather(
            _relay(reader, up_writer),
            _relay(up_reader, writer),
        )
    except Exception:
        pass
    finally:
        try:
            up_writer.close()
        except Exception:
            pass
