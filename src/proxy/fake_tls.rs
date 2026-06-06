use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use sha2::Sha256;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proxy::STATS;

type HmacSha256 = Hmac<Sha256>;

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
pub const TLS_RECORD_CCS: u8 = 0x14;
pub const TLS_RECORD_APPDATA: u8 = 0x17;

const CLIENT_RANDOM_OFFSET: usize = 11;
const CLIENT_RANDOM_LEN: usize = 32;
const SESSION_ID_OFFSET: usize = 44;
const SESSION_ID_LEN: usize = 32;
const TIMESTAMP_TOLERANCE: i64 = 120;
const TLS_APPDATA_MAX: usize = 16384;

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

/// Verify TLS ClientHello with Fake TLS (ee-secret) protocol.
/// Returns (client_random, session_id, timestamp) on success.
pub fn verify_client_hello(
    data: &[u8],
    secret: &[u8],
) -> Option<([u8; 32], [u8; 32], i64)> {
    if data.len() < 43 {
        return None;
    }
    if data[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }
    if data[5] != 0x01 {
        return None;
    }

    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]);

    let mut zeroed = data.to_vec();
    zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN]
        .copy_from_slice(&[0u8; CLIENT_RANDOM_LEN]);

    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(&zeroed);
    let expected = mac.finalize().into_bytes();

    if !constant_time_eq(&expected[..28], &client_random[..28]) {
        return None;
    }

    let ts_xor: [u8; 4] = [
        client_random[28] ^ expected[28],
        client_random[29] ^ expected[29],
        client_random[30] ^ expected[30],
        client_random[31] ^ expected[31],
    ];
    let timestamp = i64::from_le_bytes([ts_xor[0], ts_xor[1], ts_xor[2], ts_xor[3], 0, 0, 0, 0]);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    if (now - timestamp).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }

    let mut session_id = [0u8; 32];
    if data.len() >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20 {
        session_id.copy_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]);
    }

    Some((client_random, session_id, timestamp))
}

/// Build ServerHello response for Fake TLS.
pub fn build_server_hello(
    secret: &[u8],
    client_random: &[u8; 32],
    session_id: &[u8; 32],
) -> Vec<u8> {
    // Template: TLS 1.3 ServerHello
    let mut sh = vec![
        0x16, 0x03, 0x03, 0x00, 0x7a, // record header
        0x02, 0x00, 0x00, 0x76, // handshake type + length
        0x03, 0x03, // version
    ];
    // random placeholder (32 bytes)
    sh.extend_from_slice(&[0u8; 32]);
    sh.push(0x20); // session_id length
    sh.extend_from_slice(session_id); // 32 bytes
    sh.extend_from_slice(&[
        0x13, 0x01, 0x00, // cipher suite
        0x00, 0x2e, // extensions length
        0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, // key_share
    ]);
    // public key placeholder (32 bytes)
    sh.extend_from_slice(&[0u8; 32]);
    sh.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions

    let sh_random_off = 11;
    let sh_pubkey_off = 89;

    // fill random public key
    let pubkey: [u8; 32] = rand::random();
    sh[sh_pubkey_off..sh_pubkey_off + 32].copy_from_slice(&pubkey);

    let mut response = sh.clone();
    response.extend_from_slice(&CCS_FRAME);

    let encrypted_size: usize = rand::rng().random_range(1900..2100);
    let encrypted_data: Vec<u8> = (0..encrypted_size).map(|_| rand::random()).collect();
    response.push(0x17);
    response.push(0x03);
    response.push(0x03);
    response.extend_from_slice(&(encrypted_size as u16).to_be_bytes());
    response.extend_from_slice(&encrypted_data);

    // HMAC the response with client_random to compute server_random
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(client_random);
    mac.update(&response);
    let server_random = mac.finalize().into_bytes();

    let mut final_response = response;
    final_response[sh_random_off..sh_random_off + 32].copy_from_slice(&server_random);
    final_response
}

/// Wrap data in TLS application data records.
pub fn wrap_tls_record(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len() + data.len() / TLS_APPDATA_MAX * 5 + 5);
    for chunk in data.chunks(TLS_APPDATA_MAX) {
        result.push(0x17);
        result.push(0x03);
        result.push(0x03);
        result.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        result.extend_from_slice(chunk);
    }
    result
}

/// Proxy connection to masking domain (when Fake TLS verification fails).
pub async fn proxy_to_masking_domain(
    mut client_reader: tokio::io::ReadHalf<TcpStream>,
    mut client_writer: tokio::io::WriteHalf<TcpStream>,
    initial_data: &[u8],
    domain: &str,
) {
    let up = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect((domain, 443)),
    )
    .await;

    let mut up_stream = match up {
        Ok(Ok(s)) => s,
        _ => return,
    };

    STATS.connections_masked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let _ = up_stream.set_nodelay(true);
    if !initial_data.is_empty() {
        let _ = up_stream.write_all(initial_data).await;
        let _ = up_stream.flush().await;
    }

    let (mut up_reader, mut up_writer) = up_stream.split();

    tokio::select! {
        _ = relay(&mut client_reader, &mut up_writer) => {},
        _ = relay(&mut up_reader, &mut client_writer) => {},
    }
}

async fn relay(
    src: &mut (impl AsyncReadExt + Unpin),
    dst: &mut (impl AsyncWriteExt + Unpin),
) {
    let mut buf = [0u8; 16384];
    loop {
        match src.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                if dst.flush().await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// Wraps a stream to transparently encode/decode TLS Application Data records.
///
/// Reading: strips 5-byte record headers (type 0x17 = AppData), returns raw payload.
/// Writing: wraps data in AppData records before passing to the inner writer.
pub struct FakeTlsStream<R, W> {
    reader: R,
    writer: W,
    buf: VecDeque<u8>,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> FakeTlsStream<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer, buf: VecDeque::new() }
    }

    pub fn into_inner(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for FakeTlsStream<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.buf.is_empty() {
            let n = buf.remaining().min(self.buf.len());
            for b in self.buf.drain(..n) {
                buf.put_slice(&[b]);
            }
            return Poll::Ready(Ok(()));
        }

        let mut hdr = [0u8; 5];
        let mut rb = tokio::io::ReadBuf::new(&mut hdr);
        match Pin::new(&mut self.reader).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) if rb.filled().len() < 5 => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "short TLS record header",
                )));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
            _ => {}
        }

        let record_type = hdr[0];
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut body = vec![0u8; len];
        let mut bb = tokio::io::ReadBuf::new(&mut body);
        match Pin::new(&mut self.reader).poll_read(cx, &mut bb) {
            Poll::Ready(Ok(())) if bb.filled().len() < len => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "short TLS record body",
                )));
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
            _ => {}
        }

        match record_type {
            0x17 => {
                let n = buf.remaining().min(len);
                buf.put_slice(&body[..n]);
                if n < len {
                    self.buf.extend(&body[n..]);
                }
                Poll::Ready(Ok(()))
            }
            0x14 => {
                self.poll_read(cx, buf)
            }
            _ => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected TLS record type 0x{:02X}", record_type),
            ))),
        }
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for FakeTlsStream<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let wrapped = wrap_tls_record(buf);
        Pin::new(&mut self.writer).poll_write(cx, &wrapped)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b) {
        result |= x ^ y;
    }
    result == 0
}
