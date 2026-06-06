use rand::Rng;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_native_tls::TlsConnector;

use crate::proxy::crypto::xor_mask;

type TlsHalf = tokio::io::ReadHalf<tokio_native_tls::TlsStream<TcpStream>>;

fn tls_connector() -> TlsConnector {
    let mut builder = native_tls::TlsConnector::builder();
    builder.danger_accept_invalid_certs(true);
    TlsConnector::from(builder.build().unwrap())
}

#[derive(Debug)]
pub struct WsHandshakeError {
    pub status_code: u16,
    pub status_line: String,
    pub location: Option<String>,
}

impl WsHandshakeError {
    pub fn is_redirect(&self) -> bool {
        matches!(self.status_code, 301 | 302 | 303 | 307 | 308)
    }
}

impl std::fmt::Display for WsHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {}: {}", self.status_code, self.status_line)
    }
}

impl std::error::Error for WsHandshakeError {}

pub struct RawWebSocket {
    reader: BufReader<TlsHalf>,
    writer: tokio::io::WriteHalf<tokio_native_tls::TlsStream<TcpStream>>,
    closed: bool,
}

impl RawWebSocket {
    pub async fn connect(
        host: &str,
        domain: &str,
        timeout: std::time::Duration,
        path: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect((host, 443))).await??;
        stream.set_nodelay(true)?;

        let connector = tls_connector();
        let tls_stream =
            tokio::time::timeout(timeout, connector.connect(domain, stream)).await??;

        let (reader, writer) = tokio::io::split(tls_stream);
        let mut reader = BufReader::new(reader);

        let ws_key = {
            let mut bytes = [0u8; 16];
            rand::rng().fill_bytes(&mut bytes);
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
        };

        let req = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {domain}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {ws_key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: binary\r\n\
             \r\n"
        );

        let mut writer = writer;
        writer.write_all(req.as_bytes()).await?;
        writer.flush().await?;

        let mut response_lines = Vec::new();
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(timeout, reader.read_line(&mut line)).await??;
            if n == 0 || line.trim().is_empty() {
                break;
            }
            response_lines.push(line.trim().to_string());
        }

        if response_lines.is_empty() {
            return Err("empty response".into());
        }

        let first_line = &response_lines[0];
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        let status_code: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

        if status_code == 101 {
            return Ok(Self {
                reader,
                writer,
                closed: false,
            });
        }

        let location = response_lines[1..]
            .iter()
            .find_map(|line| {
                let mut parts = line.splitn(2, ':');
                let key = parts.next()?.trim().to_lowercase();
                if key == "location" {
                    Some(parts.next()?.trim().to_string())
                } else {
                    None
                }
            });

        Err(WsHandshakeError {
            status_code,
            status_line: first_line.clone(),
            location,
        }
        .into())
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.closed {
            return Err("WebSocket closed".into());
        }
        let frame = build_frame(0x2, data, true);
        self.writer.write_all(&frame).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn send_batch(
        &mut self,
        parts: &[Vec<u8>],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.closed {
            return Err("WebSocket closed".into());
        }
        for part in parts {
            let frame = build_frame(0x2, part, true);
            self.writer.write_all(&frame).await?;
        }
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let (opcode, payload) = read_frame(&mut self.reader).await?;

            match opcode {
                0x8 => {
                    self.closed = true;
                    let close_frame = build_frame(0x8, &payload[..payload.len().min(2)], true);
                    let _ = self.writer.write_all(&close_frame).await;
                    let _ = self.writer.flush().await;
                    return Ok(None);
                }
                0x9 => {
                    let pong = build_frame(0xA, &payload, true);
                    let _ = self.writer.write_all(&pong).await;
                    let _ = self.writer.flush().await;
                    continue;
                }
                0xA => continue,
                0x1 | 0x2 => return Ok(Some(payload)),
                _ => continue,
            }
        }
    }

    pub async fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        let frame = build_frame(0x8, &[], true);
        let _ = self.writer.write_all(&frame).await;
        let _ = self.writer.flush().await;
        let _ = self.writer.shutdown().await;
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
}

pub fn build_frame(opcode: u8, data: &[u8], mask: bool) -> Vec<u8> {
    let len = data.len();
    let mut frame = Vec::with_capacity(10 + len);
    frame.push(0x80 | opcode);

    if mask {
        let mask_key: [u8; 4] = rand::random();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len < 65536 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask_key);
        frame.extend_from_slice(&xor_mask(data, &mask_key));
    } else {
        if len < 126 {
            frame.push(len as u8);
        } else if len < 65536 {
            frame.push(126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(data);
    }
    frame
}

pub async fn read_frame(
    reader: &mut BufReader<TlsHalf>,
) -> Result<(u8, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let mut hdr = [0u8; 2];
    reader.read_exact(&mut hdr).await?;
    let opcode = hdr[0] & 0x0F;
    let mut length = (hdr[1] & 0x7F) as u64;

    if length == 126 {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;
        length = u16::from_be_bytes(buf) as u64;
    } else if length == 127 {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).await?;
        length = u64::from_be_bytes(buf);
    }

    let payload = if hdr[1] & 0x80 != 0 {
        let mut mask_key = [0u8; 4];
        reader.read_exact(&mut mask_key).await?;
        let mut data = vec![0u8; length as usize];
        reader.read_exact(&mut data).await?;
        xor_mask(&data, &mask_key)
    } else {
        let mut data = vec![0u8; length as usize];
        reader.read_exact(&mut data).await?;
        data
    };

    Ok((opcode, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_frame() {
        let data = b"hello";
        let frame = build_frame(0x2, data, true);
        assert!(frame.len() > data.len());
        assert_eq!(frame[0] & 0x0F, 0x2);
        assert!(frame[1] & 0x80 != 0);
    }

    #[test]
    fn test_build_frame_unmasked() {
        let data = b"hello";
        let frame = build_frame(0x2, data, false);
        assert_eq!(frame[0] & 0x0F, 0x2);
        assert!(frame[1] & 0x80 == 0);
        assert_eq!(&frame[2..], data);
    }
}
