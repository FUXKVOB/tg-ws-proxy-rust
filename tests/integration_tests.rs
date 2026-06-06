use std::time::Duration;
use aes::cipher::StreamCipher;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tg_ws_proxy::proxy::bridge::{bridge_ws_reencrypt_halves, SessionStats, WsTransport};
use tg_ws_proxy::proxy::crypto::aes_ctr_new;
use tg_ws_proxy::proxy::handshake::{generate_relay_init, CryptoContext, MsgSplitter};
use tg_ws_proxy::proxy::raw_websocket::build_frame;

const ZERO_64: [u8; 64] = [0u8; 64];

struct MockWsServer {
    reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
}

impl MockWsServer {
    fn new() -> (Self, tokio::io::DuplexStream) {
        let (server, client) = tokio::io::duplex(65536);
        let (reader, writer) = tokio::io::split(server);
        (Self { reader, writer }, client)
    }

    async fn send_ws_frame(&mut self, data: &[u8]) {
        let frame = build_frame(0x2, data, false);
        self.writer.write_all(&frame).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    async fn recv_ws_frame(&mut self) -> Vec<u8> {
        let mut hdr = [0u8; 2];
        self.reader.read_exact(&mut hdr).await.unwrap();
        let mut length = (hdr[1] & 0x7F) as u64;
        if length == 126 {
            let mut buf = [0u8; 2];
            self.reader.read_exact(&mut buf).await.unwrap();
            length = u16::from_be_bytes(buf) as u64;
        } else if length == 127 {
            let mut buf = [0u8; 8];
            self.reader.read_exact(&mut buf).await.unwrap();
            length = u64::from_be_bytes(buf);
        }
        let mut data = vec![0u8; length as usize];
        self.reader.read_exact(&mut data).await.unwrap();
        data
    }

    async fn send_close(&mut self) {
        let frame = build_frame(0x8, &[], false);
        let _ = self.writer.write_all(&frame).await;
        let _ = self.writer.flush().await;
    }
}

struct WsClientTransport {
    reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    closed: bool,
}

impl WsClientTransport {
    fn new(stream: tokio::io::DuplexStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self { reader, writer, closed: false }
    }
}

impl WsTransport for WsClientTransport {
    async fn send(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let frame = build_frame(0x2, data, true);
        self.writer.write_all(&frame).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn send_batch(&mut self, parts: &[Vec<u8>]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for part in parts {
            let frame = build_frame(0x2, part, true);
            self.writer.write_all(&frame).await?;
        }
        self.writer.flush().await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let mut hdr = [0u8; 2];
            self.reader.read_exact(&mut hdr).await?;
            let opcode = hdr[0] & 0x0F;
            let mut length = (hdr[1] & 0x7F) as u64;
            if length == 126 {
                let mut buf = [0u8; 2];
                self.reader.read_exact(&mut buf).await?;
                length = u16::from_be_bytes(buf) as u64;
            } else if length == 127 {
                let mut buf = [0u8; 8];
                self.reader.read_exact(&mut buf).await?;
                length = u64::from_be_bytes(buf);
            }
            let mut data = vec![0u8; length as usize];
            self.reader.read_exact(&mut data).await?;
            match opcode {
                0x8 => { self.closed = true; return Ok(None); }
                0x9 => continue,
                0x1 | 0x2 => return Ok(Some(data)),
                _ => continue,
            }
        }
    }

    async fn close(&mut self) {
        if self.closed { return; }
        self.closed = true;
        let frame = build_frame(0x8, &[], true);
        let _ = self.writer.write_all(&frame).await;
        let _ = self.writer.flush().await;
    }
}

#[tokio::test]
async fn test_bridge_ws_simple_flow() {
    let ri = generate_relay_init(&[0xee, 0xee, 0xee, 0xee], 2);
    let key = &ri[8..40];
    let iv = &ri[40..56];
    let mut ctx = CryptoContext {
        clt_dec: aes_ctr_new(key, iv),
        clt_enc: aes_ctr_new(key, iv),
        tg_enc: aes_ctr_new(key, iv),
        tg_dec: aes_ctr_new(key, iv),
    };

    let (mut ws_server, ws_client_stream) = MockWsServer::new();
    let mut ws_transport = WsClientTransport::new(ws_client_stream);
    let (proxy_tcp, mut tcp_client) = tokio::io::duplex(65536);
    let (tcp_read, tcp_write) = tokio::io::split(proxy_tcp);

    let ws = tokio::spawn(async move {
        let _ = ws_server.recv_ws_frame().await;
        ws_server.send_close().await;
    });

    let tcp = tokio::spawn(async move {
        tcp_client.write_all(b"hello").await.unwrap();
        let _ = tcp_client.shutdown().await;
    });

    let stats = tokio::time::timeout(
        Duration::from_secs(5),
        bridge_ws_reencrypt_halves(tcp_read, tcp_write, &mut ws_transport, &mut ctx, &mut None),
    ).await.expect("bridge should complete within 5s");

    ws.await.unwrap();
    tcp.await.unwrap();
    assert!(stats.packets_up >= 1, "packets_up >= 1, got {}", stats.packets_up);
    assert_eq!(stats.packets_down, 0, "no WS responses");
}

#[tokio::test]
async fn test_bridge_ws_end_to_end() {
    let ri = generate_relay_init(&[0xee, 0xee, 0xee, 0xee], 2);
    let key = &ri[8..40];
    let iv = &ri[40..56];
    let mut ctx = CryptoContext {
        clt_dec: aes_ctr_new(key, iv),
        clt_enc: aes_ctr_new(key, iv),
        tg_enc: aes_ctr_new(key, iv),
        tg_dec: aes_ctr_new(key, iv),
    };

    let (mut ws_server, ws_client_stream) = MockWsServer::new();
    let mut ws_transport = WsClientTransport::new(ws_client_stream);
    let (proxy_tcp, mut tcp_client) = tokio::io::duplex(65536);
    let (tcp_read, tcp_write) = tokio::io::split(proxy_tcp);

    let ws_handle = tokio::spawn(async move {
        let _ = ws_server.recv_ws_frame().await;
        ws_server.send_ws_frame(b"RESP").await;
        ws_server.send_close().await;
    });

    let client_handle = tokio::spawn(async move {
        tcp_client.write_all(b"PING").await.unwrap();
        let mut buf = [0u8; 32];
        let n = tcp_client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"RESP");
    });

    let stats = tokio::time::timeout(
        Duration::from_secs(5),
        bridge_ws_reencrypt_halves(tcp_read, tcp_write, &mut ws_transport, &mut ctx, &mut None),
    ).await.expect("bridge should complete within 5s");

    ws_handle.await.unwrap();
    client_handle.await.unwrap();

    assert!(stats.packets_up >= 1, "packets_up >= 1, got {}", stats.packets_up);
    assert_eq!(stats.packets_down, 1, "one WS responses");
}

#[test]
fn test_crypto_roundtrip() {
    let relay_init = generate_relay_init(&[0xee, 0xee, 0xee, 0xee], 2);
    let key = &relay_init[8..40];
    let iv = &relay_init[40..56];

    let mut enc = aes_ctr_new(key, iv);
    let mut dec = aes_ctr_new(key, iv);

    let original = b"Hello MTProto!";
    let mut encrypted = original.to_vec();
    enc.apply_keystream(&mut encrypted);
    dec.apply_keystream(&mut encrypted);
    assert_eq!(&encrypted, original, "encrypt/decrypt roundtrip with same key/iv");
}

#[test]
fn test_ws_frame_splitter_single_packet() {
    let relay_init = generate_relay_init(&[0xee, 0xee, 0xee, 0xee], 2);
    let mut splitter = MsgSplitter::new(&relay_init, 0xEEEEEEEE);

    let payload = vec![0x42u8; 64];
    let mut plain = Vec::with_capacity(4 + payload.len());
    plain.extend_from_slice(&(payload.len() as u32 | 0x8000_0000).to_le_bytes());
    plain.extend_from_slice(&payload);

    let key = &relay_init[8..40];
    let iv = &relay_init[40..56];
    let mut enc = aes_ctr_new(key, iv);
    enc.apply_keystream(&mut ZERO_64.to_vec());
    let mut encrypted = plain.clone();
    enc.apply_keystream(&mut encrypted);

    let parts = splitter.split(&encrypted);
    assert_eq!(parts.len(), 1, "should produce a single part, got {}", parts.len());
    assert_eq!(parts[0].len(), 4 + payload.len(), "full packet with header");
}

#[tokio::test]
async fn test_concurrent_ws_bridges() {
    let mut handles = Vec::new();

    for _ in 0..5 {
        let ri = generate_relay_init(&[0xee, 0xee, 0xee, 0xee], 2);
        let key = &ri[8..40];
        let iv = &ri[40..56];
        let mut ctx = CryptoContext {
            clt_dec: aes_ctr_new(key, iv),
            clt_enc: aes_ctr_new(key, iv),
            tg_enc: aes_ctr_new(key, iv),
            tg_dec: aes_ctr_new(key, iv),
        };

        let (mut ws_server, ws_client_stream) = MockWsServer::new();
        let mut ws_transport = WsClientTransport::new(ws_client_stream);
        let (proxy_tcp, mut tcp_client) = tokio::io::duplex(65536);
        let (tcp_read, tcp_write) = tokio::io::split(proxy_tcp);

        let h_ws = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            let _ = ws_server.recv_ws_frame().await;
            ws_server.send_ws_frame(b"ok").await;
            ws_server.send_close().await;
        });
        handles.push(h_ws);

        let h_tcp = tokio::spawn(async move {
            tcp_client.write_all(b"data").await.unwrap();
            let mut buf = [0u8; 16];
            let _ = tcp_client.read(&mut buf).await;
        });
        handles.push(h_tcp);

        let h_bridge = tokio::spawn(async move {
            let _stats = bridge_ws_reencrypt_halves(tcp_read, tcp_write, &mut ws_transport, &mut ctx, &mut None).await;
        });
        handles.push(h_bridge);
    }

    for h in handles {
        let _ = tokio::time::timeout(Duration::from_secs(10), h).await;
    }
}

#[test]
fn test_session_stats_defaults() {
    let s = SessionStats::new();
    assert_eq!(s.bytes_up, 0);
    assert_eq!(s.bytes_down, 0);
    assert_eq!(s.packets_up, 0);
    assert_eq!(s.packets_down, 0);
    let s: SessionStats = Default::default();
    assert_eq!(s.bytes_up, 0);
}

#[tokio::test]
async fn test_stress_20_concurrent_bridges() {
    let mut handles = Vec::new();
    for _ in 0..20 {
        let ri = generate_relay_init(&[0xee, 0xee, 0xee, 0xee], 2);
        let key = &ri[8..40];
        let iv = &ri[40..56];
        let mut ctx = CryptoContext {
            clt_dec: aes_ctr_new(key, iv),
            clt_enc: aes_ctr_new(key, iv),
            tg_enc: aes_ctr_new(key, iv),
            tg_dec: aes_ctr_new(key, iv),
        };

        let (mut ws_server, ws_client_stream) = MockWsServer::new();
        let mut ws_transport = WsClientTransport::new(ws_client_stream);
        let (proxy_tcp, mut tcp_client) = tokio::io::duplex(65536);
        let (tcp_read, tcp_write) = tokio::io::split(proxy_tcp);

        handles.push(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = ws_server.recv_ws_frame().await;
            ws_server.send_ws_frame(b"ok").await;
            ws_server.send_close().await;
        }));

        handles.push(tokio::spawn(async move {
            tcp_client.write_all(b"x").await.unwrap();
            let mut buf = [0u8; 8];
            let _ = tcp_client.read(&mut buf).await;
        }));

        handles.push(tokio::spawn(async move {
            let _stats = bridge_ws_reencrypt_halves(tcp_read, tcp_write, &mut ws_transport, &mut ctx, &mut None).await;
        }));
    }
    for h in handles {
        let _ = tokio::time::timeout(Duration::from_secs(15), h).await;
    }
}
