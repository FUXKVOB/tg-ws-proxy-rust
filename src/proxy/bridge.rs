use aes::cipher::StreamCipher;
use std::sync::atomic::Ordering;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proxy::handshake::{CryptoContext, MsgSplitter};
use crate::proxy::raw_websocket::RawWebSocket;
use crate::proxy::STATS;

pub struct SessionStats {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub packets_up: u64,
    pub packets_down: u64,
}

impl SessionStats {
    pub fn new() -> Self {
        Self { bytes_up: 0, bytes_down: 0, packets_up: 0, packets_down: 0 }
    }
}

impl Default for SessionStats {
    fn default() -> Self {
        Self::new()
    }
}

pub trait WsTransport {
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send;
    fn send_batch(&mut self, parts: &[Vec<u8>]) -> impl std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send;
    fn recv(&mut self) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>>> + Send;
    fn close(&mut self) -> impl std::future::Future<Output = ()> + Send;
}

impl WsTransport for RawWebSocket {
    async fn send(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send(data).await
    }

    async fn send_batch(&mut self, parts: &[Vec<u8>]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_batch(parts).await
    }

    async fn recv(&mut self) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        self.recv().await
    }

    async fn close(&mut self) {
        self.close().await
    }
}

pub async fn bridge_ws_reencrypt_halves<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    ws: &mut impl WsTransport,
    ctx: &mut CryptoContext,
    splitter: &mut Option<MsgSplitter>,
) -> SessionStats {
    let mut buf = [0u8; 65536];
    let mut s = SessionStats::new();

    loop {
        tokio::select! {
            result = reader.read(&mut buf) => {
                let n = match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                s.bytes_up += n as u64;
                s.packets_up += 1;
                STATS.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                ctx.clt_dec.apply_keystream(&mut buf[..n]);
                ctx.tg_enc.apply_keystream(&mut buf[..n]);

                if let Some(sp) = splitter {
                    let parts = sp.split(&buf[..n]);
                    s.packets_up += parts.len() as u64 - 1;
                    if ws.send_batch(&parts).await.is_err() {
                        break;
                    }
                } else {
                    if ws.send(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
            result = ws.recv() => {
                match result {
                    Ok(Some(mut data)) => {
                        let n = data.len() as u64;
                        s.bytes_down += n;
                        s.packets_down += 1;
                        STATS.bytes_down.fetch_add(n, Ordering::Relaxed);
                        ctx.tg_dec.apply_keystream(&mut data);
                        ctx.clt_enc.apply_keystream(&mut data);
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                        if writer.flush().await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        }
    }

    ws.close().await;
    s
}

pub async fn bridge_tcp_reencrypt(
    mut client: TcpStream,
    mut remote: TcpStream,
    ctx: &mut CryptoContext,
) -> SessionStats {
    let (mut cr, mut cw) = client.split();
    let (mut rr, mut rw) = remote.split();
    let mut cbuf = [0u8; 65536];
    let mut rbuf = [0u8; 65536];
    let mut s = SessionStats::new();

    loop {
        tokio::select! {
            result = cr.read(&mut cbuf) => {
                let n = match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                s.bytes_up += n as u64;
                s.packets_up += 1;
                STATS.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                ctx.clt_dec.apply_keystream(&mut cbuf[..n]);
                ctx.tg_enc.apply_keystream(&mut cbuf[..n]);
                if rw.write_all(&cbuf[..n]).await.is_err() {
                    break;
                }
                if rw.flush().await.is_err() {
                    break;
                }
            }
            result = rr.read(&mut rbuf) => {
                let n = match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                s.bytes_down += n as u64;
                s.packets_down += 1;
                STATS.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                ctx.tg_dec.apply_keystream(&mut rbuf[..n]);
                ctx.clt_enc.apply_keystream(&mut rbuf[..n]);
                if cw.write_all(&rbuf[..n]).await.is_err() {
                    break;
                }
                if cw.flush().await.is_err() {
                    break;
                }
            }
        }
    }

    let _ = cw.shutdown().await;
    let _ = rw.shutdown().await;
    s
}

pub async fn bridge_ws_reencrypt(
    tcp: TcpStream,
    ws: &mut RawWebSocket,
    ctx: &mut CryptoContext,
    splitter: &mut Option<MsgSplitter>,
) -> SessionStats {
    let (reader, writer) = tokio::io::split(tcp);
    bridge_ws_reencrypt_halves(reader, writer, ws, ctx, splitter).await
}
