use aes::cipher::StreamCipher;
use std::sync::atomic::Ordering;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proxy::handshake::{CryptoContext, MsgSplitter};
use crate::proxy::raw_websocket::RawWebSocket;
use crate::proxy::STATS;

pub async fn bridge_ws_reencrypt_halves<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    ws: &mut RawWebSocket,
    ctx: &mut CryptoContext,
    splitter: &mut Option<MsgSplitter>,
) {
    let mut buf = [0u8; 65536];

    loop {
        tokio::select! {
            result = reader.read(&mut buf) => {
                let n = match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                STATS.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                ctx.clt_dec.apply_keystream(&mut buf[..n]);
                ctx.tg_enc.apply_keystream(&mut buf[..n]);

                if let Some(sp) = splitter {
                    let parts = sp.split(&buf[..n]);
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
}

pub async fn bridge_tcp_reencrypt(
    mut client: TcpStream,
    mut remote: TcpStream,
    ctx: &mut CryptoContext,
) {
    let (mut cr, mut cw) = client.split();
    let (mut rr, mut rw) = remote.split();
    let mut cbuf = [0u8; 65536];
    let mut rbuf = [0u8; 65536];

    loop {
        tokio::select! {
            result = cr.read(&mut cbuf) => {
                let n = match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
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
}

pub async fn bridge_ws_reencrypt(
    tcp: TcpStream,
    ws: &mut RawWebSocket,
    ctx: &mut CryptoContext,
    splitter: &mut Option<MsgSplitter>,
) {
    let (reader, writer) = tokio::io::split(tcp);
    bridge_ws_reencrypt_halves(reader, writer, ws, ctx, splitter).await;
}
