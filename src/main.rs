use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::sync::watch;

use clap::Parser;
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use cipher::StreamCipher;
use tg_ws_proxy::proxy::balancer::BALANCER;
use tg_ws_proxy::proxy::bridge::bridge_ws_reencrypt_halves;
use tg_ws_proxy::proxy::config::{self, PROXY_CONFIG};
use tg_ws_proxy::proxy::fake_tls::{build_server_hello, verify_client_hello, FakeTlsStream, TLS_RECORD_HANDSHAKE};
use tg_ws_proxy::proxy::handshake::{
    build_crypto_ctx, generate_relay_init, try_handshake, CryptoContext, MsgSplitter,
};
use tg_ws_proxy::proxy::pool::{CF_WORKER_POOL, WS_POOL};
use tg_ws_proxy::proxy::raw_websocket::{RawWebSocket, WsHandshakeError};
use tg_ws_proxy::proxy::utils::*;
use tg_ws_proxy::proxy::STATS;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const DC_FAIL_COOLDOWN: f64 = 30.0;
const WS_FAIL_TIMEOUT: f64 = 2.0;

static DC_FAIL_UNTIL: std::sync::OnceLock<std::sync::RwLock<HashMap<String, Instant>>> =
    std::sync::OnceLock::new();
static WS_BLACKLIST: std::sync::OnceLock<std::sync::RwLock<HashSet<String>>> =
    std::sync::OnceLock::new();

fn dc_fail_until() -> &'static std::sync::RwLock<HashMap<String, Instant>> {
    DC_FAIL_UNTIL.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

fn ws_blacklist() -> &'static std::sync::RwLock<HashSet<String>> {
    WS_BLACKLIST.get_or_init(|| std::sync::RwLock::new(HashSet::new()))
}

#[derive(Parser)]
#[command(name = "tg-ws-proxy", about = "Telegram MTProto WebSocket Bridge Proxy")]
struct Cli {
    #[arg(long, default_value = "1443")]
    port: u16,

    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    #[arg(long)]
    secret: Option<String>,

    #[arg(long = "dc-ip", value_name = "DC:IP")]
    dc_ip: Vec<String>,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long)]
    log_file: Option<String>,

    #[arg(long = "buf-kb", default_value = "256")]
    buf_kb: usize,

    #[arg(long = "pool-size", default_value = "4")]
    pool_size: usize,

    #[arg(long = "cfproxy-domain")]
    cfproxy_domain: Vec<String>,

    #[arg(long = "cfproxy-worker-domain")]
    cfproxy_worker_domain: Vec<String>,

    #[arg(long = "no-cfproxy")]
    no_cfproxy: bool,

    #[arg(long = "fake-tls-domain", default_value = "")]
    fake_tls_domain: String,

    #[arg(long = "proxy-protocol")]
    proxy_protocol: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Cli::parse();

    if args.verbose {
        unsafe { std::env::set_var("RUST_LOG", "debug"); }
    }

    let dc_redirects = if args.dc_ip.is_empty() {
        HashMap::from([
            (2u32, "149.154.167.220".to_string()),
            (4u32, "149.154.167.220".to_string()),
        ])
    } else {
        config::parse_dc_ip_list(&args.dc_ip).unwrap_or_else(|e| {
            error!("{}", e);
            std::process::exit(1);
        })
    };

    let secret_hex = if let Some(s) = &args.secret {
        if s.len() != 32 {
            error!("Secret must be exactly 32 hex characters");
            std::process::exit(1);
        }
        if hex::decode(s).is_err() {
            error!("Secret must be valid hex");
            std::process::exit(1);
        }
        s.clone()
    } else {
        let secret: String = (0..32)
            .map(|_| {
                const HEX: &[u8] = b"0123456789abcdef";
                HEX[rand::rng().random_range(0..16)] as char
            })
            .collect();
        info!("Generated secret: {}", secret);
        secret
    };

    {
        let mut cfg = PROXY_CONFIG.write().unwrap();
        cfg.port = args.port;
        cfg.host = args.host.clone();
        cfg.secret = secret_hex.clone();
        cfg.dc_redirects = dc_redirects.clone();
        cfg.buffer_size = args.buf_kb.max(4) * 1024;
        cfg.pool_size = args.pool_size;
        cfg.fallback_cfproxy = !args.no_cfproxy;
        cfg.cfproxy_user_domains = config::coerce_domain_list(Some(&args.cfproxy_domain));
        cfg.cfproxy_worker_domains = config::coerce_domain_list(Some(&args.cfproxy_worker_domain));
        cfg.fake_tls_domain = args.fake_tls_domain.clone();
        cfg.proxy_protocol = args.proxy_protocol;
    }

    let secret_bytes = hex::decode(&secret_hex).expect("invalid hex");
    let link_host = get_link_host(&args.host);

    info!("{}", "=".repeat(60));
    info!("  Telegram MTProto WS Bridge Proxy");
    info!("  Listening on   {}:{}", args.host, args.port);
    info!("  Secret:        {}", secret_hex);
    if !args.fake_tls_domain.is_empty() {
        info!("  Fake TLS:      {}", args.fake_tls_domain);
    }
    info!("  Target DC IPs:");
    for (dc, ip) in &dc_redirects {
        info!("    DC{}: {}", dc, ip);
    }
    if !args.no_cfproxy {
        let user = if args.cfproxy_domain.is_empty() {
            "auto"
        } else {
            "user"
        };
        info!("  CF proxy:      enabled ({})", user);
    }
    if !args.cfproxy_worker_domain.is_empty() {
        info!(
            "  CF worker:     enabled ({})",
            args.cfproxy_worker_domain.join(", ")
        );
    }
    info!("{}", "=".repeat(60));
    if let Some(host) = &link_host {
        let dd_link = format!(
            "tg://proxy?server={}&port={}&secret=dd{}",
            host, args.port, secret_hex
        );
        info!("  Connect (dd):  {}", dd_link);
        if !args.fake_tls_domain.is_empty() {
            let domain_hex = hex::encode(args.fake_tls_domain.as_bytes());
            let ee_link = format!(
                "tg://proxy?server={}&port={}&secret=ee{}{}",
                host, args.port, secret_hex, domain_hex
            );
            info!("  Connect (ee):  {}", ee_link);
        }
    }
    info!("{}", "=".repeat(60));

    start_proxy(secret_bytes, args).await;
}

async fn start_proxy(secret: Vec<u8>, _args: Cli) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Handle Ctrl+C
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutdown signal received, draining connections...");
        let _ = shutdown_tx.send(true);
    });

    let (host, port) = {
        let cfg = PROXY_CONFIG.read().expect("config poisoned");
        (cfg.host.clone(), cfg.port)
    };

    let listener = TcpListener::bind((host.as_str(), port))
        .await
        .expect("Failed to bind");

    // Start tray icon (non-blocking, runs in background thread)
    let gui_state = std::sync::Arc::new(parking_lot::Mutex::new(
        tg_ws_proxy::ui::GuiState::default(),
    ));
    tg_ws_proxy::ui::start_tray(shutdown_rx.clone(), gui_state);

    WS_POOL.warmup().await;
    CF_WORKER_POOL.warmup().await;

    let _log_handle = tokio::spawn({
        let mut shutdown = shutdown_rx.clone();
        async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                    _ = shutdown.changed() => return,
                }
                let bl: Vec<String> = ws_blacklist()
                    .read()
                    .expect("blacklist poisoned")
                    .iter()
                    .map(|k| format!("DC{}", k))
                    .collect();
                let bl_str = if bl.is_empty() {
                    "none".into()
                } else {
                    bl.join(", ")
                };
                info!("stats: {} | ws_bl: {}", STATS.summary(), bl_str);
            }
        }
    });

    // CF domain auto-refresh
    let _domain_refresh = tokio::spawn({
        let mut shutdown = shutdown_rx.clone();
        async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(300)) => {}
                    _ = shutdown.changed() => return,
                }
                refresh_cf_domains().await;
            }
        }
    });

    let mut shutdown = shutdown_rx.clone();
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                info!("Server stopping");
                break;
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        STATS.connections_total.fetch_add(1, Ordering::Relaxed);
                        STATS.connections_active.fetch_add(1, Ordering::Relaxed);
                        // Socket buffer sizing skipped (not available on tokio::TcpStream)
                        let secret = secret.clone();
                        tokio::spawn(async move {
                            let label = format!("{}:{}", peer.ip(), peer.port());
                            let start = Instant::now();
                            handle_client(stream, &secret, &label).await;
                            let elapsed = start.elapsed();
                            info!("[{}] disconnected after {:.1}s", label, elapsed.as_secs_f64());
                            STATS.connections_active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                    }
                }
            }
        }
    }
}

async fn handle_client(stream: TcpStream, secret: &[u8], label: &str) {
    let (mut reader, mut writer) = tokio::io::split(stream);

    // PROXY protocol v1
    let proxy_protocol = PROXY_CONFIG.read().expect("config poisoned").proxy_protocol;
    if proxy_protocol {
        let mut proxy_line = String::new();
        let mut buf = [0u8; 1];
        loop {
            if reader.read_exact(&mut buf).await.is_err() { return; }
            if buf[0] == b'\r' { continue; }
            if buf[0] == b'\n' { break; }
            proxy_line.push(buf[0] as char);
        }
        debug!("[{}] PROXY header: {}", label, proxy_line);
    }

    let masking = {
        let cfg = PROXY_CONFIG.read().expect("config poisoned");
        cfg.fake_tls_domain.clone()
    };

    let mut first_byte = [0u8; 1];
    if tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut first_byte)).await.is_err() {
        return;
    }

    let handshake;
    let clt_reader: Box<dyn AsyncRead + Unpin + Send>;
    let clt_writer: Box<dyn AsyncWrite + Unpin + Send>;
    if first_byte[0] == TLS_RECORD_HANDSHAKE && !masking.is_empty() {
        let mut hdr_rest = [0u8; 4];
        if tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut hdr_rest)).await.is_err() {
            return;
        }
        let record_len = u16::from_be_bytes([hdr_rest[0], hdr_rest[1]]) as usize;
        let mut record_body = vec![0u8; record_len];
        if tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut record_body)).await.is_err() {
            return;
        }

        let mut client_hello = vec![first_byte[0], hdr_rest[0], hdr_rest[1], hdr_rest[2], hdr_rest[3]];
        client_hello.extend_from_slice(&record_body);

        match verify_client_hello(&client_hello, secret) {
            Some((client_random, session_id, ts)) => {
                debug!("[{}] Fake TLS handshake ok (ts={})", label, ts);
                let server_hello = build_server_hello(secret, &client_random, &session_id);
                if writer.write_all(&server_hello).await.is_err() { return; }
                if writer.flush().await.is_err() { return; }

                let ft_stream = FakeTlsStream::new(reader, writer);
                let (mut ft_reader, ft_writer) = tokio::io::split(ft_stream);

                let mut hs = vec![0u8; HANDSHAKE_LEN];
                if tokio::time::timeout(HANDSHAKE_TIMEOUT, ft_reader.read_exact(&mut hs)).await.is_err() {
                    return;
                }
                handshake = hs;
                clt_reader = Box::new(ft_reader);
                clt_writer = Box::new(ft_writer);
            }
            None => {
                debug!("[{}] Fake TLS verify failed -> masking", label);
                return;
            }
        }
    } else if !masking.is_empty() {
        debug!(
            "[{}] non-TLS byte 0x{:02X} -> redirect",
            label, first_byte[0]
        );
        let redirect = format!(
            "HTTP/1.1 301 Moved Permanently\r\n\
             Location: https://{}/\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\r\n",
            masking
        );
        let _ = writer.write_all(redirect.as_bytes()).await;
        let _ = writer.flush().await;
        return;
    } else {
        let mut rest = vec![0u8; HANDSHAKE_LEN - 1];
        if tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut rest)).await.is_err() {
            return;
        }
        let mut hs = vec![first_byte[0]];
        hs.extend_from_slice(&rest);
        handshake = hs;
        clt_reader = Box::new(reader);
        clt_writer = Box::new(writer);
    }

    let result = try_handshake(&handshake, secret);
    let (dc, is_media, proto_tag, client_dec_prekey_iv) = match result {
        Some(r) => r,
        None => {
            STATS.connections_bad.fetch_add(1, Ordering::Relaxed);
            warn!("[{}] bad handshake (wrong secret or proto)", label);
            return;
        }
    };

    let proto_int = if proto_tag == PROTO_TAG_ABRIDGED {
        PROTO_ABRIDGED_INT
    } else if proto_tag == PROTO_TAG_INTERMEDIATE {
        PROTO_INTERMEDIATE_INT
    } else {
        PROTO_PADDED_INTERMEDIATE_INT
    };

    let dc_idx = if is_media {
        -(dc as i16)
    } else {
        dc as i16
    };
    debug!(
        "[{}] handshake ok: DC{}{} proto=0x{:08X}",
        label,
        dc,
        if is_media { " media" } else { "" },
        proto_int
    );

    let relay_init = generate_relay_init(&proto_tag, dc_idx);
    let mut ctx = build_crypto_ctx(&client_dec_prekey_iv, secret, &relay_init);

    let dc_key = format!("{}{}", dc, if is_media { "m" } else { "" });

    // Check config
    let dc_in_config = {
        let cfg = PROXY_CONFIG.read().expect("config poisoned");
        cfg.dc_redirects.contains_key(&dc)
    };

    let blacklisted = ws_blacklist().read().expect("blacklist poisoned").contains(&dc_key);

    if !dc_in_config || blacklisted {
        if !dc_in_config {
            info!("[{}] DC{} not in config -> fallback", label, dc);
        } else {
            info!("[{}] DC{}{} WS blacklisted -> fallback", label, dc, if is_media { " media" } else { "" });
        }
        do_fallback_tcp_ws(clt_reader, clt_writer, &relay_init, dc, &mut ctx, label).await;
        return;
    }

    // Try WebSocket / CF fallback chain
    let now = Instant::now();
    let fail_until = dc_fail_until()
        .read()
        .expect("dc_fail_until poisoned")
        .get(&dc_key)
        .copied();
    let ws_timeout = if let Some(fail) = fail_until {
        if now < fail { WS_FAIL_TIMEOUT } else { 10.0 }
    } else {
        10.0
    };

    let domains = ws_domains(dc, is_media);
    let target = {
        let cfg = PROXY_CONFIG.read().expect("config poisoned");
        cfg.dc_redirects.get(&dc).cloned()
    };

    let target = match target {
        Some(t) => t,
        None => return,
    };

    let mut ws = WS_POOL.get(dc, is_media, &target, &domains).await;
    let mut ws_failed_redirect = false;
    let mut all_redirects = true;

    if ws.is_none() {
        for domain in &domains {
            info!("[{}] DC{} -> wss://{}/apiws via {}", label, dc, domain, target);
            match RawWebSocket::connect(
                &target,
                domain,
                Duration::from_secs_f64(ws_timeout),
                "/apiws",
            )
            .await
            {
                Ok(w) => {
                    ws = Some(w);
                    all_redirects = false;
                    break;
                }
                Err(e) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    if let Some(ws_err) = e.downcast_ref::<WsHandshakeError>() {
                        if ws_err.is_redirect() {
                            ws_failed_redirect = true;
                            warn!("[{}] DC{} got {} from {} -> {:?}",
                                label, dc, ws_err.status_code, domain, ws_err.location);
                            continue;
                        }
                        all_redirects = false;
                        warn!("[{}] DC{} WS handshake: {}", label, dc, ws_err);
                    } else {
                        all_redirects = false;
                        warn!("[{}] DC{} WS connect failed: {}", label, dc, e);
                    }
                }
            }
        }
    }

    if ws.is_none() {
        if ws_failed_redirect && all_redirects {
            ws_blacklist().write().expect("blacklist poisoned").insert(dc_key.clone());
            warn!("[{}] DC{} blacklisted for WS (all 302)", label, dc);
        } else {
            dc_fail_until().write().expect("dc_fail_until poisoned").insert(
                dc_key.clone(),
                now + Duration::from_secs_f64(DC_FAIL_COOLDOWN),
            );
            if !ws_failed_redirect {
                info!("[{}] DC{} WS cooldown for {}s", label, dc, DC_FAIL_COOLDOWN as u32);
            }
        }
        do_fallback_tcp_ws(clt_reader, clt_writer, &relay_init, dc, &mut ctx, label).await;
        return;
    }

    dc_fail_until().write().expect("dc_fail_until poisoned").remove(&dc_key);
    STATS.connections_ws.fetch_add(1, Ordering::Relaxed);

    let splitter = MsgSplitter::new(&relay_init, proto_int);
    let mut ws = ws.expect("ws should be Some");

    if ws.send(&relay_init).await.is_err() { return; }

    bridge_ws_reencrypt_halves(clt_reader, clt_writer, &mut ws, &mut ctx, &mut Some(splitter)).await;
}

/// Fetch CF proxy domains from GitHub and update the balancer.
async fn refresh_cf_domains() {
    let url = "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/domains.txt";
    match reqwest::get(url).await {
        Ok(resp) => {
            if let Ok(text) = resp.text().await {
                let domains: Vec<String> = text
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
                if !domains.is_empty() {
                    let mut balancer = BALANCER.write().expect("balancer poisoned");
                    balancer.update_domains_list(&domains);
                    info!("Updated {} CF proxy domains", domains.len());
                }
            }
        }
        Err(e) => debug!("CF domain refresh failed: {}", e),
    }
}

/// Fallback via CF Worker → CF proxy → TCP
async fn do_fallback_tcp_ws(
    mut reader: Box<dyn AsyncRead + Unpin + Send>,
    mut writer: Box<dyn AsyncWrite + Unpin + Send>,
    relay_init: &[u8],
    dc: u32,
    ctx: &mut CryptoContext,
    label: &str,
) {
    let fallback_dst = dc_default_ips().get(&dc).map(|s| s.to_string());
    let dst = match &fallback_dst {
        Some(d) => d.clone(),
        None => {
            warn!("[{}] DC{} no fallback target", label, dc);
            return;
        }
    };

    // 1. Try CF Worker pool
    let cfg_workers = PROXY_CONFIG.read().expect("config poisoned").cfproxy_worker_domains.clone();
    if !cfg_workers.is_empty() {
        for worker_domain in &cfg_workers {
            if let Some(mut ws) = CF_WORKER_POOL.get(dc, worker_domain, &dst).await {
                info!("[{}] DC{} -> CF Worker fallback via {}", label, dc, worker_domain);
                STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
                if ws.send(relay_init).await.is_err() { continue; }
                let splitter = MsgSplitter::new(relay_init, PROTO_INTERMEDIATE_INT);
                bridge_ws_reencrypt_halves(reader, writer, &mut ws, ctx, &mut Some(splitter)).await;
                return;
            }
        }
    }

    // 2. Try CF proxy via balancer
    let use_cfproxy = PROXY_CONFIG.read().expect("config poisoned").fallback_cfproxy;
    if use_cfproxy {
        let domains = {
            let balancer = BALANCER.read().expect("balancer poisoned");
            balancer.get_domains_for_dc(dc)
        };
        if !domains.is_empty() {
            for domain in &domains {
                info!("[{}] DC{} -> CF proxy fallback via {}", label, dc, domain);
                if let Ok(mut ws) = RawWebSocket::connect(domain, domain, Duration::from_secs(10), &format!("/{}", dst)).await {
                    STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
                    if ws.send(relay_init).await.is_err() { continue; }
                    let splitter = MsgSplitter::new(relay_init, PROTO_INTERMEDIATE_INT);
                    bridge_ws_reencrypt_halves(reader, writer, &mut ws, ctx, &mut Some(splitter)).await;
                    return;
                }
            }
        }
    }

    // 3. Raw TCP fallback
    info!("[{}] DC{} -> TCP fallback to {}:443", label, dc, dst);
    let up = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((dst.as_str(), 443))).await;

    match up {
        Ok(Ok(mut up_stream)) => {
            let _ = up_stream.set_nodelay(true);
            STATS.connections_tcp_fallback.fetch_add(1, Ordering::Relaxed);
            if up_stream.write_all(relay_init).await.is_err() { return; }
            if up_stream.flush().await.is_err() { return; }

            let (mut rr, mut rw) = up_stream.split();
            let mut cbuf = [0u8; 65536];
            let mut rbuf = [0u8; 65536];

            loop {
                tokio::select! {
                    result = reader.read(&mut cbuf) => {
                        let n = match result {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        STATS.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                        ctx.clt_dec.apply_keystream(&mut cbuf[..n]);
                        ctx.tg_enc.apply_keystream(&mut cbuf[..n]);
                        if rw.write_all(&cbuf[..n]).await.is_err() { break; }
                        if rw.flush().await.is_err() { break; }
                    }
                    result = rr.read(&mut rbuf) => {
                        let n = match result {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        STATS.bytes_down.fetch_add(n as u64, Ordering::Relaxed);
                        ctx.tg_dec.apply_keystream(&mut rbuf[..n]);
                        ctx.clt_enc.apply_keystream(&mut rbuf[..n]);
                        if writer.write_all(&rbuf[..n]).await.is_err() { break; }
                        if writer.flush().await.is_err() { break; }
                    }
                }
            }
        }
        Ok(Err(e)) => warn!("[{}] TCP fallback connection error: {}", label, e),
        Err(e) => warn!("[{}] TCP fallback timeout: {}", label, e),
    }
}
