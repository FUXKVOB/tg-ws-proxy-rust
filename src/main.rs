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
use tg_ws_proxy::proxy::bridge::{bridge_ws_reencrypt_halves, SessionStats};
use tg_ws_proxy::proxy::config::{self, ConfigFile, PROXY_CONFIG};
use tg_ws_proxy::proxy::fake_tls::{build_server_hello, verify_client_hello, FakeTlsStream, TLS_RECORD_HANDSHAKE};
use tg_ws_proxy::proxy::handshake::{
    build_crypto_ctx, generate_relay_init, try_handshake, CryptoContext, MsgSplitter,
};
use tg_ws_proxy::proxy::pool::{CF_WORKER_POOL, WS_POOL};
use tg_ws_proxy::proxy::raw_websocket::{RawWebSocket, WsHandshakeError};
use tg_ws_proxy::proxy::utils::*;
use tg_ws_proxy::proxy::stats::human_bytes;
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
    #[arg(long)]
    config: Option<String>,

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

    #[arg(long = "log-max-mb", default_value = "5")]
    log_max_mb: u64,

    #[arg(long = "log-backups", default_value = "0")]
    log_backups: usize,

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

    #[arg(long)]
    autostart: bool,
}

#[cfg(windows)]
fn ensure_single_instance() {
    use std::net::TcpListener;
    let _lock = Box::leak(Box::new(
        TcpListener::bind("127.0.0.1:18923")
            .expect("Another instance is already running. Exiting.")
    ));
}

#[cfg(windows)]
fn set_autostart(enable: bool) {
    use windows_sys::Win32::System::Registry::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let key_path: Vec<u16> = OsStr::new(r"Software\Microsoft\Windows\CurrentVersion\Run")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let app_name: Vec<u16> = OsStr::new("TG WS Proxy")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut hkey = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_CURRENT_USER, key_path.as_ptr(), 0, KEY_SET_VALUE, &mut hkey) == 0 {
            if enable {
                if let Ok(exe) = std::env::current_exe() {
                    let path: Vec<u16> = exe.as_os_str()
                        .encode_wide()
                        .chain(std::iter::once(0))
                        .collect();
                    RegSetValueExW(hkey, app_name.as_ptr(), 0, REG_SZ,
                        path.as_ptr() as *const u8, (path.len() * 2) as u32);
                }
            } else {
                RegDeleteValueW(hkey, app_name.as_ptr());
            }
            RegCloseKey(hkey);
        }
    }
}

fn check_ipv6() -> bool {
    std::net::TcpStream::connect_timeout(
        &"[::1]:1".parse().unwrap(),
        Duration::from_millis(100),
    ).is_ok()
}

fn first_run_marker_path() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    let dir = exe.parent().unwrap_or(std::path::Path::new("."));
    dir.join(".first_run_done")
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let (cfg_file, config_path) = if let Some(ref path) = args.config {
        let path = if path.is_empty() { config::default_config_path() } else { path.clone() };
        (config::load_config(&path).ok(), Some(path))
    } else {
        (None, Some(config::default_config_path()))
    };

    let log_file = args.log_file.clone()
        .or_else(|| cfg_file.as_ref().and_then(|c| c.log_file.clone()));

    if let Some(ref path) = log_file {
        let file_appender = tracing_appender::rolling::never(
            std::path::Path::new(path).parent().unwrap_or(std::path::Path::new(".")),
            std::path::Path::new(path).file_name().unwrap().to_string_lossy().as_ref(),
        );
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_writer(non_blocking)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();
    }

    if args.verbose {
        unsafe { std::env::set_var("RUST_LOG", "debug"); }
    }

    #[cfg(windows)]
    ensure_single_instance();

    let log_max_mb = args.log_max_mb;
    let log_backups = args.log_backups;

    let cfg = cfg_file.unwrap_or(ConfigFile {
        host: None, port: None, secret: None, fake_tls_domain: None,
        proxy_protocol: None, no_cfproxy: None, pool_size: None, buf_kb: None,
        cfproxy_domain: None, cfproxy_worker_domain: None, dc_ip: None,
        log_file: None, log_max_mb: None, log_backups: None, autostart: None,
    });

    let dc_redirects = if !args.dc_ip.is_empty() {
        config::parse_dc_ip_list(&args.dc_ip).unwrap_or_else(|e| {
            error!("{}", e);
            std::process::exit(1);
        })
    } else if let Some(ref dc_map) = cfg.dc_ip {
        dc_map.clone()
    } else {
        HashMap::from([
            (2u32, "149.154.167.220".to_string()),
            (4u32, "149.154.167.220".to_string()),
        ])
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
    } else if let Some(ref s) = cfg.secret {
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

    let host = if args.host != "127.0.0.1" { args.host.clone() } else { cfg.host.clone().unwrap_or_else(|| args.host.clone()) };
    let port = args.port != 1443 || cfg.port.unwrap_or(1443) == 1443;
    let port_val = if !port { cfg.port.unwrap_or(1443) } else { args.port };

    let fake_tls_domain = if !args.fake_tls_domain.is_empty() {
        args.fake_tls_domain.clone()
    } else {
        cfg.fake_tls_domain.clone().unwrap_or_default()
    };

    let proxy_protocol = args.proxy_protocol || cfg.proxy_protocol.unwrap_or(false);
    let no_cfproxy = args.no_cfproxy || cfg.no_cfproxy.unwrap_or(false);
    let pool_size = if args.pool_size != 4 { args.pool_size } else { cfg.pool_size.unwrap_or(4) };
    let buf_kb = if args.buf_kb != 256 { args.buf_kb } else { cfg.buf_kb.unwrap_or(256) };

    let autostart = args.autostart || cfg.autostart.unwrap_or(false);
    #[cfg(windows)]
    set_autostart(autostart);

    {
        let mut pc = PROXY_CONFIG.write().unwrap();
        pc.port = port_val;
        pc.host = host.clone();
        pc.secret = secret_hex.clone();
        pc.dc_redirects = dc_redirects.clone();
        pc.buffer_size = buf_kb.max(4) * 1024;
        pc.pool_size = pool_size;
        pc.fallback_cfproxy = !no_cfproxy;
        pc.cfproxy_user_domains = config::coerce_domain_list(
            if !args.cfproxy_domain.is_empty() { Some(&args.cfproxy_domain) } else { cfg.cfproxy_domain.as_deref() }
        );
        pc.cfproxy_worker_domains = config::coerce_domain_list(
            if !args.cfproxy_worker_domain.is_empty() { Some(&args.cfproxy_worker_domain) } else { cfg.cfproxy_worker_domain.as_deref() }
        );
        pc.fake_tls_domain = fake_tls_domain.clone();
        pc.proxy_protocol = proxy_protocol;
        pc.log_file = log_file.clone();
        pc.log_max_mb = log_max_mb;
        pc.log_backups = log_backups;
        pc.autostart = autostart;
    }

    let secret_bytes = hex::decode(&secret_hex).expect("invalid hex");
    let link_host = get_link_host(&host);

    info!("{}", "=".repeat(60));
    info!("  Telegram MTProto WS Bridge Proxy");
    info!("  Listening on   {}:{}", host, port_val);
    info!("  Secret:        {}", secret_hex);
    if !fake_tls_domain.is_empty() {
        info!("  Fake TLS:      {}", fake_tls_domain);
    }
    info!("  Target DC IPs:");
    for (dc, ip) in &dc_redirects {
        info!("    DC{}: {}", dc, ip);
    }
    if !no_cfproxy {
        info!("  CF proxy:      enabled");
    }
    info!("{}", "=".repeat(60));
    if let Some(ref host) = link_host {
        let dd_link = format!(
            "tg://proxy?server={}&port={}&secret=dd{}",
            host, port_val, secret_hex
        );
        info!("  Connect (dd):  {}", dd_link);
        if !fake_tls_domain.is_empty() {
            let domain_hex = hex::encode(fake_tls_domain.as_bytes());
            let ee_link = format!(
                "tg://proxy?server={}&port={}&secret=ee{}{}",
                host, port_val, secret_hex, domain_hex
            );
            info!("  Connect (ee):  {}", ee_link);
        }
    }
    info!("{}", "=".repeat(60));

    let first_run = !first_run_marker_path().exists();
    if first_run {
        let _ = std::fs::write(first_run_marker_path(), "");
        info!("First run detected, showing welcome wizard");
    }

    if check_ipv6() {
        info!("IPv6 detected — WebSocket connections may not work over IPv6");
    }

    let gui_state = std::sync::Arc::new(parking_lot::Mutex::new(
        tg_ws_proxy::ui::GuiState {
            link_host: link_host.clone().unwrap_or_default(),
            link_port: port_val,
            link_secret: secret_hex.clone(),
            link_domain_hex: if fake_tls_domain.is_empty() { String::new() } else { hex::encode(fake_tls_domain.as_bytes()) },
            log_path: log_file.clone(),
            config_path: config_path.clone().unwrap_or_default(),
            wizard_open: first_run,
            version: "1.7.2".into(),
            ..Default::default()
        },
    ));

    start_proxy(secret_bytes, gui_state).await;
}

async fn start_proxy(secret: Vec<u8>, gui_state: std::sync::Arc<parking_lot::Mutex<tg_ws_proxy::ui::GuiState>>) {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

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
                        let secret = secret.clone();
                        tokio::spawn(async move {
                            let label = format!("{}:{}", peer.ip(), peer.port());
                            let start = Instant::now();
                            let s = handle_client(stream, &secret, &label).await;
                            let elapsed = start.elapsed();
                            let up_str = human_bytes(s.bytes_up);
                            let down_str = human_bytes(s.bytes_down);
                            info!("[{}] disconnected ^ {} ({} pkts) v {} ({} pkts) in {:.1}s",
                                label, up_str, s.packets_up, down_str, s.packets_down, elapsed.as_secs_f64());
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

async fn handle_client(stream: TcpStream, secret: &[u8], label: &str) -> SessionStats {
    let (mut reader, mut writer) = tokio::io::split(stream);

    let proxy_protocol = PROXY_CONFIG.read().expect("config poisoned").proxy_protocol;
    if proxy_protocol {
        let mut proxy_line = String::new();
        let mut buf = [0u8; 1];
        loop {
            if reader.read_exact(&mut buf).await.is_err() { return SessionStats::new(); }
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
        return SessionStats::new();
    }

    let handshake;
    let clt_reader: Box<dyn AsyncRead + Unpin + Send>;
    let clt_writer: Box<dyn AsyncWrite + Unpin + Send>;
    if first_byte[0] == TLS_RECORD_HANDSHAKE && !masking.is_empty() {
        let mut hdr_rest = [0u8; 4];
        if tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut hdr_rest)).await.is_err() {
            return SessionStats::new();
        }
        let record_len = u16::from_be_bytes([hdr_rest[0], hdr_rest[1]]) as usize;
        let mut record_body = vec![0u8; record_len];
        if tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut record_body)).await.is_err() {
            return SessionStats::new();
        }

        let mut client_hello = vec![first_byte[0], hdr_rest[0], hdr_rest[1], hdr_rest[2], hdr_rest[3]];
        client_hello.extend_from_slice(&record_body);

        match verify_client_hello(&client_hello, secret) {
            Some((client_random, session_id, ts)) => {
                debug!("[{}] Fake TLS handshake ok (ts={})", label, ts);
                let server_hello = build_server_hello(secret, &client_random, &session_id);
                if writer.write_all(&server_hello).await.is_err() { return SessionStats::new(); }
                if writer.flush().await.is_err() { return SessionStats::new(); }

                let ft_stream = FakeTlsStream::new(reader, writer);
                let (mut ft_reader, ft_writer) = tokio::io::split(ft_stream);

                let mut hs = vec![0u8; HANDSHAKE_LEN];
                if tokio::time::timeout(HANDSHAKE_TIMEOUT, ft_reader.read_exact(&mut hs)).await.is_err() {
                    return SessionStats::new();
                }
                handshake = hs;
                clt_reader = Box::new(ft_reader);
                clt_writer = Box::new(ft_writer);
            }
            None => {
                debug!("[{}] Fake TLS verify failed -> masking", label);
                return SessionStats::new();
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
        return SessionStats::new();
    } else {
        let mut rest = vec![0u8; HANDSHAKE_LEN - 1];
        if tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut rest)).await.is_err() {
            return SessionStats::new();
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
            return SessionStats::new();
        }
    };

    let proto_int = if proto_tag == PROTO_TAG_ABRIDGED {
        PROTO_ABRIDGED_INT
    } else if proto_tag == PROTO_TAG_INTERMEDIATE {
        PROTO_INTERMEDIATE_INT
    } else {
        PROTO_PADDED_INTERMEDIATE_INT
    };

    let dc_idx = if is_media { -(dc as i16) } else { dc as i16 };
    debug!(
        "[{}] handshake ok: DC{}{} proto=0x{:08X}",
        label, dc, if is_media { " media" } else { "" }, proto_int
    );

    let relay_init = generate_relay_init(&proto_tag, dc_idx);
    let mut ctx = build_crypto_ctx(&client_dec_prekey_iv, secret, &relay_init);

    let dc_key = format!("{}{}", dc, if is_media { "m" } else { "" });

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
        return do_fallback_tcp_ws(clt_reader, clt_writer, &relay_init, dc, &mut ctx, label).await;
    }

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
        None => return SessionStats::new(),
    };

    let mut ws = WS_POOL.get(dc, is_media, &target, &domains).await;
    let mut ws_failed_redirect = false;
    let mut all_redirects = true;

    if ws.is_none() {
        for domain in &domains {
            info!("[{}] DC{} -> wss://{}/apiws via {}", label, dc, domain, target);
            match RawWebSocket::connect(
                &target, domain, Duration::from_secs_f64(ws_timeout), "/apiws",
            ).await {
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
        return do_fallback_tcp_ws(clt_reader, clt_writer, &relay_init, dc, &mut ctx, label).await;
    }

    dc_fail_until().write().expect("dc_fail_until poisoned").remove(&dc_key);
    STATS.connections_ws.fetch_add(1, Ordering::Relaxed);

    let splitter = MsgSplitter::new(&relay_init, proto_int);
    let mut ws = ws.expect("ws should be Some");

    if ws.send(&relay_init).await.is_err() { return SessionStats::new(); }

    bridge_ws_reencrypt_halves(clt_reader, clt_writer, &mut ws, &mut ctx, &mut Some(splitter)).await
}

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

async fn do_fallback_tcp_ws(
    mut reader: Box<dyn AsyncRead + Unpin + Send>,
    mut writer: Box<dyn AsyncWrite + Unpin + Send>,
    relay_init: &[u8],
    dc: u32,
    ctx: &mut CryptoContext,
    label: &str,
) -> SessionStats {
    let fallback_dst = dc_default_ips().get(&dc).map(|s| s.to_string());
    let dst = match &fallback_dst {
        Some(d) => d.clone(),
        None => {
            warn!("[{}] DC{} no fallback target", label, dc);
            return SessionStats::new();
        }
    };

    let cfg_workers = PROXY_CONFIG.read().expect("config poisoned").cfproxy_worker_domains.clone();
    if !cfg_workers.is_empty() {
        for worker_domain in &cfg_workers {
            if let Some(mut ws) = CF_WORKER_POOL.get(dc, worker_domain, &dst).await {
                info!("[{}] DC{} -> CF Worker fallback via {}", label, dc, worker_domain);
                STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
                if ws.send(relay_init).await.is_err() { continue; }
                let splitter = MsgSplitter::new(relay_init, PROTO_INTERMEDIATE_INT);
                return bridge_ws_reencrypt_halves(reader, writer, &mut ws, ctx, &mut Some(splitter)).await;
            }
        }
    }

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
                    return bridge_ws_reencrypt_halves(reader, writer, &mut ws, ctx, &mut Some(splitter)).await;
                }
            }
        }
    }

    info!("[{}] DC{} -> TCP fallback to {}:443", label, dc, dst);
    let up = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((dst.as_str(), 443))).await;

    match up {
        Ok(Ok(mut up_stream)) => {
            let _ = up_stream.set_nodelay(true);
            STATS.connections_tcp_fallback.fetch_add(1, Ordering::Relaxed);
            if up_stream.write_all(relay_init).await.is_err() { return SessionStats::new(); }
            if up_stream.flush().await.is_err() { return SessionStats::new(); }

            let (mut rr, mut rw) = up_stream.split();
            let mut cbuf = [0u8; 65536];
            let mut rbuf = [0u8; 65536];
            let mut stats = SessionStats::new();

            loop {
                tokio::select! {
                    result = reader.read(&mut cbuf) => {
                        let n = match result {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        STATS.bytes_up.fetch_add(n as u64, Ordering::Relaxed);
                        stats.bytes_up += n as u64;
                        stats.packets_up += 1;
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
                        stats.bytes_down += n as u64;
                        stats.packets_down += 1;
                        ctx.tg_dec.apply_keystream(&mut rbuf[..n]);
                        ctx.clt_enc.apply_keystream(&mut rbuf[..n]);
                        if writer.write_all(&rbuf[..n]).await.is_err() { break; }
                        if writer.flush().await.is_err() { break; }
                    }
                }
            }
            stats
        }
        Ok(Err(e)) => {
            warn!("[{}] TCP fallback connection error: {}", label, e);
            SessionStats::new()
        }
        Err(e) => {
            warn!("[{}] TCP fallback timeout: {}", label, e);
            SessionStats::new()
        }
    }
}
