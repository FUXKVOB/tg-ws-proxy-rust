use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub port: u16,
    pub host: String,
    pub secret: String,
    pub dc_redirects: HashMap<u32, String>,
    pub buffer_size: usize,
    pub pool_size: usize,
    pub fallback_cfproxy: bool,
    pub cfproxy_user_domains: Vec<String>,
    pub cfproxy_worker_domains: Vec<String>,
    pub fake_tls_domain: String,
    pub proxy_protocol: bool,
    pub log_file: Option<String>,
    pub log_max_mb: u64,
    pub log_backups: usize,
    pub autostart: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 1443,
            host: "127.0.0.1".into(),
            secret: Self::random_secret(),
            dc_redirects: HashMap::from([
                (2, "149.154.167.220".into()),
                (4, "149.154.167.220".into()),
            ]),
            buffer_size: 256 * 1024,
            pool_size: 4,
            fallback_cfproxy: true,
            cfproxy_user_domains: vec![],
            cfproxy_worker_domains: vec![],
            fake_tls_domain: String::new(),
            proxy_protocol: false,
            log_file: None,
            log_max_mb: 5,
            log_backups: 0,
            autostart: false,
        }
    }
}

impl ProxyConfig {
    fn random_secret() -> String {
        let bytes: [u8; 16] = rand::random();
        hex::encode(bytes)
    }
}

pub static PROXY_CONFIG: LazyLock<RwLock<ProxyConfig>> =
    LazyLock::new(|| RwLock::new(ProxyConfig::default()));

pub fn parse_dc_ip_list(list: &[String]) -> Result<HashMap<u32, String>, String> {
    let mut map = HashMap::new();
    for entry in list {
        let parts: Vec<&str> = entry.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid --dc-ip format {:?}, expected DC:IP", entry));
        }
        let dc: u32 = parts[0]
            .parse()
            .map_err(|_| format!("Invalid DC number: {}", parts[0]))?;
        let ip = parts[1].to_string();
        if !ip.contains('.') {
            return Err(format!("Invalid IP: {}", ip));
        }
        map.insert(dc, ip);
    }
    Ok(map)
}

pub fn coerce_domain_list(value: Option<&[String]>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    if let Some(list) = value {
        for item in list {
            for s in item.split(&[',', ';', ' ']) {
                let s = s.trim().to_lowercase();
                if !s.is_empty() && seen.insert(s.clone()) {
                    result.push(s);
                }
            }
        }
    }
    result
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ConfigFile {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub secret: Option<String>,
    pub fake_tls_domain: Option<String>,
    pub proxy_protocol: Option<bool>,
    pub no_cfproxy: Option<bool>,
    pub pool_size: Option<usize>,
    pub buf_kb: Option<usize>,
    pub cfproxy_domain: Option<Vec<String>>,
    pub cfproxy_worker_domain: Option<Vec<String>>,
    pub dc_ip: Option<HashMap<u32, String>>,
    pub log_file: Option<String>,
    pub log_max_mb: Option<u64>,
    pub log_backups: Option<usize>,
    pub autostart: Option<bool>,
}

pub fn default_config_path() -> String {
    if let Some(path) = std::env::current_exe().ok()
        && let Some(dir) = path.parent()
    {
        return dir.join("config.toml").to_string_lossy().to_string();
    }
    "config.toml".into()
}

pub fn load_config(path: &str) -> Result<ConfigFile, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Cannot read config: {e}"))?;
    toml::from_str(&content).map_err(|e| format!("Invalid config: {e}"))
}

pub fn save_config(path: &str, cfg: &ConfigFile) -> Result<(), String> {
    let content = toml::to_string_pretty(cfg).map_err(|e| format!("Serialize config: {e}"))?;
    std::fs::write(path, content).map_err(|e| format!("Write config: {e}"))
}
