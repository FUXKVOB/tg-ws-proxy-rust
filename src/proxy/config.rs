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
