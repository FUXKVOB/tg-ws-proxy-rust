use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Instant;

use crate::proxy::config::PROXY_CONFIG;
use crate::proxy::raw_websocket::RawWebSocket;
use crate::proxy::utils::{dc_default_ips, ws_domains};
use crate::proxy::STATS;

type PoolBucket<T> = VecDeque<(T, Instant)>;

pub struct WsPool {
    idle: Mutex<HashMap<(u32, bool), PoolBucket<RawWebSocket>>>,
    refilling: Mutex<HashSet<(u32, bool)>>,
}

impl Default for WsPool {
    fn default() -> Self {
        Self::new()
    }
}

impl WsPool {
    pub fn new() -> Self {
        Self {
            idle: Mutex::new(HashMap::new()),
            refilling: Mutex::new(HashSet::new()),
        }
    }

    pub async fn get(
        &self,
        dc: u32,
        is_media: bool,
        target_ip: &str,
        domains: &[String],
    ) -> Option<RawWebSocket> {
        let key = (dc, is_media);
        let now = Instant::now();

        {
            let mut idle = self.idle.lock().unwrap();
            if let Some(bucket) = idle.get_mut(&key) {
                while let Some((ws, created)) = bucket.pop_front() {
                    let age = now.duration_since(created).as_secs_f64();
                    if age > 120.0 || ws.is_closed() {
                        tokio::spawn(quiet_close(ws));
                        continue;
                    }
                    STATS
                        .pool_hits
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    drop(idle);
                    self.schedule_refill(key, target_ip, domains);
                    return Some(ws);
                }
            }
        }

        STATS
            .pool_misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.schedule_refill(key, target_ip, domains);
        None
    }

    fn schedule_refill(&self, key: (u32, bool), target_ip: &str, domains: &[String]) {
        let mut refilling = self.refilling.lock().unwrap();
        if refilling.contains(&key) {
            return;
        }
        refilling.insert(key);

        let target_ip = target_ip.to_string();
        let domains = domains.to_vec();

        tokio::spawn(async move {
            let pool = &WS_POOL;
            let pool_size = {
                let cfg = PROXY_CONFIG.read().unwrap();
                cfg.pool_size
            };

            let needed = {
                let mut idle = pool.idle.lock().unwrap();
                let bucket = idle.entry(key).or_default();
                pool_size.saturating_sub(bucket.len())
            };

            if needed > 0 {
                let mut handles = Vec::new();
                for _ in 0..needed {
                    let tip = target_ip.clone();
                    let doms = domains.clone();
                    handles.push(tokio::spawn(async move {
                        connect_one(&tip, &doms).await
                    }));
                }
                for handle in handles {
                    if let Ok(Some(ws)) = handle.await {
                        let mut idle = pool.idle.lock().unwrap();
                        idle.entry(key).or_default().push_back((ws, Instant::now()));
                    }
                }
            }

            pool.refilling.lock().unwrap().remove(&key);
        });
    }

    pub async fn warmup(&self) {
        let dc_redirects = {
            let cfg = PROXY_CONFIG.read().unwrap();
            cfg.dc_redirects.clone()
        };
        for (dc, target_ip) in &dc_redirects {
            for is_media in [false, true] {
                let domains = ws_domains(*dc, is_media);
                self.schedule_refill((*dc, is_media), target_ip, &domains);
            }
        }
    }

    pub fn reset(&self) {
        self.idle.lock().unwrap().clear();
        self.refilling.lock().unwrap().clear();
    }
}

pub struct CfWorkerPool {
    idle: Mutex<HashMap<(u32, String), PoolBucket<RawWebSocket>>>,
    refilling: Mutex<HashSet<(u32, String)>>,
}

impl Default for CfWorkerPool {
    fn default() -> Self {
        Self::new()
    }
}

impl CfWorkerPool {
    pub fn new() -> Self {
        Self {
            idle: Mutex::new(HashMap::new()),
            refilling: Mutex::new(HashSet::new()),
        }
    }

    pub async fn get(
        &self,
        dc: u32,
        worker_domain: &str,
        fallback_dst: &str,
    ) -> Option<RawWebSocket> {
        let key = (dc, worker_domain.to_string());
        let now = Instant::now();

        {
            let mut idle = self.idle.lock().unwrap();
            if let Some(bucket) = idle.get_mut(&key) {
                while let Some((ws, created)) = bucket.pop_front() {
                    let age = now.duration_since(created).as_secs_f64();
                    if age > 120.0 || ws.is_closed() {
                        tokio::spawn(quiet_close(ws));
                        continue;
                    }
                    STATS
                        .cf_pool_hits
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    drop(idle);
                    self.schedule_refill(&key, fallback_dst);
                    return Some(ws);
                }
            }
        }

        STATS
            .cf_pool_misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.schedule_refill(&key, fallback_dst);
        None
    }

    fn schedule_refill(&self, key: &(u32, String), fallback_dst: &str) {
        let mut refilling = self.refilling.lock().unwrap();
        if refilling.contains(key) {
            return;
        }
        refilling.insert(key.clone());

        let key = key.clone();
        let fallback_dst = fallback_dst.to_string();

        tokio::spawn(async move {
            let pool = &CF_WORKER_POOL;
            let pool_size = {
                let cfg = PROXY_CONFIG.read().unwrap();
                cfg.pool_size
            };

            let needed = {
                let mut idle = pool.idle.lock().unwrap();
                let bucket = idle.entry(key.clone()).or_default();
                pool_size.saturating_sub(bucket.len())
            };

            if needed > 0 {
                let (dc, worker_domain) = &key;
                let path = format!("/apiws?dst={}&dc={}", fallback_dst, dc);

                let mut handles = Vec::new();
                for _ in 0..needed {
                    let wd = worker_domain.clone();
                    let p = path.clone();
                    handles.push(tokio::spawn(async move {
                        RawWebSocket::connect(&wd, &wd, std::time::Duration::from_secs(8), &p)
                            .await
                            .ok()
                    }));
                }

                for handle in handles {
                    if let Ok(Some(ws)) = handle.await {
                        let mut idle = pool.idle.lock().unwrap();
                        idle.entry(key.clone())
                            .or_default()
                            .push_back((ws, Instant::now()));
                    }
                }
            }

            pool.refilling.lock().unwrap().remove(&key);
        });
    }

    pub async fn warmup(&self) {
        let cf_worker_domains = {
            let cfg = PROXY_CONFIG.read().unwrap();
            cfg.cfproxy_worker_domains.clone()
        };
        if cf_worker_domains.is_empty() {
            return;
        }
        let dc_redirects = {
            let cfg = PROXY_CONFIG.read().unwrap();
            cfg.dc_redirects.clone()
        };
        let cf_fallbacks: HashMap<u32, String> = dc_default_ips()
            .into_iter()
            .filter(|(dc, _)| !dc_redirects.contains_key(dc))
            .map(|(k, v)| (k, v.to_string()))
            .collect();

        for worker_domain in &cf_worker_domains {
            for (dc, fallback_dst) in &cf_fallbacks {
                self.schedule_refill(&(*dc, worker_domain.clone()), fallback_dst);
            }
        }
    }

    pub fn reset(&self) {
        self.idle.lock().unwrap().clear();
        self.refilling.lock().unwrap().clear();
    }
}

async fn connect_one(target_ip: &str, domains: &[String]) -> Option<RawWebSocket> {
    for domain in domains {
        match RawWebSocket::connect(
            target_ip,
            domain,
            std::time::Duration::from_secs(8),
            "/apiws",
        )
        .await
        {
            Ok(ws) => return Some(ws),
            Err(e) => {
                if e.downcast_ref::<crate::proxy::raw_websocket::WsHandshakeError>()
                    .is_some_and(|ws_err| ws_err.is_redirect())
                {
                    continue;
                }
                return None;
            }
        }
    }
    None
}

async fn quiet_close(mut ws: RawWebSocket) {
    ws.close().await;
}

pub static WS_POOL: LazyLock<WsPool> = LazyLock::new(WsPool::new);
pub static CF_WORKER_POOL: LazyLock<CfWorkerPool> = LazyLock::new(CfWorkerPool::new);
