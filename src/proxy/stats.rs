use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::fmt;

pub struct Stats {
    pub connections_total: AtomicU64,
    pub connections_active: AtomicI64,
    pub connections_ws: AtomicU64,
    pub connections_tcp_fallback: AtomicU64,
    pub connections_cfproxy: AtomicU64,
    pub connections_bad: AtomicU64,
    pub connections_masked: AtomicU64,
    pub ws_errors: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub pool_hits: AtomicU64,
    pub pool_misses: AtomicU64,
    pub cf_pool_hits: AtomicU64,
    pub cf_pool_misses: AtomicU64,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    pub const fn new() -> Self {
        Self {
            connections_total: AtomicU64::new(0),
            connections_active: AtomicI64::new(0),
            connections_ws: AtomicU64::new(0),
            connections_tcp_fallback: AtomicU64::new(0),
            connections_cfproxy: AtomicU64::new(0),
            connections_bad: AtomicU64::new(0),
            connections_masked: AtomicU64::new(0),
            ws_errors: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            pool_hits: AtomicU64::new(0),
            pool_misses: AtomicU64::new(0),
            cf_pool_hits: AtomicU64::new(0),
            cf_pool_misses: AtomicU64::new(0),
        }
    }

    pub fn summary(&self) -> String {
        let pool_total = self.pool_hits.load(Ordering::Relaxed)
            + self.pool_misses.load(Ordering::Relaxed);
        let pool_s = if pool_total > 0 {
            format!(
                "{}/{}",
                self.pool_hits.load(Ordering::Relaxed),
                pool_total
            )
        } else {
            "n/a".into()
        };
        let cf_pool_total = self.cf_pool_hits.load(Ordering::Relaxed)
            + self.cf_pool_misses.load(Ordering::Relaxed);
        let cf_pool_s = if cf_pool_total > 0 {
            format!(
                "{}/{}",
                self.cf_pool_hits.load(Ordering::Relaxed),
                cf_pool_total
            )
        } else {
            "n/a".into()
        };
        format!(
            "total={} active={} ws={} tcp_fb={} cf={} bad={} masked={} err={} pool={} cf_pool={} up={} down={}",
            self.connections_total.load(Ordering::Relaxed),
            self.connections_active.load(Ordering::Relaxed),
            self.connections_ws.load(Ordering::Relaxed),
            self.connections_tcp_fallback.load(Ordering::Relaxed),
            self.connections_cfproxy.load(Ordering::Relaxed),
            self.connections_bad.load(Ordering::Relaxed),
            self.connections_masked.load(Ordering::Relaxed),
            self.ws_errors.load(Ordering::Relaxed),
            pool_s,
            cf_pool_s,
            human_bytes(self.bytes_up.load(Ordering::Relaxed)),
            human_bytes(self.bytes_down.load(Ordering::Relaxed)),
        )
    }
}

pub fn human_bytes(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut size = n as f64;
    for unit in &units {
        if size < 1024.0 {
            return format!("{:.1}{}", size, unit);
        }
        size /= 1024.0;
    }
    format!("{:.1}TB", size)
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}
