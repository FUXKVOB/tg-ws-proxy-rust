use std::sync::OnceLock;
use std::time::Duration;

pub struct UpdateInfo {
    pub has_update: bool,
    pub latest: String,
    pub html_url: String,
    pub download_url: Option<String>,
}

static CACHED_LATEST: OnceLock<std::sync::Mutex<Option<String>>> = OnceLock::new();
static CACHED_ETAG: OnceLock<std::sync::Mutex<Option<String>>> = OnceLock::new();

fn cached_latest() -> &'static std::sync::Mutex<Option<String>> {
    CACHED_LATEST.get_or_init(|| std::sync::Mutex::new(None))
}

fn cached_etag() -> &'static std::sync::Mutex<Option<String>> {
    CACHED_ETAG.get_or_init(|| std::sync::Mutex::new(None))
}

pub async fn check_for_update(current_version: &str) -> Result<UpdateInfo, Box<dyn std::error::Error + Send + Sync>> {
    let url = "https://api.github.com/repos/Flowseal/tg-ws-proxy/releases/latest";
    let client = reqwest::Client::builder()
        .user_agent("tg-ws-proxy")
        .timeout(Duration::from_secs(10))
        .build()?;

    let etag = cached_etag().lock().ok().and_then(|g| g.clone());

    let mut req = client.get(url);
    if let Some(etag) = &etag {
        req = req.header("If-None-Match", etag);
    }

    let resp = req.send().await?;

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        let latest = cached_latest().lock().ok().and_then(|g| g.clone()).unwrap_or_default();
        return Ok(UpdateInfo {
            has_update: false,
            latest,
            html_url: String::new(),
            download_url: None,
        });
    }

    if let Some(etag) = resp.headers().get("etag").and_then(|v| v.to_str().ok())
        && let Ok(mut cache) = cached_etag().lock()
    {
        *cache = Some(etag.to_string());
    }

    let data: serde_json::Value = resp.json().await?;

    let latest = data["tag_name"]
        .as_str()
        .unwrap_or("unknown")
        .trim_start_matches('v')
        .to_string();

    if let Ok(mut cache) = cached_latest().lock() {
        *cache = Some(latest.clone());
    }

    let html_url = data["html_url"].as_str().unwrap_or("").to_string();

    let has_update = compare_versions(&latest, current_version) > 0;

    let download_url = data["assets"]
        .as_array()
        .and_then(|assets| {
            assets.first().and_then(|a| a["browser_download_url"].as_str().map(String::from))
        });

    Ok(UpdateInfo {
        has_update,
        latest,
        html_url,
        download_url,
    })
}

fn compare_versions(a: &str, b: &str) -> i32 {
    let a_parts: Vec<u32> = a.split('.').filter_map(|s| s.parse().ok()).collect();
    let b_parts: Vec<u32> = b.split('.').filter_map(|s| s.parse().ok()).collect();
    for i in 0..a_parts.len().max(b_parts.len()) {
        let av = a_parts.get(i).copied().unwrap_or(0);
        let bv = b_parts.get(i).copied().unwrap_or(0);
        if av > bv { return 1; }
        if av < bv { return -1; }
    }
    0
}
