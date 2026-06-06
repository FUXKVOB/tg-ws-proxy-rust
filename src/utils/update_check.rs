use std::sync::OnceLock;
use std::time::Duration;

pub struct UpdateInfo {
    pub has_update: bool,
    pub latest: String,
    pub html_url: String,
    pub download_url: Option<String>,
}

static CACHED_ETAG: OnceLock<std::sync::Mutex<Option<String>>> = OnceLock::new();

fn cached_etag() -> &'static std::sync::Mutex<Option<String>> {
    CACHED_ETAG.get_or_init(|| std::sync::Mutex::new(None))
}

fn cache_path() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    let dir = exe.parent().unwrap_or(std::path::Path::new("."));
    dir.join(".update_cache")
}

fn read_cached_latest() -> Option<String> {
    std::fs::read_to_string(cache_path()).ok().filter(|s| !s.is_empty())
}

fn write_cached_latest(ver: &str) {
    let _ = std::fs::write(cache_path(), ver);
}

pub async fn check_for_update(current_version: &str) -> Result<UpdateInfo, Box<dyn std::error::Error + Send + Sync>> {
    let url = "https://api.github.com/repos/Flowseal/tg-ws-proxy/releases/latest";
    let client = reqwest::Client::builder()
        .user_agent("tg-ws-proxy")
        .timeout(Duration::from_secs(10))
        .build()?;

    let etag = cached_etag().lock().ok().and_then(|g| g.clone());

    let mut req = client.get(url);
    if let Some(ref etag) = etag {
        req = req.header("If-None-Match", etag);
    }
    let resp = req.send().await?;

    if resp.status() == 304 {
        let cached = cached_latest().unwrap_or_default();
        return Ok(UpdateInfo {
            has_update: !cached.is_empty() && cached != current_version,
            latest: cached,
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
    let html_url = data["html_url"].as_str().unwrap_or("").to_string();
    let download_url = data["assets"]
        .as_array()
        .and_then(|assets| assets.first())
        .and_then(|a| a["browser_download_url"].as_str())
        .map(|s| s.to_string());

    write_cached_latest(&latest);

    Ok(UpdateInfo {
        has_update: latest != current_version,
        latest,
        html_url,
        download_url,
    })
}

fn cached_latest() -> Option<String> {
    let cached = read_cached_latest();
    if cached.as_ref().is_some_and(|s| !s.is_empty()) { cached } else { None }
}
