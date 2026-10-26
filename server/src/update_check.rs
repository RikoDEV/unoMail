//! Whether a newer unoMail release is out: the latest GitHub release compared with the running
//! version. The answer is cached, so the administration pages ask GitHub at most a few times a day.

use std::{sync::Mutex, time::Duration};

use serde::Serialize;

use crate::{app::App, util::now};

/// The running version: the release tag a release build was made from, else the crate's own.
pub const VERSION: &str = match option_env!("UNOMAIL_VERSION") {
    // Empty when a Docker build gets no version argument.
    Some(version) if !version.is_empty() => version,
    _ => env!("CARGO_PKG_VERSION"),
};

const LATEST_RELEASE: &str = "https://api.github.com/repos/RikoDEV/unoMail/releases/latest";
const CACHE_FOR: i64 = 12 * 3600;
/// After a failure, try again sooner than after an answer.
const RETRY_AFTER: i64 = 15 * 60;

#[derive(Clone, Debug, Serialize)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub published_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub current: &'static str,
    pub latest: Option<Release>,
    pub update_available: bool,
    pub checked_at: i64,
    pub error: Option<String>,
}

static CACHE: Mutex<Option<Status>> = Mutex::new(None);

/// The release status, from the cache unless it is stale or `refresh` is asked for.
pub async fn status(app: &App, refresh: bool) -> Status {
    if !refresh && let Some(cached) = CACHE.lock().unwrap().clone() {
        let age = now() - cached.checked_at;
        if age < if cached.error.is_some() { RETRY_AFTER } else { CACHE_FOR } {
            return cached;
        }
    }
    let status = match latest(&app.http).await {
        Ok(release) => Status { current: VERSION, update_available: newer(&release.version, VERSION), latest: Some(release), checked_at: now(), error: None },
        Err(err) => {
            tracing::warn!(%err, "update check failed");
            Status { current: VERSION, latest: None, update_available: false, checked_at: now(), error: Some("GitHub could not be reached".into()) }
        }
    };
    *CACHE.lock().unwrap() = Some(status.clone());
    status
}

async fn latest(http: &reqwest::Client) -> anyhow::Result<Release> {
    #[derive(serde::Deserialize)]
    struct GitHubRelease { tag_name: String, html_url: String, published_at: Option<String> }
    let release: GitHubRelease = http
        .get(LATEST_RELEASE)
        .header("User-Agent", "unoMail")
        .header("Accept", "application/vnd.github+json")
        .timeout(Duration::from_secs(10))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    // Only a link to the project's own releases is passed on to the page.
    anyhow::ensure!(release.html_url.starts_with("https://github.com/RikoDEV/unoMail/releases/"), "unexpected release address");
    Ok(Release { version: release.tag_name.trim_start_matches('v').to_owned(), url: release.html_url, published_at: release.published_at })
}

/// Whether `candidate` is a later version than `current`, comparing the dotted numbers. A
/// version that is not plain numbers (a pre-release, a development build) is never "newer".
pub fn newer(candidate: &str, current: &str) -> bool {
    let parse = |v: &str| -> Option<Vec<u64>> { v.trim_start_matches('v').split('.').map(|part| part.parse().ok()).collect() };
    match (parse(candidate), parse(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::newer;

    #[test]
    fn compares_versions_by_number() {
        assert!(newer("1.0.8", "1.0.7"));
        assert!(newer("v1.10.0", "1.9.9"));
        assert!(newer("2.0", "1.99.99"));
        assert!(!newer("1.0.7", "1.0.7"));
        assert!(!newer("1.0.6", "1.0.7"));
        assert!(!newer("1.1.0-rc.1", "1.0.7"));
        assert!(!newer("1.0.8", "dev"));
    }
}
