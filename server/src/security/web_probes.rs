//! Web vulnerability scanners: requests for paths that only exist in other software (PHP
//! applications, leaked configuration, admin panels). This server has none of them, so a
//! client asking for several within a short time is scanning, and is reported to AbuseIPDB.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::app::App;
use crate::security::reputation::{self, Abuse};
use crate::util::now;

/// Probes from one address within [`WINDOW_SECS`] before it is reported.
const THRESHOLD: u32 = 3;
const WINDOW_SECS: i64 = 10 * 60;
/// Addresses tracked at once; old entries are dropped beyond this.
const MAX_TRACKED: usize = 10_000;

/// Paths (compared in lower case) that no unoMail page or API ever uses.
const PREFIXES: &[&str] = &[
    "/wp-", "/wordpress", "/xmlrpc.php", "/.env", "/.git", "/.svn", "/.hg/", "/.aws", "/.ssh", "/.htaccess", "/.htpasswd", "/.ds_store",
    "/phpmyadmin", "/pma/", "/myadmin", "/mysqladmin", "/adminer", "/vendor/phpunit", "/cgi-bin/", "/boaform", "/hnap1", "/actuator",
    "/server-status", "/solr/", "/console/", "/manager/html", "/owa/auth", "/ecp/", "/remote/fgt_lang", "/shell", "/setup.cgi",
    "/config.json", "/debug/", "/telescope", "/_ignition", "/druid/", "/jenkins", "/geoserver",
];
/// File endings of software this server does not run.
const SUFFIXES: &[&str] = &[".php", ".asp", ".aspx", ".jsp", ".cgi", ".env", ".sql", ".bak", ".old", "web.config", "wp-config.php.bak"];

/// Whether `path` asks for something only other software has.
pub fn is_probe(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    // The server's own routes; plug-in assets are served under their own paths.
    if ["/api/", "/jmap", "/dav", "/package-asset/", "/plugin-frame/", "/.well-known/"].iter().any(|own| path.starts_with(own)) {
        return false;
    }
    PREFIXES.iter().any(|prefix| path.starts_with(prefix)) || SUFFIXES.iter().any(|suffix| path.ends_with(suffix))
}

/// Recent probes per address: how many, and since when.
#[derive(Default)]
pub struct WebProbes(parking_lot::Mutex<HashMap<IpAddr, (u32, i64)>>);

/// Counts a request for `path` from `ip`; the [`THRESHOLD`]th probe within the window is
/// reported (once per window).
pub fn note(app: &App, ip: IpAddr, path: &str) {
    if !is_probe(path) {
        return;
    }
    let now = now();
    let reached = {
        let mut seen = app.web_probes.0.lock();
        if seen.len() >= MAX_TRACKED {
            seen.retain(|_, (_, since)| now - *since < WINDOW_SECS);
        }
        let entry = seen.entry(ip).or_insert((0, now));
        if now - entry.1 >= WINDOW_SECS {
            *entry = (0, now);
        }
        entry.0 += 1;
        entry.0 == THRESHOLD
    };
    if reached {
        tracing::info!(%ip, path, "web vulnerability scan");
        reputation::report_abuse(app, ip, Abuse::WebScan);
    }
}

#[cfg(test)]
mod tests {
    use super::is_probe;

    #[test]
    fn only_paths_of_other_software_are_probes() {
        for path in ["/wp-login.php", "/WP-ADMIN/", "/.env", "/.git/config", "/index.php", "/phpmyadmin/", "/vendor/phpunit/src/Util/PHP/eval-stdin.php", "/cgi-bin/luci"] {
            assert!(is_probe(path), "{path}");
        }
        for path in ["/", "/mail/inbox", "/admin/mailboxes", "/api/auth/login", "/assets/index-abc.js", "/dav/calendars/x", "/.well-known/caldav", "/autodiscover/autodiscover.xml", "/environment"] {
            assert!(!is_probe(path), "{path}");
        }
    }
}
