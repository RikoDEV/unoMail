//! The document a plug-in runs in: a sandboxed frame with the SDK and the plug-in inlined.
//!
//! The web client loads it in `<iframe sandbox="allow-scripts">`; the `sandbox` directive of
//! the policy below applies the same restrictions if it is ever opened on its own. Without
//! `allow-same-origin` the frame has an opaque origin, so it cannot read the page, its cookies
//! or the API. Scripts are inlined and allowed by hash, which needs no origin to match
//! against; network access is limited to the hosts the manifest declared.

use base64::{Engine, engine::general_purpose::STANDARD};


pub const SDK: &str = include_str!("../../assets/plugin-sdk.js");

/// Script text as it can sit inside `<script>` without ending it early.
fn inline(script: &str) -> String {
    script.replace("</script", "<\\/script").replace("</SCRIPT", "<\\/SCRIPT").replace("<!--", "<\\!--")
}

fn hash(script: &str) -> String {
    format!("'sha256-{}'", STANDARD.encode(crate::util::sha256(script.as_bytes())))
}

/// The frame's HTML and its Content-Security-Policy.
pub fn document(permissions: &[String], entry: &str) -> (String, String) {
    let sdk = inline(SDK);
    let plugin = inline(entry);
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <style>html{{color-scheme:light dark}}body{{margin:0;font:14px system-ui,sans-serif}}</style>\
         <script>{sdk}</script><script type=\"module\">{plugin}</script></head><body></body></html>"
    );
    let hosts: Vec<String> = permissions.iter().filter_map(|p| p.strip_prefix("network:")).map(|host| format!("https://{host}")).collect();
    let connect = if hosts.is_empty() { "'none'".to_owned() } else { hosts.join(" ") };
    let policy = format!(
        "default-src 'none'; script-src {} {}; style-src 'unsafe-inline'; img-src data: blob:; font-src data:; \
         connect-src {connect}; form-action 'none'; base-uri 'none'; frame-ancestors 'self'; sandbox allow-scripts",
        hash(&sdk),
        hash(&plugin)
    );
    (html, policy)
}

/// The page an OAuth provider sends the sign-in window back to. It hands the answer (the
/// query string) to the web client over a same-origin `BroadcastChannel`, which works even
/// though the provider's pages cut the window off from its opener, and closes the window.
/// The client matches the answer to the plug-in that asked by its `state`.
pub fn auth_callback() -> (String, String) {
    let script = "new BroadcastChannel('unomail-plugin-auth').postMessage({ search: location.search, hash: location.hash });\
                  document.getElementById('done').hidden = false; setTimeout(() => window.close(), 300);";
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>unoMail</title><style>body{{font:15px system-ui,sans-serif;margin:3em;text-align:center;color-scheme:light dark}}</style></head>\
         <body><p id=\"done\" hidden>You are signed in. You can close this window.</p><script>{script}</script></body></html>"
    );
    let policy = format!("default-src 'none'; script-src {}; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", hash(script));
    (html, policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_cannot_end_their_tag_and_network_is_declared_hosts_only() {
        let (html, policy) = document(&["notify".into(), "network:api.example.com".into()], "x = '</script><img src=x onerror=alert(1)>';");
        assert!(!html.contains("</script><img"));
        assert!(policy.contains("connect-src https://api.example.com;"));
        assert!(policy.contains("sandbox allow-scripts") && !policy.contains("allow-same-origin"));
        let (_, closed) = document(&[], "");
        assert!(closed.contains("connect-src 'none'"));
    }
}
