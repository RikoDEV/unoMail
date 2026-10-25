//! Fetching a package from a git repository: one commit, no history, no hooks, no submodules.
//!
//! The `git` program does the work, locked down by configuration given on its command line:
//! only https (redirects refused), no credential prompts, no hooks, no symlinks, no user or
//! system configuration. The checkout is then inspected before anything trusts it.

use std::{path::Path, process::Stdio, time::Duration};

use tokio::process::Command;

const TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_PACKAGE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_FILES: usize = 2000;

/// Checks a repository address before git is pointed at it.
pub async fn check_url(url: &str, allow_local: bool, allow_private: bool) -> Result<String, String> {
    let parsed = reqwest::Url::parse(url.trim()).map_err(|_| "invalid repository address".to_owned())?;
    if allow_local && parsed.scheme() == "file" {
        return Ok(parsed.to_string());
    }
    if parsed.scheme() != "https" {
        return Err("repositories must be fetched over https".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("the address must not contain credentials".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("the address must not have a query or fragment".into());
    }
    // The same rule as webhooks: the host must resolve to public addresses only.
    let local = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if local && !allow_private {
        return Err("refused: private address".into());
    }
    crate::webhooks::destination(parsed.as_str(), allow_private).await.map_err(str::to_owned)?;
    Ok(parsed.to_string())
}

/// A tag, branch or commit as the administrator typed it.
pub fn valid_ref(git_ref: &str) -> bool {
    !git_ref.is_empty()
        && git_ref.len() <= 100
        && !git_ref.starts_with('-')
        && !git_ref.contains("..")
        && git_ref.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/'))
}

fn is_commit(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn git(allow_local: bool) -> Command {
    let mut command = Command::new("git");
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", if cfg!(windows) { "NUL" } else { "/dev/null" })
        .env("GIT_ASKPASS", if cfg!(windows) { "NUL" } else { "/bin/false" })
        .args(["-c", "protocol.allow=never", "-c", "protocol.https.allow=always"])
        .args(["-c", if allow_local { "protocol.file.allow=always" } else { "protocol.file.allow=never" }])
        .args(["-c", "http.followRedirects=false", "-c", "credential.helper=", "-c", "core.symlinks=false"])
        .args(["-c", "core.hooksPath=/dev/null", "-c", "submodule.recurse=false", "-c", "core.fsmonitor=false"])
        .stdin(Stdio::null())
        .kill_on_drop(true);
    if let Some(root) = std::env::var_os("SYSTEMROOT") {
        command.env("SYSTEMROOT", root);
    }
    command
}

async fn run(mut command: Command) -> Result<String, String> {
    let output = tokio::time::timeout(TIMEOUT, command.output()).await.map_err(|_| "the repository took too long to respond".to_owned())?.map_err(|_| "git is not installed on the server".to_owned())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let reason = stderr.lines().find(|l| l.starts_with("fatal:")).unwrap_or("git failed").trim_start_matches("fatal:").trim();
        return Err(crate::util::sanitize_line(&reason.chars().take(200).collect::<String>()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The commit `git_ref` names in the repository. A full commit hash is taken as it is.
pub async fn resolve(url: &str, git_ref: &str, allow_local: bool) -> Result<String, String> {
    if is_commit(git_ref) {
        return Ok(git_ref.to_owned());
    }
    let mut command = git(allow_local);
    command.args(["ls-remote", "--", url, git_ref, &format!("{git_ref}^{{}}")]);
    let listing = run(command).await?;
    // An annotated tag lists the tag object and, with ^{}, the commit it points to.
    let mut lines: Vec<(&str, &str)> = listing.lines().filter_map(|l| l.split_once('\t')).collect();
    lines.sort_by_key(|(_, name)| !name.ends_with("^{}"));
    lines.into_iter().map(|(hash, _)| hash).find(|hash| is_commit(hash)).map(str::to_owned).ok_or_else(|| format!("no tag, branch or commit named {}", crate::util::sanitize_line(git_ref)))
}

/// Fetches exactly `commit` into the empty directory `dest`, and removes the repository data.
pub async fn fetch(url: &str, git_ref: &str, commit: &str, dest: &Path, allow_local: bool) -> Result<(), String> {
    tokio::fs::create_dir_all(dest).await.map_err(|e| e.to_string())?;
    let dir = dest.to_string_lossy().into_owned();
    let mut init = git(allow_local);
    init.args(["init", "--quiet", "--", &dir]);
    run(init).await?;
    // Fetching by name works with every server; fetching a bare commit needs server support.
    let wanted = if is_commit(git_ref) { commit } else { git_ref };
    let mut fetch = git(allow_local);
    fetch.args(["-C", &dir, "fetch", "--quiet", "--depth", "1", "--no-tags", "--no-recurse-submodules", "--", url, wanted]);
    run(fetch).await?;
    let mut head = git(allow_local);
    head.args(["-C", &dir, "rev-parse", "FETCH_HEAD^{commit}"]);
    if run(head).await?.trim() != commit {
        return Err("the repository changed while it was being fetched; try again".into());
    }
    let mut checkout = git(allow_local);
    checkout.args(["-C", &dir, "checkout", "--quiet", "--detach", "FETCH_HEAD"]);
    run(checkout).await?;
    tokio::fs::remove_dir_all(dest.join(".git")).await.map_err(|e| e.to_string())?;
    inspect(dest).await
}

/// Refuses checkouts with links, too many files or too much data.
pub async fn inspect(root: &Path) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    let (mut files, mut bytes) = (0usize, 0u64);
    while let Some(dir) = pending.pop() {
        let mut entries = tokio::fs::read_dir(&dir).await.map_err(|e| e.to_string())?;
        while let Some(entry) = entries.next_entry().await.map_err(|e| e.to_string())? {
            let meta = tokio::fs::symlink_metadata(entry.path()).await.map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() {
                return Err("packages must not contain symbolic links".into());
            }
            if meta.is_dir() {
                pending.push(entry.path());
                continue;
            }
            files += 1;
            bytes += meta.len();
            if files > MAX_FILES || bytes > MAX_PACKAGE_BYTES {
                return Err(format!("packages may hold at most {MAX_FILES} files and {} MB", MAX_PACKAGE_BYTES / 1024 / 1024));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_public_https_repositories_are_fetched() {
        for bad in ["http://example.com/x.git", "file:///etc", "ext::sh -c id", "https://user:pw@example.com/x.git", "https://example.com/x.git?a=1", "ssh://git@example.com/x", "https://127.0.0.1/x.git", "https://localhost/x.git"] {
            assert!(check_url(bad, false, false).await.is_err(), "{bad}");
        }
    }

    #[test]
    fn refs_cannot_become_options() {
        assert!(valid_ref("v1.2.0") && valid_ref("main") && valid_ref("release/2"));
        for bad in ["", "-u", "--upload-pack=x", "a..b", "a b", "a;b"] {
            assert!(!valid_ref(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn symbolic_links_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.js"), "x").unwrap();
        assert!(inspect(dir.path()).await.is_ok());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", dir.path().join("link")).unwrap();
            assert!(inspect(dir.path()).await.is_err());
        }
    }
}
