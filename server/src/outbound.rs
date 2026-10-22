//! HTTP clients for the requests the server makes to other hosts, and the checks that keep
//! user-supplied addresses from reaching internal services.

use std::{net::SocketAddr, time::Duration};

use crate::{app::App, error::ApiError, security::reputation::is_private};

/// A client builder that verifies certificates against the web's root authorities.
pub fn builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().use_preconfigured_tls((*crate::smtp::client::tls_config(true)).clone())
}

/// A client that connects `host` to exactly `addr` (the address that was checked) and never
/// follows a redirect on its own: each hop has to be checked again.
pub fn pinned(host: &str, addr: SocketAddr, timeout: Duration) -> reqwest::Result<reqwest::Client> {
    builder().resolve(host, addr).redirect(reqwest::redirect::Policy::none()).timeout(timeout).build()
}

/// Resolves the host of `url` and returns the address to connect to, refusing anything that is
/// not a public web server.
pub async fn public_target(state: &App, url: &reqwest::Url, ports: &[u16]) -> Result<(String, SocketAddr), ApiError> {
    let refuse = || ApiError::bad("this address cannot be reached");
    if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty() || url.password().is_some() {
        return Err(refuse());
    }
    let host = url.host_str().ok_or_else(refuse)?.trim_matches(['[', ']']).to_owned();
    let port = url.port_or_known_default().ok_or_else(refuse)?;
    let lenient = state.cfg.allow_private_destinations;
    if !lenient && !ports.contains(&port) {
        return Err(refuse());
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port)).await.map_err(|_| refuse())?.collect();
    // Every address must be public: the server must not become a way to reach internal hosts.
    if addrs.is_empty() || (!lenient && addrs.iter().any(|a| is_private(a.ip()))) {
        return Err(refuse());
    }
    Ok((host, addrs[0]))
}

/// [`public_target`] followed by [`pinned`]: a client for one request to a public `url`.
pub async fn to_public(state: &App, url: &reqwest::Url, ports: &[u16], timeout: Duration) -> Result<reqwest::Client, ApiError> {
    let (host, addr) = public_target(state, url, ports).await?;
    Ok(pinned(&host, addr, timeout).map_err(anyhow::Error::from)?)
}
