//! HTTP/HTTPS listener: serves the router over plain TCP or TLS with HTTP/1.1 and HTTP/2.

use std::{collections::HashMap, sync::{Arc, LazyLock}, time::Duration};

use axum::{Extension, Router};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::{api::PeerAddr, net::HANDSHAKE_TIMEOUT};

/// Time a client gets to send its request headers; bounds slow-header (slowloris) attacks.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
static CONNECTIONS: LazyLock<parking_lot::Mutex<HashMap<String, usize>>> = LazyLock::new(Default::default);
struct ConnectionSlot(String);
impl ConnectionSlot {
    fn take(ip: std::net::IpAddr) -> Option<Self> {
        let network = crate::auth::network(ip);
        let mut open = CONNECTIONS.lock();
        if open.values().sum::<usize>() >= 512 || open.get(&network).copied().unwrap_or(0) >= 128 { return None; }
        *open.entry(network.clone()).or_default() += 1;
        Some(Self(network))
    }
}
impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let mut open = CONNECTIONS.lock();
        if let Some(count) = open.get_mut(&self.0) { *count -= 1; if *count == 0 { open.remove(&self.0); } }
    }
}

pub async fn serve(listener: TcpListener, router: Router, tls: Option<Arc<ServerConfig>>) {
    let acceptor = tls.map(TlsAcceptor::from);
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(%err, "failed to accept HTTP connection");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(slot) = ConnectionSlot::take(peer.ip()) else { drop(tcp); continue };
        let service = TowerToHyperService::new(router.clone().layer(Extension(PeerAddr(peer))));
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let _ = tcp.set_nodelay(true);
            let mut builder = Builder::new(TokioExecutor::new());
            builder.http1().timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT);
            builder.http2().timer(TokioTimer::new()).keep_alive_interval(Some(Duration::from_secs(30))).max_concurrent_streams(32);
            let result = match acceptor {
                Some(acceptor) => match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(stream)) => builder.serve_connection_with_upgrades(TokioIo::new(stream), service).await,
                    Ok(Err(err)) => {
                        tracing::debug!(%err, %peer, "TLS handshake failed");
                        return;
                    }
                    Err(_) => return,
                },
                None => builder.serve_connection_with_upgrades(TokioIo::new(tcp), service).await,
            };
            if let Err(err) = result {
                tracing::debug!(%err, %peer, "HTTP connection ended with an error");
            }
        });
    }
}
