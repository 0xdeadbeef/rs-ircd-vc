//! Network layer: listener binding and connection supervision.

pub mod compress;
pub mod connection;
pub mod dialer;
pub mod tls;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::config::{Config, ListenSection};
use crate::error::{Error, Result};
use crate::logging::LoggingHandle;
use crate::server::Server;

/// How long a peer may take to complete the TLS handshake.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// A bound TCP listener with its per-socket policy.
pub struct Listener {
    /// The bound socket.
    pub tcp: TcpListener,
    /// Configuration section that produced it.
    pub section: ListenSection,
    /// TLS acceptor, when the listener is encrypted.
    pub acceptor: Option<TlsAcceptor>,
    /// Effective local address.
    pub local: SocketAddr,
}

/// Bind every configured address.
///
/// IPv6 sockets always set `IPV6_V6ONLY` so that `[::]` and `0.0.0.0` on the
/// same port do not collide, matching the operator's intent of "all IPv4" and
/// "all IPv6" as separate families.
///
/// # Errors
///
/// Returns [`Error::Io`] when a socket cannot be created or bound, and
/// [`Error::Tls`] when TLS material is unusable.
pub fn bind(config: &Config) -> Result<Vec<Listener>> {
    let mut listeners = Vec::new();
    // Only the sections that ask for TLS get an acceptor; a plaintext port on
    // the same server must stay plaintext.
    let mut shared: Option<TlsAcceptor> = None;
    for section in &config.listen {
        let acceptor = if section.tls {
            match &shared {
                Some(acceptor) => Some(acceptor.clone()),
                None => {
                    let acceptor = tls::acceptor(&config.tls)?;
                    shared = Some(acceptor.clone());
                    Some(acceptor)
                }
            }
        } else {
            None
        };
        for address in &section.addresses {
            let socket_address = SocketAddr::new(*address, section.port);
            let tcp = bind_one(socket_address)?;
            let local = tcp.local_addr()?;
            listeners.push(Listener {
                tcp,
                section: section.clone(),
                acceptor: acceptor.clone(),
                local,
            });
        }
    }
    if listeners.is_empty() {
        return Err(Error::Config("no listen addresses configured".to_owned()));
    }
    Ok(listeners)
}

fn bind_one(address: SocketAddr) -> Result<TcpListener> {
    let domain = if address.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    let listener = std::net::TcpListener::from(socket);
    Ok(TcpListener::from_std(listener)?)
}

/// Bind every listener and serve until a shutdown signal arrives.
///
/// # Errors
///
/// Propagates binding failures and shutdown join errors.
pub async fn run(server: Arc<Server>, logging: Arc<LoggingHandle>) -> Result<()> {
    server.attach_logging(Arc::clone(&logging));
    let listeners = bind(&server.cfg())?;
    for listener in listeners {
        info!(
            address = %listener.local,
            tls = listener.acceptor.is_some(),
            server_link = listener.section.server_link,
            "listening"
        );
        spawn_accept_loop(Arc::clone(&server), listener);
    }
    dialer::spawn_all(Arc::clone(&server));
    server.spawn_invite_sweeper();
    info!(server = %server.cfg().server.name, "server ready");
    wait_for_shutdown(Arc::clone(&server), &logging).await;
    info!("shutting down");
    server.shutdown();
    Ok(())
}

/// SHA-256 fingerprint of the peer's client certificate, when it sent one.
fn certificate_fingerprint<T>(stream: &tokio_rustls::server::TlsStream<T>) -> Option<Arc<str>> {
    let (_, session) = stream.get_ref();
    session
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .map(|certificate| Arc::from(crate::util::sha256_hex(certificate.as_ref())))
}

/// Serve an already-bound listener; used by tests and embedded callers.
pub fn spawn_accept_loop(server: Arc<Server>, listener: Listener) {
    tokio::spawn(async move {
        loop {
            match listener.tcp.accept().await {
                Ok((stream, peer)) => {
                    let server = Arc::clone(&server);
                    let acceptor = listener.acceptor.clone();
                    let server_link = listener.section.server_link;
                    tokio::spawn(async move {
                        if let Err(error) = stream.set_nodelay(true) {
                            debug!(%peer, %error, "cannot set TCP_NODELAY");
                        }
                        let result = match acceptor {
                            Some(acceptor) => {
                                match tokio::time::timeout(
                                    TLS_HANDSHAKE_TIMEOUT,
                                    acceptor.accept(stream),
                                )
                                .await
                                {
                                    Ok(Ok(stream)) => {
                                        let certificate = certificate_fingerprint(&stream);
                                        connection::run(
                                            server,
                                            stream,
                                            peer,
                                            true,
                                            server_link,
                                            certificate,
                                            false,
                                        )
                                        .await
                                    }
                                    Ok(Err(error)) => {
                                        debug!(%peer, %error, "tls handshake failed");
                                        return;
                                    }
                                    Err(_) => {
                                        debug!(%peer, "tls handshake timed out");
                                        return;
                                    }
                                }
                            }
                            None => {
                                connection::run(
                                    server,
                                    stream,
                                    peer,
                                    false,
                                    server_link,
                                    None,
                                    false,
                                )
                                .await
                            }
                        };
                        if let Err(error) = result {
                            debug!(%peer, %error, "connection ended with error");
                        }
                    });
                }
                Err(error) => {
                    // Descriptor exhaustion must not spin the accept loop.
                    warn!(%error, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    });
}

async fn wait_for_shutdown(server: Arc<Server>, logging: &Arc<LoggingHandle>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                error!(%error, "cannot install SIGTERM handler");
                return;
            }
        };
        let mut hangup = match signal(SignalKind::hangup()) {
            Ok(signal) => signal,
            Err(error) => {
                error!(%error, "cannot install SIGHUP handler");
                return;
            }
        };
        let mut interrupt = match signal(SignalKind::interrupt()) {
            Ok(signal) => signal,
            Err(error) => {
                error!(%error, "cannot install SIGINT handler");
                return;
            }
        };
        loop {
            tokio::select! {
                _ = terminate.recv() => break,
                _ = interrupt.recv() => break,
                _ = hangup.recv() => match server.rehash(logging) {
                    Ok(()) => info!("configuration reloaded"),
                    Err(error) => error!(%error, "rehash failed"),
                },
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = logging;
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ListenSection};
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn binds_ephemeral_port_on_ipv4() {
        let mut config = Config::default();
        config.listen.push(ListenSection {
            addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            port: 0,
            ..ListenSection::default()
        });
        let listeners = bind(&config).expect("bind");
        assert_eq!(listeners.len(), 1);
        assert!(listeners[0].local.is_ipv4());
        assert!(listeners[0].tcp.local_addr().is_ok());
    }

    #[tokio::test]
    async fn binds_ipv6_when_the_host_supports_it() {
        let mut config = Config::default();
        config.listen.push(ListenSection {
            addresses: vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)],
            port: 0,
            ..ListenSection::default()
        });
        // Some containers disable IPv6 entirely; that is an environment
        // limitation, not a server bug.
        if let Ok(listeners) = bind(&config) {
            assert_eq!(listeners.len(), 1);
            assert!(listeners[0].local.is_ipv6());
        }
    }

    #[test]
    fn tls_listener_without_material_fails() {
        let mut config = Config::default();
        config.listen.push(ListenSection {
            addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            port: 0,
            tls: true,
            ..ListenSection::default()
        });
        assert!(matches!(bind(&config), Err(Error::Tls(_))));
    }
}
