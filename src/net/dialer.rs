//! Outbound server links.
//!
//! Every `[[links]]` entry gets one task that dials the peer, runs the same
//! connection driver as an inbound link, and reconnects with exponential
//! backoff when the link drops. The dialling side opens with the same
//! `PASS`/`SERVER` exchange an inbound peer would send, so both ends run the
//! identical handshake and burst code.
//!
//! Retries are jittered by 20% so a network of servers reconnecting after a hub
//! restart does not synchronise into a connection storm.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::config::{Config, LinkSection};
use crate::net::connection;
use crate::server::Server;

/// How long a TCP connect or TLS handshake may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Start one dialler per configured link.
pub fn spawn_all(server: Arc<Server>) {
    for link in server.cfg().links.clone() {
        info!(
            peer = %link.name,
            address = %link.address,
            tls = link.tls,
            "outbound link configured"
        );
        let server = Arc::clone(&server);
        tokio::spawn(async move { run_link(server, link).await });
    }
}

async fn run_link(server: Arc<Server>, link: LinkSection) {
    let initial = link.retry_initial_secs.max(1);
    let maximum = link.retry_max_secs.max(initial);
    let mut delay = initial;
    loop {
        if server.route(&link.name).is_some() {
            // The peer dialled us, or another path already reaches it; a
            // second link would be refused as a cycle anyway.
            tokio::time::sleep(Duration::from_secs(initial)).await;
            continue;
        }
        match dial(Arc::clone(&server), &link).await {
            // A link that came up and later dropped starts again from the
            // shortest delay; only repeated failures back off.
            Ok(true) => delay = initial,
            Ok(false) => {}
            Err(error) => warn!(peer = %link.name, %error, "link attempt failed"),
        }
        let wait = jittered(delay);
        debug!(
            peer = %link.name,
            seconds = wait.as_secs_f64(),
            "link retry scheduled"
        );
        tokio::time::sleep(wait).await;
        delay = delay.saturating_mul(2).min(maximum);
    }
}

/// Dial once. `true` means the link was established before the socket closed.
async fn dial(server: Arc<Server>, link: &LinkSection) -> Result<bool, String> {
    let config = server.cfg();
    let password = password(&config, link)?;
    let target = format!("{}:{}", link.address, link.port);
    let address = tokio::net::lookup_host(&target)
        .await
        .map_err(|error| format!("cannot resolve {target}: {error}"))?
        .next()
        .ok_or_else(|| format!("{target} resolved to no address"))?;

    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| format!("timed out connecting to {target}"))?
        .map_err(|error| format!("cannot connect to {target}: {error}"))?;
    stream
        .set_nodelay(true)
        .map_err(|error| format!("cannot set TCP_NODELAY: {error}"))?;

    if link.tls {
        let connector = tls_connector(link)?;
        let name = link
            .tls_server_name
            .clone()
            .unwrap_or_else(|| link.name.clone());
        let server_name = rustls::pki_types::ServerName::try_from(name)
            .map_err(|error| format!("invalid TLS server name: {error}"))?;
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, stream))
            .await
            .map_err(|_| "TLS handshake timed out".to_owned())?
            .map_err(|error| format!("TLS handshake failed: {error}"))?;
        return handshake(server, stream, address, true, &password).await;
    }
    handshake(server, stream, address, false, &password).await
}

async fn handshake<S>(
    server: Arc<Server>,
    mut stream: S,
    peer: SocketAddr,
    secure: bool,
    password: &str,
) -> Result<bool, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = server.cfg();
    let opening = format!(
        "PASS {password}\r\nSERVER {} 1 {} :{}\r\n",
        config.server.name, config.server.sid, config.server.description
    );
    drop(config);
    stream
        .write_all(opening.as_bytes())
        .await
        .map_err(|error| format!("cannot send the opening handshake: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("cannot flush the opening handshake: {error}"))?;
    connection::run(server, stream, peer, secure, true, None, true)
        .await
        .map_err(|error| error.to_string())
}

/// Build a client-side TLS configuration that verifies the peer against the
/// configured authority.
///
/// Link TLS is verified, not opportunistic: a self-signed link certificate has
/// to be installed as `tls_ca_path` explicitly, which is also how a private
/// link CA is pinned.
fn tls_connector(link: &LinkSection) -> Result<tokio_rustls::TlsConnector, String> {
    let path = link
        .tls_ca_path
        .as_deref()
        .ok_or_else(|| "tls_ca_path is required when tls is enabled".to_owned())?;
    let pem = std::fs::read(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    let mut reader = std::io::BufReader::new(pem.as_slice());
    let certificates: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot parse {path}: {error}"))?;
    if certificates.is_empty() {
        return Err(format!("{path} contains no certificates"));
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|error| format!("invalid authority certificate in {path}: {error}"))?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("unsupported TLS versions: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

fn password(config: &Config, link: &LinkSection) -> Result<String, String> {
    let variable = link
        .password_env
        .as_deref()
        .or(config.server.link_password_env.as_deref())
        .ok_or_else(|| "no link password is configured".to_owned())?;
    let value = std::env::var(variable)
        .map_err(|_| format!("environment variable {variable} is not set"))?;
    if value.is_empty() {
        return Err(format!("environment variable {variable} is empty"));
    }
    Ok(value)
}

/// Apply up to 20% jitter so reconnecting servers do not retry in lockstep.
fn jittered(seconds: u64) -> Duration {
    let factor = 0.8 + rand::random::<f64>() * 0.4;
    Duration::from_secs_f64((seconds as f64 * factor).max(0.1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link() -> LinkSection {
        LinkSection {
            name: "peer.test".to_owned(),
            address: "127.0.0.1".to_owned(),
            ..LinkSection::default()
        }
    }

    #[test]
    fn jitter_stays_near_the_requested_delay() {
        for _ in 0..50 {
            let wait = jittered(10);
            assert!(wait >= Duration::from_secs(8), "{wait:?} was too short");
            assert!(wait <= Duration::from_secs(12), "{wait:?} was too long");
        }
    }

    #[test]
    fn missing_environment_variables_are_reported() {
        std::env::remove_var("RS_IRCD_TEST_DIALER_ABSENT");
        let mut config = Config::default();
        config.server.link_password_env = Some("RS_IRCD_TEST_DIALER_ABSENT".to_owned());
        assert!(password(&config, &link()).is_err());
    }

    #[test]
    fn tls_without_an_authority_is_reported() {
        let mut link = link();
        link.tls = true;
        assert!(tls_connector(&link).is_err());
    }

    #[test]
    fn empty_authority_files_are_reported() {
        let directory = tempfile::tempdir().expect("temp dir");
        let authority = directory.path().join("ca.pem");
        std::fs::write(&authority, "").expect("write");
        let mut link = link();
        link.tls = true;
        link.tls_ca_path = Some(authority.to_string_lossy().into_owned());
        assert!(tls_connector(&link).is_err());
    }
}
