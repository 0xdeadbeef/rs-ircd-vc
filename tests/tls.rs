//! TLS end-to-end tests: handshake, registration, and SASL `EXTERNAL`.
//!
//! Neither side trusts a certificate authority here: the server pins client
//! certificates by fingerprint, so the test proves the fingerprint reaches the
//! account backend through a real handshake.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ircd::auth::{AccountBackend, Credential};
use ircd::config::{Config, ListenSection, TlsSection};
use ircd::net;
use ircd::server::Server;
use ircd::util::sha256_hex;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Verifier that accepts the self-signed test certificate.
///
/// Signature verification still runs, so the handshake exercises real
/// cryptography; only the trust anchor is bypassed, which is correct for a
/// throwaway certificate.
#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

type ClientReader = BufReader<ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>>;
type ClientWriter = WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>;

fn connector(
    client_certificate: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)));
    let config = match client_certificate {
        Some((chain, key)) => builder
            .with_client_auth_cert(chain, key)
            .expect("client certificate"),
        None => builder.with_no_client_auth(),
    };
    TlsConnector::from(Arc::new(config))
}

/// Start a TLS-only server on an ephemeral loopback port.
async fn start_server(request_client_certs: bool) -> (Arc<Server>, SocketAddr) {
    let directory = tempfile::tempdir().expect("temp dir");
    let certified =
        rcgen::generate_simple_self_signed(vec!["irc.test".to_owned()]).expect("certificate");
    let certificate_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&certificate_path, certified.cert.pem()).expect("write cert");
    std::fs::write(&key_path, certified.key_pair.serialize_pem()).expect("write key");

    let mut config = Config::default();
    config.server.name = "irc.test".to_owned();
    config.tls = TlsSection {
        cert_path: Some(certificate_path.to_string_lossy().into_owned()),
        key_path: Some(key_path.to_string_lossy().into_owned()),
        request_client_certs,
        ..TlsSection::default()
    };
    config.listen.push(ListenSection {
        addresses: vec!["127.0.0.1".parse().expect("ipv4")],
        port: 0,
        tls: true,
        server_link: false,
    });

    let config = Arc::new(config);
    let server = Server::new(Arc::clone(&config), None).expect("server state");
    let listeners = net::bind(&config).expect("bind tls listener");
    let address = listeners[0].local;
    assert!(listeners[0].acceptor.is_some(), "TLS acceptor missing");
    for listener in listeners {
        net::spawn_accept_loop(Arc::clone(&server), listener);
    }
    (server, address)
}

/// Connect over TLS, optionally presenting a client certificate.
async fn connect(
    address: SocketAddr,
    client_certificate: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> (ClientReader, ClientWriter) {
    let stream = TcpStream::connect(address).await.expect("tcp connect");
    let server_name = ServerName::try_from("irc.test").expect("server name");
    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        connector(client_certificate).connect(server_name, stream),
    )
    .await
    .expect("handshake timeout")
    .expect("handshake");
    let (read, write) = tokio::io::split(stream);
    (BufReader::new(read), write)
}

/// Read lines until one contains `needle`, returning everything seen.
async fn read_until<R>(reader: &mut BufReader<R>, needle: &str) -> Vec<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut seen = Vec::new();
    for _ in 0..60 {
        let mut line = String::new();
        let read = tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line))
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {needle:?}; saw {seen:?}"))
            .expect("read");
        assert_ne!(
            read, 0,
            "connection closed waiting for {needle:?}; saw {seen:?}"
        );
        let trimmed = line.trim_end().to_owned();
        let found = trimmed.contains(needle);
        seen.push(trimmed);
        if found {
            return seen;
        }
    }
    panic!("never saw {needle:?}; saw {seen:?}");
}

async fn send(writer: &mut ClientWriter, line: &str) {
    let mut payload = line.as_bytes().to_vec();
    payload.extend_from_slice(b"\r\n");
    writer.write_all(&payload).await.expect("write");
}

#[tokio::test]
async fn tls_handshake_and_registration() {
    let (_server, address) = start_server(false).await;
    let (mut reader, mut writer) = connect(address, None).await;
    send(&mut writer, "NICK tlsuser").await;
    send(&mut writer, "USER tlsuser 0 * :TLS User").await;

    let seen = read_until(&mut reader, " 001 ").await;
    assert!(
        seen.iter().any(|line| line.contains(" 001 ")),
        "no welcome over TLS; saw {seen:?}"
    );
}

/// Backend that maps one pinned certificate fingerprint to an account.
#[derive(Debug)]
struct PinnedCertificate {
    fingerprint: String,
}

impl AccountBackend for PinnedCertificate {
    fn name(&self) -> &'static str {
        "test-certificates"
    }

    fn mechanisms(&self) -> &'static [&'static str] {
        &["EXTERNAL"]
    }

    fn verify(&self, credential: &Credential<'_>) -> Option<String> {
        match credential {
            Credential::External { fingerprint, .. } if *fingerprint == self.fingerprint => {
                Some("alice".to_owned())
            }
            Credential::External { .. } | Credential::Plain { .. } => None,
        }
    }
}

#[tokio::test]
async fn sasl_external_uses_the_client_certificate() {
    let certified =
        rcgen::generate_simple_self_signed(vec!["client".to_owned()]).expect("client certificate");
    let chain = vec![certified.cert.der().clone()];
    let fingerprint = sha256_hex(certified.cert.der().as_ref());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));

    let (server, address) = start_server(true).await;
    server.set_account_backend(Arc::new(PinnedCertificate {
        fingerprint: fingerprint.clone(),
    }));
    assert!(server.sasl_mechanisms().contains(&"EXTERNAL"));

    let (mut reader, mut writer) = connect(address, Some((chain, key))).await;
    send(&mut writer, "AUTHENTICATE EXTERNAL").await;
    read_until(&mut reader, "AUTHENTICATE +").await;
    send(&mut writer, "AUTHENTICATE +").await;
    let seen = read_until(&mut reader, " 903 ").await;
    assert!(
        seen.iter().any(|line| line.contains(" 900 ")),
        "logged-in numeric missing; saw {seen:?}"
    );
    assert!(
        seen.iter()
            .any(|line| line.ends_with("alice") || line.contains("alice")),
        "account name missing from 900; saw {seen:?}"
    );

    send(&mut writer, "NICK alice").await;
    send(&mut writer, "USER alice 0 * :Alice").await;
    read_until(&mut reader, " 001 ").await;

    // Without a certificate the same mechanism must be refused, which proves
    // the fingerprint is what authenticated the first connection.
    let (mut reader, mut writer) = connect(address, None).await;
    send(&mut writer, "AUTHENTICATE EXTERNAL").await;
    read_until(&mut reader, "AUTHENTICATE +").await;
    send(&mut writer, "AUTHENTICATE +").await;
    let seen = read_until(&mut reader, " 904 ").await;
    assert!(
        seen.iter().any(|line| line.contains(" 904 ")),
        "EXTERNAL without a certificate must fail; saw {seen:?}"
    );
}
