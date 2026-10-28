//! TLS support.
//!
//! Certificates and keys are read from PEM files. Keys may be plaintext or
//! encrypted with a passphrase supplied through an environment variable, which
//! keeps the passphrase out of the configuration file and process arguments.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use crate::config::{TlsMinVersion, TlsSection};
use crate::error::{Error, Result};

/// Build an acceptor from the TLS configuration.
///
/// # Errors
///
/// Returns [`Error::Tls`] when the certificate or key is missing, unreadable,
/// malformed, or when the passphrase fails to decrypt the key.
pub fn acceptor(config: &TlsSection) -> Result<TlsAcceptor> {
    let cert_path = config
        .cert_path
        .as_deref()
        .ok_or_else(|| Error::Tls("tls.cert_path is not configured".to_owned()))?;
    let key_path = config
        .key_path
        .as_deref()
        .ok_or_else(|| Error::Tls("tls.key_path is not configured".to_owned()))?;

    let certificates = load_certificates(cert_path)?;
    let key = load_private_key(config, key_path)?;

    let versions: &[&'static rustls::SupportedProtocolVersion] = match config.min_version {
        TlsMinVersion::Tls12 => &[&rustls::version::TLS12, &rustls::version::TLS13],
        TlsMinVersion::Tls13 => &[&rustls::version::TLS13],
    };

    // The ring provider is selected explicitly so the client-certificate
    // verifier can read its signature algorithms without depending on a
    // process-wide default.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(versions)
        .map_err(|error| Error::Tls(format!("unsupported TLS versions: {error}")))?;
    let builder = if config.request_client_certs {
        builder.with_client_cert_verifier(Arc::new(AcceptAnyClientCertificate(provider)))
    } else {
        builder.with_no_client_auth()
    };
    let server_config = builder
        .with_single_cert(certificates, key)
        .map_err(|error| Error::Tls(format!("invalid certificate/key pair: {error}")))?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn load_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .map_err(|error| Error::Tls(format!("cannot open certificate {path}: {error}")))?;
    let mut reader = BufReader::new(file);
    let certificates: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .map_err(|error| Error::Tls(format!("cannot parse certificate {path}: {error}")))?;
    if certificates.is_empty() {
        return Err(Error::Tls(format!(
            "certificate file {path} contains no certificates"
        )));
    }
    Ok(certificates)
}

fn load_private_key(config: &TlsSection, path: &str) -> Result<PrivateKeyDer<'static>> {
    let pem = std::fs::read_to_string(path)
        .map_err(|error| Error::Tls(format!("cannot read key {path}: {error}")))?;

    if let Some(variable) = &config.key_password_env {
        let passphrase = std::env::var(variable)
            .map_err(|_| Error::Tls(format!("environment variable {variable} is not set")))?;
        return decrypt_key(&pem, passphrase.as_bytes())
            .map_err(|error| Error::Tls(format!("cannot decrypt key {path}: {error}")));
    }

    let mut reader = BufReader::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| Error::Tls(format!("cannot parse key {path}: {error}")))?
        .ok_or_else(|| Error::Tls(format!("key file {path} contains no private key")))
}

/// Decrypt an encrypted PKCS#8 private key with `passphrase`.
fn decrypt_key(
    pem: &str,
    passphrase: &[u8],
) -> std::result::Result<PrivateKeyDer<'static>, String> {
    use pkcs8::der::{Decode, SecretDocument};

    let (_, document) = SecretDocument::from_pem(pem).map_err(|error| error.to_string())?;
    let encrypted = pkcs8::EncryptedPrivateKeyInfo::from_der(document.as_bytes())
        .map_err(|error| error.to_string())?;
    let decrypted = encrypted
        .decrypt(passphrase)
        .map_err(|error| error.to_string())?;
    Ok(PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(decrypted.as_bytes().to_vec()),
    ))
}

// MARK: security: high: SEC-TLS-001: identity comes from the pinned fingerprint, not a CA chain.
/// Accepts any client certificate, without a certificate authority.
///
/// `EXTERNAL` does not trust a CA: each account pins the SHA-256 fingerprint of
/// the certificate it may use, and that fingerprint is compared after the
/// handshake. Trusting the CA would add no security here, because a certificate
/// from any authority would still have to match the pinned fingerprint. The
/// handshake does prove the client holds the matching private key, since rustls
/// verifies the `CertificateVerify` signature against the presented
/// certificate.
#[derive(Debug)]
struct AcceptAnyClientCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::server::danger::ClientCertVerifier for AcceptAnyClientCertificate {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // A client without a certificate can still register; it simply cannot
        // use `EXTERNAL`.
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_paths_are_reported() {
        let error = acceptor(&TlsSection::default()).err().expect("must fail");
        assert!(matches!(error, Error::Tls(_)));
    }

    #[test]
    fn missing_file_is_reported() {
        let config = TlsSection {
            cert_path: Some("/nonexistent/cert.pem".to_owned()),
            key_path: Some("/nonexistent/key.pem".to_owned()),
            ..TlsSection::default()
        };
        let error = acceptor(&config).err().expect("must fail");
        assert!(matches!(error, Error::Tls(_)));
    }

    #[test]
    fn empty_certificate_file_is_reported() {
        let directory = tempfile::tempdir().expect("temp dir");
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&cert, "").expect("write cert");
        std::fs::write(&key, "").expect("write key");
        let config = TlsSection {
            cert_path: Some(cert.to_string_lossy().into_owned()),
            key_path: Some(key.to_string_lossy().into_owned()),
            ..TlsSection::default()
        };
        let error = acceptor(&config).err().expect("must fail");
        assert!(matches!(error, Error::Tls(_)));
    }
}
