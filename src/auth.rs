//! Pluggable account authentication for SASL.
//!
//! The daemon ships one backend, [`ConfigAccounts`], which reads account
//! records from the configuration file while keeping password hashes in the
//! environment. An embedder can replace it through
//! [`crate::server::Server::set_account_backend`], which is how a services
//! package, a SQL database or a directory service plugs in without touching
//! the protocol layer.
//!
//! Verifying a credential returns the account name it authenticated rather
//! than a bare boolean: SASL `EXTERNAL` may arrive without an authorisation
//! identity, and the backend is the only component that can map a certificate
//! fingerprint to a name.

use std::collections::HashMap;

use crate::config::AccountSection;
use crate::error::{Error, Result};
use crate::util::{constant_time_eq, verify_password};

/// Credential types the protocol layer can present to a backend.
#[derive(Debug, Clone, Copy)]
pub enum Credential<'a> {
    /// An account name and password, from SASL `PLAIN`.
    Plain {
        /// Account the client claims.
        account: &'a str,
        /// Password supplied with it.
        password: &'a str,
    },
    /// A TLS client certificate, from SASL `EXTERNAL`.
    External {
        /// Authorisation identity sent by the client, usually absent.
        account: Option<&'a str>,
        /// Lowercase hex SHA-256 fingerprint of the certificate.
        fingerprint: &'a str,
    },
}

impl Credential<'_> {
    /// Account name the client asked for, when it supplied one.
    pub fn requested_account(&self) -> Option<&str> {
        match self {
            Credential::Plain { account, .. } => Some(account),
            Credential::External { account, .. } => *account,
        }
    }
}

/// A source of account records.
///
/// One backend is shared by every connection, so implementations must be
/// thread-safe. `verify` runs on the connection's task, which means a backend
/// that talks to a network service should do so on a blocking pool.
pub trait AccountBackend: Send + Sync + std::fmt::Debug {
    /// Backend name, used in logs.
    fn name(&self) -> &'static str;

    /// SASL mechanisms this backend can verify.
    ///
    /// The protocol layer intersects this with the mechanisms it can decode,
    /// so returning an unknown name simply hides it from clients.
    fn mechanisms(&self) -> &'static [&'static str] {
        &["PLAIN", "EXTERNAL"]
    }

    /// Authenticate `credential`, returning the account it belongs to.
    ///
    // MARK: security: critical: SEC-AUTH-001: all credential failures are indistinguishable.
    /// Returns `None` for every failure: an unknown account, a wrong password
    /// and a mismatched certificate are deliberately indistinguishable to the
    /// client.
    fn verify(&self, credential: &Credential<'_>) -> Option<String>;
}

/// Account records loaded from `[[accounts]]` configuration entries.
#[derive(Debug, Clone, Default)]
pub struct ConfigAccounts {
    records: HashMap<String, AccountRecord>,
    has_password: bool,
    has_certificate: bool,
}

#[derive(Debug, Clone, Default)]
struct AccountRecord {
    password_hash: Option<String>,
    cert_fingerprint: Option<String>,
}

impl ConfigAccounts {
    /// Resolve every account's credentials.
    ///
    /// Hashes and fingerprints are normalised to lowercase hex at load time so
    /// that comparison never depends on how the operator typed them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when an account name is empty, duplicated, or
    /// when the environment variable holding its password hash is missing or
    /// is not a SHA-256 digest. Failing at start-up is deliberate: silently
    /// ignoring a mistyped variable would lock every account out.
    pub fn load(sections: &[AccountSection]) -> Result<Self> {
        let mut accounts = Self::default();
        for section in sections {
            let key = section.name.to_ascii_lowercase();
            if key.is_empty() {
                return Err(Error::Config("account name must not be empty".to_owned()));
            }
            let password_hash = match &section.password_hash_env {
                Some(variable) => {
                    let value = std::env::var(variable).map_err(|_| {
                        Error::Config(format!(
                            "environment variable {variable} for account {} is not set",
                            section.name
                        ))
                    })?;
                    let value = value.trim().to_ascii_lowercase();
                    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        return Err(Error::Config(format!(
                            "{variable} must hold a SHA-256 hex digest"
                        )));
                    }
                    accounts.has_password = true;
                    Some(value)
                }
                None => None,
            };
            let cert_fingerprint = section.cert_fingerprint.as_ref().map(|fingerprint| {
                accounts.has_certificate = true;
                fingerprint.to_ascii_lowercase()
            });
            let previous = accounts.records.insert(
                key.clone(),
                AccountRecord {
                    password_hash,
                    cert_fingerprint,
                },
            );
            if previous.is_some() {
                return Err(Error::Config(format!("duplicate account {key}")));
            }
        }
        Ok(accounts)
    }

    /// Number of configured accounts.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// True when no account is configured.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl AccountBackend for ConfigAccounts {
    fn name(&self) -> &'static str {
        "config"
    }

    fn mechanisms(&self) -> &'static [&'static str] {
        match (self.has_password, self.has_certificate) {
            (true, true) => &["PLAIN", "EXTERNAL"],
            (true, false) => &["PLAIN"],
            (false, true) => &["EXTERNAL"],
            (false, false) => &[],
        }
    }

    fn verify(&self, credential: &Credential<'_>) -> Option<String> {
        match credential {
            Credential::Plain { account, password } => {
                let key = account.to_ascii_lowercase();
                let record = self.records.get(&key)?;
                let hash = record.password_hash.as_deref()?;
                verify_password(password, hash).then_some(key)
            }
            Credential::External {
                account,
                fingerprint,
            } => {
                // MARK: security: high: SEC-PIN-001: the fingerprint must match exactly and the authzid binds the name.
                let presented = fingerprint.to_ascii_lowercase();
                match account {
                    Some(account) => {
                        let key = account.to_ascii_lowercase();
                        let record = self.records.get(&key)?;
                        record
                            .cert_fingerprint
                            .as_deref()
                            .filter(|stored| constant_time_eq(stored, &presented))
                            .map(|_| key)
                    }
                    // No authorisation identity: the certificate alone selects
                    // the account it is pinned to.
                    None => self
                        .records
                        .iter()
                        .find(|(_, record)| {
                            record
                                .cert_fingerprint
                                .as_deref()
                                .is_some_and(|stored| constant_time_eq(stored, &presented))
                        })
                        .map(|(name, _)| name.clone()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::sha256_hex;

    fn backend(records: &[(&str, Option<&str>, Option<&str>)]) -> ConfigAccounts {
        let mut accounts = ConfigAccounts::default();
        for (name, password_hash, fingerprint) in records {
            accounts.has_password |= password_hash.is_some();
            accounts.has_certificate |= fingerprint.is_some();
            accounts.records.insert(
                name.to_ascii_lowercase(),
                AccountRecord {
                    password_hash: password_hash.map(str::to_owned),
                    cert_fingerprint: fingerprint.map(str::to_owned),
                },
            );
        }
        accounts
    }

    #[test]
    fn plain_credentials_authenticate() {
        let hash = sha256_hex(b"hunter2");
        let accounts = backend(&[("Alice", Some(&hash), None)]);
        let account = accounts.verify(&Credential::Plain {
            account: "alice",
            password: "hunter2",
        });
        assert_eq!(account.as_deref(), Some("alice"));
    }

    #[test]
    fn plain_rejects_wrong_password_and_unknown_account() {
        let hash = sha256_hex(b"hunter2");
        let accounts = backend(&[("alice", Some(&hash), None)]);
        assert!(accounts
            .verify(&Credential::Plain {
                account: "alice",
                password: "hunter3",
            })
            .is_none());
        assert!(accounts
            .verify(&Credential::Plain {
                account: "mallory",
                password: "hunter2",
            })
            .is_none());
    }

    #[test]
    fn password_only_accounts_cannot_use_external() {
        let hash = sha256_hex(b"hunter2");
        let accounts = backend(&[("alice", Some(&hash), None)]);
        assert!(accounts
            .verify(&Credential::External {
                account: Some("alice"),
                fingerprint: &sha256_hex(b"certificate"),
            })
            .is_none());
    }

    #[test]
    fn external_maps_a_certificate_without_authzid() {
        let fingerprint = sha256_hex(b"certificate");
        let accounts = backend(&[("alice", None, Some(&fingerprint))]);
        let account = accounts.verify(&Credential::External {
            account: None,
            fingerprint: &fingerprint,
        });
        assert_eq!(account.as_deref(), Some("alice"));
    }

    #[test]
    fn external_honours_the_authorisation_identity() {
        let fingerprint = sha256_hex(b"certificate");
        let accounts = backend(&[
            ("alice", None, Some(&fingerprint)),
            ("bob", None, Some("00")),
        ]);
        assert!(accounts
            .verify(&Credential::External {
                account: Some("alice"),
                fingerprint: &fingerprint,
            })
            .is_some());
        assert!(accounts
            .verify(&Credential::External {
                account: Some("bob"),
                fingerprint: &fingerprint,
            })
            .is_none());
        assert!(accounts
            .verify(&Credential::External {
                account: None,
                fingerprint: &sha256_hex(b"other"),
            })
            .is_none());
    }

    #[test]
    fn mechanisms_follow_the_configured_credentials() {
        let hash = sha256_hex(b"hunter2");
        assert!(backend(&[]).mechanisms().is_empty());
        assert_eq!(
            backend(&[("alice", Some(&hash), None)]).mechanisms(),
            &["PLAIN"]
        );
        assert_eq!(
            backend(&[("alice", None, Some("ab"))]).mechanisms(),
            &["EXTERNAL"]
        );
        assert_eq!(
            backend(&[("alice", Some(&hash), Some("ab"))]).mechanisms(),
            &["PLAIN", "EXTERNAL"]
        );
    }

    #[test]
    fn load_reads_the_hash_from_the_environment() {
        let variable = "RS_IRCD_TEST_ACCOUNT_LOAD_HASH";
        let hash = sha256_hex(b"correct horse");
        std::env::set_var(variable, hash.to_uppercase());
        let section = AccountSection {
            name: "Alice".to_owned(),
            password_hash_env: Some(variable.to_owned()),
            cert_fingerprint: None,
        };
        let accounts = ConfigAccounts::load(&[section]).expect("load");
        assert_eq!(accounts.len(), 1);
        assert!(accounts
            .verify(&Credential::Plain {
                account: "alice",
                password: "correct horse",
            })
            .is_some());
    }

    #[test]
    fn load_rejects_missing_environment_variables() {
        let section = AccountSection {
            name: "alice".to_owned(),
            password_hash_env: Some("RS_IRCD_TEST_ACCOUNT_ABSENT_VARIABLE".to_owned()),
            cert_fingerprint: None,
        };
        assert!(matches!(
            ConfigAccounts::load(&[section]),
            Err(Error::Config(_))
        ));
    }

    #[test]
    fn load_rejects_duplicate_accounts() {
        let variable = "RS_IRCD_TEST_ACCOUNT_DUPLICATE";
        std::env::set_var(variable, sha256_hex(b"x"));
        let section = AccountSection {
            name: "alice".to_owned(),
            password_hash_env: Some(variable.to_owned()),
            cert_fingerprint: None,
        };
        let mut second = section.clone();
        second.name = "ALICE".to_owned();
        assert!(matches!(
            ConfigAccounts::load(&[section, second]),
            Err(Error::Config(_))
        ));
    }
}
