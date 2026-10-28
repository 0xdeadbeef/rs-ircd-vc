//! Configuration: TOML schema, defaults and validation.
//!
//! Secrets are never stored in this file directly. Password hashes are read
//! from environment variables named by the configuration, which keeps them in
//! `.env` (ignored by git) rather than in a world-readable config.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::casemap::CaseMapping;
use crate::error::{Error, Result};

/// Top-level daemon configuration.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Identity and protocol behaviour.
    pub server: ServerSection,
    /// Resource ceilings and timeouts.
    pub limits: LimitsSection,
    /// Optional connection compression.
    pub compression: CompressionSection,
    /// Logging sinks.
    pub logging: LoggingSection,
    /// Process daemonisation.
    pub daemon: DaemonSection,
    /// Embedded Rhai scripting hooks.
    pub scripting: ScriptingSection,
    /// Self-instrumentation.
    pub diagnostics: DiagnosticsSection,
    /// TLS material.
    pub tls: TlsSection,
    /// SASL authentication policy.
    pub sasl: SaslSection,
    /// Accounts usable for SASL.
    pub accounts: Vec<AccountSection>,
    /// Operator accounts.
    pub opers: Vec<OperSection>,
    /// Outbound links this server dials itself.
    pub links: Vec<LinkSection>,
    /// Listener definitions; several may bind the same port on different
    /// address families.
    pub listen: Vec<ListenSection>,
}

/// Server identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerSection {
    /// Primary server name, usually fully qualified.
    pub name: String,
    /// Human-readable version banner.
    pub description: String,
    /// Network name advertised in `005`.
    pub network: String,
    /// RFC 2813 server identifier, exactly three characters.
    pub sid: String,
    /// Environment variable holding the optional connection password.
    pub password_env: Option<String>,
    /// Optional MOTD file.
    pub motd: Option<String>,
    /// Environment variable holding the RFC 2813 link password.
    pub link_password_env: Option<String>,
    /// Server names allowed to establish a link.
    pub peers: Vec<String>,
    /// Reverse-resolve client addresses (adds latency per connection).
    pub resolve_hostnames: bool,
    /// Nickname/channel casemapping.
    pub casemapping: CaseMapping,
    /// Maximum nickname length (RFC 1459 allows 9, modern clients expect 30).
    pub max_nick_length: usize,
    /// Seconds a channel invitation stays valid.
    pub invite_expiry_secs: u64,
    /// How long before expiry the invitee and inviter are warned. Zero
    /// disables the warning.
    pub invite_warning_secs: u64,
    /// Vendor tags a client may send without the `+` prefix.
    ///
    /// Keys are matched exactly and must be tag names such as
    /// `example.com/foo`; server tags (`time`, `account`, `label`) are always
    /// refused so a client can never forge them.
    pub client_tag_allowlist: Vec<String>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            name: "irc.localhost".to_owned(),
            description: "rs-ircd".to_owned(),
            network: "rs-ircd".to_owned(),
            sid: "0RS".to_owned(),
            password_env: None,
            link_password_env: None,
            peers: Vec::new(),
            motd: None,
            resolve_hostnames: false,
            casemapping: CaseMapping::Rfc1459,
            max_nick_length: 30,
            invite_expiry_secs: 300,
            invite_warning_secs: 60,
            client_tag_allowlist: Vec::new(),
        }
    }
}

/// Resource limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsSection {
    /// Maximum simultaneous client connections.
    pub max_clients: usize,
    /// Channels a single client may join.
    pub max_channels_per_client: usize,
    /// Members a single channel may hold.
    pub max_channel_members: usize,
    /// Maximum accepted line length, including `CRLF`.
    pub max_line_len: usize,
    /// Seconds a connection may stay unregistered.
    pub registration_timeout_secs: u64,
    /// Seconds between server-initiated `PING`s.
    pub ping_interval_secs: u64,
    /// Seconds to wait for a `PONG` before dropping the link.
    pub ping_timeout_secs: u64,
    /// Outbound queue depth per connection.
    pub send_queue: usize,
    /// `WHOWAS` history entries.
    pub whowas_size: usize,
    /// Recipients allowed per `PRIVMSG`.
    pub max_targets: usize,
}

impl Default for LimitsSection {
    fn default() -> Self {
        Self {
            max_clients: 4096,
            max_channels_per_client: 100,
            max_channel_members: 1024,
            max_line_len: 512,
            registration_timeout_secs: 60,
            ping_interval_secs: 90,
            ping_timeout_secs: 120,
            send_queue: 2048,
            whowas_size: 512,
            max_targets: 4,
        }
    }
}

/// Compression negotiation defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CompressionSection {
    /// Allow `COMPRESS` negotiation at all.
    pub enabled: bool,
    /// zlib level (0-9).
    pub level: u32,
    /// Reject inbound frames inflating beyond this size (zip-bomb guard).
    pub max_decompressed: usize,
}

impl Default for CompressionSection {
    fn default() -> Self {
        Self {
            enabled: true,
            level: 6,
            max_decompressed: 1 << 20,
        }
    }
}

/// Logging sinks and format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingSection {
    /// `tracing` filter directive, e.g. `info` or `ircd::net=debug`.
    pub level: String,
    /// Line format.
    pub format: LogFormat,
    /// Write to stderr.
    pub console: bool,
    /// Rolling file sink.
    pub file: FileSection,
    /// Syslog (Unix) or Windows Event Log sink.
    pub syslog: SyslogSection,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            format: LogFormat::Text,
            console: true,
            file: FileSection::default(),
            syslog: SyslogSection::default(),
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable single-line output.
    #[default]
    Text,
    /// Newline-delimited JSON suitable for log shippers.
    Json,
}

/// Rolling file logging.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileSection {
    /// Enable the file sink.
    pub enabled: bool,
    /// Directory receiving the log files.
    pub directory: String,
    /// Filename prefix.
    pub prefix: String,
    /// Rotated files to retain.
    pub max_files: usize,
}

impl Default for FileSection {
    fn default() -> Self {
        Self {
            enabled: false,
            directory: "logs".to_owned(),
            prefix: "ircd".to_owned(),
            max_files: 7,
        }
    }
}

/// System log sink.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SyslogSection {
    /// Enable the system log sink.
    pub enabled: bool,
    /// Syslog facility name (`daemon`, `local0`, ...).
    pub facility: String,
    /// Tag/application name.
    pub tag: String,
}

impl Default for SyslogSection {
    fn default() -> Self {
        Self {
            enabled: false,
            facility: "daemon".to_owned(),
            tag: "rs-ircd".to_owned(),
        }
    }
}

/// Daemonisation options.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DaemonSection {
    /// Detach from the controlling terminal.
    pub enabled: bool,
    /// PID file to write after detaching.
    pub pid_file: Option<String>,
    /// Working directory after detaching.
    pub working_directory: Option<String>,
}

/// Rhai hook engine options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScriptingSection {
    /// Enable script loading.
    pub enabled: bool,
    /// Script files evaluated at start-up.
    pub scripts: Vec<String>,
    /// Compiled guard rule files, evaluated before any script runs.
    pub rules: Vec<String>,
    /// Per-call instruction budget; bounds runaway scripts.
    pub max_operations: u64,
    /// Per-call expression nesting limit.
    pub max_call_depth: usize,
    /// Maximum string length a script may allocate in one value.
    pub max_string_size: usize,
}

impl Default for ScriptingSection {
    fn default() -> Self {
        Self {
            enabled: false,
            scripts: Vec::new(),
            rules: Vec::new(),
            max_operations: 100_000,
            max_call_depth: 32,
            max_string_size: 1 << 20,
        }
    }
}

/// Runtime diagnostics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DiagnosticsSection {
    /// Enable operator diagnostics commands such as `STATS l`.
    pub enabled: bool,
    /// Expose the in-process `BENCH` micro-benchmark command to operators.
    pub benchmarks: bool,
}

impl Default for DiagnosticsSection {
    fn default() -> Self {
        Self {
            enabled: true,
            benchmarks: false,
        }
    }
}

/// Enum in the configuration for TLS certificate handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum TlsMinVersion {
    /// TLS 1.2 and newer.
    #[serde(rename = "1.2")]
    #[default]
    Tls12,
    /// TLS 1.3 only.
    #[serde(rename = "1.3")]
    Tls13,
}

/// TLS material and policy.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsSection {
    /// PEM certificate chain.
    pub cert_path: Option<String>,
    /// PEM private key (PKCS#8, PKCS#1 or SEC1).
    pub key_path: Option<String>,
    /// Environment variable holding the passphrase for an encrypted PEM key.
    pub key_password_env: Option<String>,
    /// Lowest accepted protocol version.
    pub min_version: TlsMinVersion,
    /// Ask for a client certificate during the handshake.
    ///
    /// The certificate is not checked against a CA: SASL `EXTERNAL` pins its
    /// fingerprint to an account instead, so a public PKI is not required.
    pub request_client_certs: bool,
}

/// SASL authentication policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SaslSection {
    /// Advertise the `sasl` capability and accept `AUTHENTICATE`.
    pub enabled: bool,
    /// Refuse to complete registration until SASL succeeds.
    pub require: bool,
}

impl Default for SaslSection {
    fn default() -> Self {
        Self {
            enabled: true,
            require: false,
        }
    }
}

/// One SASL account.
///
/// Every credential is a reference into the environment or a digest of public
/// material; a plaintext secret never appears in this file.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AccountSection {
    /// Account name announced to clients and shown in `WHOIS`.
    pub name: String,
    /// Environment variable holding the SHA-256 hex hash of the password.
    pub password_hash_env: Option<String>,
    /// SHA-256 hex fingerprint of a TLS client certificate for `EXTERNAL`.
    pub cert_fingerprint: Option<String>,
}

/// Operator account.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OperSection {
    /// `OPER` name.
    pub name: String,
    /// Environment variable holding the SHA-256 hex hash of the password.
    pub password_hash_env: Option<String>,
    /// Optional host mask restricting the account.
    pub host: Option<String>,
    /// Granted privileges.
    pub flags: Vec<OperFlag>,
}

/// Privileges an operator may hold.
///
/// This is the configuration spelling; [`OperPrivilege`] is the run-time bit
/// set a session carries, so an authorisation check is one masked comparison
/// rather than a scan of the operator's configuration entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperFlag {
    /// `KILL` other clients.
    Kill,
    /// `REHASH` the configuration.
    Rehash,
    /// Apply network-wide disconnects and send `GLOBOPS`.
    Global,
    /// Shut the server down.
    Die,
    /// Force channel modes and join restricted channels (`SAMODE`, override).
    Admin,
    /// Create and lift network-wide server bans.
    Ban,
}

impl OperFlag {
    /// The bit this flag contributes.
    pub fn privilege(self) -> OperPrivilege {
        match self {
            OperFlag::Kill => OperPrivilege::KILL,
            OperFlag::Rehash => OperPrivilege::REHASH,
            OperFlag::Global => OperPrivilege::GLOBAL,
            OperFlag::Die => OperPrivilege::DIE,
            OperFlag::Admin => OperPrivilege::ADMIN,
            OperFlag::Ban => OperPrivilege::BAN,
        }
    }
}

/// A set of operator privileges.
///
/// A newtype over a bit mask rather than a collection: authorisation is one
/// `AND`, the value is `Copy`, and a session carries it without an allocation.
/// `+o` alone grants nothing; [`OperPrivilege::ALL`] is the union of every
/// flag, used when an operator's configuration is reloaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OperPrivilege(u16);

impl OperPrivilege {
    /// No privileges.
    pub const NONE: OperPrivilege = OperPrivilege(0);
    /// `KILL`.
    pub const KILL: OperPrivilege = OperPrivilege(1 << 0);
    /// `REHASH` and the diagnostic commands.
    pub const REHASH: OperPrivilege = OperPrivilege(1 << 1);
    /// `WALLOPS`, `GLOBOPS` and network-wide actions.
    pub const GLOBAL: OperPrivilege = OperPrivilege(1 << 2);
    /// Process shutdown.
    pub const DIE: OperPrivilege = OperPrivilege(1 << 3);
    /// `SAMODE`, `MODE` override and joining restricted channels.
    pub const ADMIN: OperPrivilege = OperPrivilege(1 << 4);
    /// Server ban management.
    pub const BAN: OperPrivilege = OperPrivilege(1 << 5);
    /// Every privilege.
    pub const ALL: OperPrivilege = OperPrivilege(0b11_1111);

    /// Union of the configured flags.
    pub fn from_flags(flags: &[OperFlag]) -> Self {
        flags
            .iter()
            .fold(OperPrivilege::NONE, |set, flag| set.union(flag.privilege()))
    }

    /// True when every bit in `other` is present.
    pub fn contains(self, other: OperPrivilege) -> bool {
        self.0 & other.0 == other.0
    }

    /// Add every bit in `other`.
    pub fn union(self, other: OperPrivilege) -> Self {
        OperPrivilege(self.0 | other.0)
    }

    /// True when no privilege is held.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// A listener binding one port to one or more addresses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ListenSection {
    /// Addresses to bind. `0.0.0.0` covers all IPv4, `::` all IPv6.
    pub addresses: Vec<IpAddr>,
    /// TCP port.
    pub port: u16,
    /// Require TLS for this listener.
    pub tls: bool,
    /// Accept RFC 2813 server links on this listener.
    pub server_link: bool,
}

impl Default for ListenSection {
    fn default() -> Self {
        Self {
            addresses: vec![
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ],
            port: 6667,
            tls: false,
            server_link: false,
        }
    }
}

/// An outbound server link the daemon dials itself.
///
/// The peer must also accept links on a `server_link` listener; this section
/// only describes how to reach it and how aggressively to retry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LinkSection {
    /// Server name expected from the peer, used as an identity check.
    pub name: String,
    /// Host name or address to dial.
    pub address: String,
    /// TCP port on the peer.
    pub port: u16,
    /// Require TLS for this link.
    pub tls: bool,
    /// PEM file with the authority that signed the peer certificate;
    /// required when `tls` is true.
    pub tls_ca_path: Option<String>,
    /// Name verified against the peer certificate; defaults to `name`.
    pub tls_server_name: Option<String>,
    /// Environment variable holding the link password; defaults to
    /// `server.link_password_env`.
    pub password_env: Option<String>,
    /// First retry delay after a failed connection.
    pub retry_initial_secs: u64,
    /// Ceiling for the exponential retry delay.
    pub retry_max_secs: u64,
}

impl Default for LinkSection {
    fn default() -> Self {
        Self {
            name: String::new(),
            address: String::new(),
            port: 7000,
            tls: false,
            tls_ca_path: None,
            tls_server_name: None,
            password_env: None,
            retry_initial_secs: 5,
            retry_max_secs: 300,
        }
    }
}

impl Config {
    /// Read and validate a TOML configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file cannot be read, [`Error::Toml`] for
    /// syntax problems, and [`Error::Config`] for semantic problems.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = std::fs::read_to_string(path.as_ref())?;
        let config: Self = toml::from_str(&text)?;
        config.validate()?;
        Ok(config)
    }

    /// Parse and validate configuration from a TOML string.
    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// Semantic validation beyond what the type system enforces.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] describing the first violated invariant.
    pub fn validate(&self) -> Result<()> {
        let name = &self.server.name;
        if name.is_empty() || !name.contains('.') {
            return Err(Error::Config(
                "server.name must be a fully qualified name containing a dot".to_owned(),
            ));
        }
        if name.len() > 63 {
            return Err(Error::Config("server.name is too long".to_owned()));
        }
        if self.server.sid.len() != 3 || !self.server.sid.is_ascii() {
            return Err(Error::Config(
                "server.sid must be exactly three ASCII characters".to_owned(),
            ));
        }
        if self.server.max_nick_length == 0 || self.server.max_nick_length > 30 {
            return Err(Error::Config(
                "server.max_nick_length must be between 1 and 30".to_owned(),
            ));
        }
        if self.server.invite_expiry_secs == 0 {
            return Err(Error::Config(
                "server.invite_expiry_secs must be at least 1".to_owned(),
            ));
        }
        for tag in &self.server.client_tag_allowlist {
            if tag.is_empty() || tag.len() > 64 {
                return Err(Error::Config(
                    "server.client_tag_allowlist entries must be 1-64 characters".to_owned(),
                ));
            }
            if !tag.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'/' | b'_')
            }) {
                return Err(Error::Config(format!(
                    "server.client_tag_allowlist entry {tag:?} has characters outside A-Za-z0-9-./_"
                )));
            }
            if tag.starts_with('+') {
                return Err(Error::Config(format!(
                    "server.client_tag_allowlist entry {tag:?} does not need a + prefix"
                )));
            }
            if matches!(tag.as_str(), "time" | "account" | "label") {
                return Err(Error::Config(format!(
                    "server.client_tag_allowlist entry {tag:?} is a server tag"
                )));
            }
        }
        if self.limits.max_line_len < 64 || self.limits.max_line_len > 8192 {
            return Err(Error::Config(
                "limits.max_line_len must be between 64 and 8192".to_owned(),
            ));
        }
        if self.limits.send_queue == 0 {
            return Err(Error::Config(
                "limits.send_queue must be at least 1".to_owned(),
            ));
        }
        if self.compression.level > 9 {
            return Err(Error::Config(
                "compression.level must be between 0 and 9".to_owned(),
            ));
        }
        if self.listen.is_empty() {
            return Err(Error::Config(
                "at least one [[listen]] section is required".to_owned(),
            ));
        }
        if self.listen.iter().any(|listener| listener.tls)
            && (self.tls.cert_path.is_none() || self.tls.key_path.is_none())
        {
            return Err(Error::Config(
                "tls.cert_path and tls.key_path are required for TLS listeners".to_owned(),
            ));
        }
        if self.sasl.require && self.accounts.is_empty() {
            return Err(Error::Config(
                "sasl.require needs at least one [[accounts]] entry".to_owned(),
            ));
        }
        let mut account_names = HashSet::with_capacity(self.accounts.len());
        for account in &self.accounts {
            if account.name.is_empty() || account.name.len() > 64 {
                return Err(Error::Config(
                    "account names must be between 1 and 64 characters".to_owned(),
                ));
            }
            if account.password_hash_env.is_none() && account.cert_fingerprint.is_none() {
                return Err(Error::Config(format!(
                    "account {} needs password_hash_env or cert_fingerprint",
                    account.name
                )));
            }
            // MARK: security: medium: SEC-PIN-002: fingerprints are shape-checked here, normalised at load.
            if let Some(fingerprint) = &account.cert_fingerprint {
                if fingerprint.len() != 64
                    || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(Error::Config(format!(
                        "account {} cert_fingerprint must be a SHA-256 hex digest",
                        account.name
                    )));
                }
            }
            if !account_names.insert(account.name.to_ascii_lowercase()) {
                return Err(Error::Config(format!("duplicate account {}", account.name)));
            }
        }
        let mut oper_names = HashSet::with_capacity(self.opers.len());
        for oper in &self.opers {
            if oper.name.is_empty() {
                return Err(Error::Config("oper name must not be empty".to_owned()));
            }
            if oper.password_hash_env.is_none() {
                return Err(Error::Config(format!(
                    "oper {} needs password_hash_env",
                    oper.name
                )));
            }
            if oper.flags.is_empty() {
                return Err(Error::Config(format!(
                    "oper {} needs at least one flag",
                    oper.name
                )));
            }
            if !oper_names.insert(oper.name.to_ascii_lowercase()) {
                return Err(Error::Config(format!("duplicate oper {}", oper.name)));
            }
        }
        let mut link_names = HashSet::with_capacity(self.links.len());
        for link in &self.links {
            if link.name.is_empty() || link.name.split_whitespace().count() != 1 {
                return Err(Error::Config(
                    "link name must be a single non-empty token".to_owned(),
                ));
            }
            if link.address.trim().is_empty() {
                return Err(Error::Config(format!(
                    "link {} needs an address",
                    link.name
                )));
            }
            if link.port == 0 {
                return Err(Error::Config(format!(
                    "link {} needs a non-zero port",
                    link.name
                )));
            }
            if link.tls && link.tls_ca_path.is_none() {
                return Err(Error::Config(format!(
                    "link {} needs tls_ca_path when tls is enabled",
                    link.name
                )));
            }
            if link.retry_initial_secs == 0 || link.retry_max_secs < link.retry_initial_secs {
                return Err(Error::Config(format!(
                    "link {} retry delays are inconsistent",
                    link.name
                )));
            }
            if link.password_env.is_none() && self.server.link_password_env.is_none() {
                return Err(Error::Config(format!(
                    "link {} needs password_env or server.link_password_env",
                    link.name
                )));
            }
            if !link_names.insert(link.name.to_ascii_lowercase()) {
                return Err(Error::Config(format!("duplicate link {}", link.name)));
            }
        }
        for path in &self.scripting.scripts {
            if path.trim().is_empty() {
                return Err(Error::Config(
                    "scripting.scripts contains an empty path".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Optional connection password, read from the configured environment
    /// variable so it never lives in the configuration file.
    pub fn connection_password(&self) -> Option<String> {
        self.server
            .password_env
            .as_deref()
            .and_then(|name| std::env::var(name).ok())
            .filter(|value| !value.is_empty())
    }

    /// Render the built-in example configuration.
    pub fn sample() -> String {
        let config = Config {
            tls: TlsSection {
                cert_path: Some("cert.pem".to_owned()),
                key_path: Some("key.pem".to_owned()),
                ..TlsSection::default()
            },
            listen: vec![
                ListenSection {
                    port: 6667,
                    ..ListenSection::default()
                },
                ListenSection {
                    port: 6697,
                    tls: true,
                    ..ListenSection::default()
                },
            ],
            logging: LoggingSection {
                file: FileSection {
                    enabled: true,
                    ..FileSection::default()
                },
                ..LoggingSection::default()
            },
            ..Config::default()
        };
        let rendered = toml::to_string_pretty(&config).unwrap_or_default();
        format!("{EXAMPLE_HEADER}\n{rendered}")
    }
}

const EXAMPLE_HEADER: &str = "\
# rs-ircd configuration
# Secrets belong in .env, referenced here by environment variable name.
# Generate an operator hash with: printf '%s' 'secret' | sha256sum";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_config_is_valid_and_round_trips() {
        let sample = Config::sample();
        let parsed = Config::parse(&sample).expect("sample must validate");
        assert_eq!(parsed.listen.len(), 2);
        assert!(parsed.listen[1].tls);
        assert_eq!(parsed.server.casemapping, CaseMapping::Rfc1459);
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = Config::parse("[server]\nname = \"irc.example.org\"\nbogus = 1\n")
            .expect_err("typos must fail");
        assert!(matches!(error, Error::Toml(_)));
    }

    #[test]
    fn rejects_invalid_sid_and_missing_name() {
        let mut config = Config::default();
        config.listen.push(ListenSection::default());
        config.server.sid = "AB".to_owned();
        assert!(matches!(config.validate(), Err(Error::Config(_))));
        config.server.sid = "0RS".to_owned();
        config.server.name = "localhost".to_owned();
        assert!(matches!(config.validate(), Err(Error::Config(_))));
    }

    #[test]
    fn sasl_require_needs_an_account() {
        let mut config = Config::default();
        config.listen.push(ListenSection::default());
        config.sasl.require = true;
        assert!(matches!(config.validate(), Err(Error::Config(_))));
        config.accounts.push(AccountSection {
            name: "alice".to_owned(),
            password_hash_env: Some("RS_IRCD_TEST_CONFIG_ACCOUNT".to_owned()),
            cert_fingerprint: None,
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn account_fingerprints_must_be_sha256_hex() {
        let mut config = Config::default();
        config.listen.push(ListenSection::default());
        config.accounts.push(AccountSection {
            name: "alice".to_owned(),
            password_hash_env: None,
            cert_fingerprint: Some("nothex".to_owned()),
        });
        assert!(matches!(config.validate(), Err(Error::Config(_))));
        config.accounts[0].cert_fingerprint = Some("ab".repeat(32));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accounts_need_at_least_one_credential() {
        let mut config = Config::default();
        config.listen.push(ListenSection::default());
        config.accounts.push(AccountSection {
            name: "alice".to_owned(),
            password_hash_env: None,
            cert_fingerprint: None,
        });
        assert!(matches!(config.validate(), Err(Error::Config(_))));
    }

    #[test]
    fn tls_listener_requires_material() {
        let mut config = Config::default();
        config.listen.push(ListenSection {
            tls: true,
            ..ListenSection::default()
        });
        assert!(matches!(config.validate(), Err(Error::Config(_))));
    }

    #[test]
    fn default_config_has_no_listeners_until_added() {
        assert!(Config::default().listen.is_empty());
        assert!(Config::default().validate().is_err());
    }
}
