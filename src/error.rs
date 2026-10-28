//! Error types shared by the daemon and the library.

use thiserror::Error;

use crate::protocol::numeric::Numeric;

/// Fatal or infrastructure errors.
#[derive(Debug, Error)]
pub enum Error {
    /// The configuration file is malformed or semantically invalid.
    #[error("configuration error: {0}")]
    Config(String),
    /// Socket, filesystem or process errors.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// TLS material could not be loaded or negotiated.
    #[error("tls error: {0}")]
    Tls(String),
    /// Logging could not be initialised.
    #[error("logging error: {0}")]
    Logging(String),
    /// An embedded script failed to compile or run.
    #[error("script error: {0}")]
    Script(String),
    /// The peer violated the wire protocol.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// TOML deserialisation failure, kept distinct for good diagnostics.
    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),
}

/// Convenience alias for [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// A command failure that maps onto an IRC numeric reply.
///
/// `text` is the preformatted remainder of the numeric (including any
/// parameters such as the target nick), so dispatch only has to prefix the
/// server name, numeric code and recipient nickname.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{text}")]
pub struct CommandError {
    /// Numeric code sent back to the client.
    pub code: Numeric,
    /// Formatted numeric body.
    pub text: String,
}

impl CommandError {
    /// Build a command error for a numeric reply.
    pub fn new(code: Numeric, text: impl Into<String>) -> Self {
        Self {
            code,
            text: text.into(),
        }
    }
}
