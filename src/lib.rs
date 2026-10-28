//! `rs-ircd` implements an IRC daemon speaking RFC 1459 and the RFC 2810-2813
//! revision of the protocol, plus TLS (RFC 7194's port 6697 convention) and
//! zlib connection compression.

pub mod auth;
pub mod casemap;
pub mod commands;
pub mod config;
pub mod daemon;
pub mod error;
pub mod hooks;
pub mod logging;
pub mod net;
pub mod protocol;
pub mod script;
pub mod server;
pub mod util;
