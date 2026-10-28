//! Command table and shared handler helpers.
//!
//! Handlers are plain function pointers returning boxed futures. The table is a
//! sorted static slice, so dispatch is a binary search over a few `&str`
//! comparisons with no per-message allocation and no hashing, and the
//! function-pointer type makes the table `Sync` without dynamic dispatch.

pub mod admin;
pub mod channel;
pub mod messaging;
pub mod registration;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::casemap::CaseMapping;
use crate::config::OperPrivilege;
use crate::error::CommandError;
use crate::protocol::{Message, Numeric};
use crate::server::{Channel, ClientHandle, Server};

/// A command plus its execution context.
pub struct Cmd {
    /// Shared server state.
    pub server: Arc<Server>,
    /// Connection that issued the command.
    pub client: Arc<ClientHandle>,
    /// Parsed message.
    pub msg: Message,
}

/// Boxed handler future.
pub type CmdFuture =
    Pin<Box<dyn Future<Output = std::result::Result<(), CommandError>> + Send + 'static>>;

/// Command implementation.
pub type HandlerFn = fn(Cmd) -> CmdFuture;

/// Who may run a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Usable before registration (`NICK`, `USER`, `CAP`, ...).
    Unregistered,
    /// Registered users only.
    Registered,
    /// Operators holding every privilege in the set.
    Oper(OperPrivilege),
}

/// One row of the command table.
#[derive(Debug, Clone, Copy)]
pub struct CommandSpec {
    /// Wire command name.
    pub name: &'static str,
    /// Minimum parameter count.
    pub min_params: usize,
    /// Required access level.
    pub access: Access,
    /// Implementation.
    pub handler: HandlerFn,
}

/// Build the command table and its lookup from one list.
///
/// The match compiles to a length-and-bytes decision tree, so dispatch costs
/// neither a hash round trip nor a binary search's unpredictable branches. The
/// list is written once: the slice keeps `names()` and the reachability tests
/// honest, and the match cannot drift from it.
macro_rules! command_table {
    ($($name:literal => $spec:expr),* $(,)?) => {
        static CLIENT_COMMANDS: &[CommandSpec] = &[$($spec),*];

        // MARK: speed: high: SPD-DISPATCH-001: match tree beats hashing (benches/dispatch.rs).
        /// Look up a client command.
        ///
        /// `name` must already be upper-cased: [`Message::parse`] normalises
        /// every verb, and the match arms are the wire spelling.
        pub fn lookup(name: &str) -> Option<&'static CommandSpec> {
            match name {
                $($name => Some(&$spec),)*
                _ => None,
            }
        }
    };
}

command_table! {
    "ADMIN" => admin::ADMIN,
    "AUTHENTICATE" => registration::AUTHENTICATE,
    "AWAY" => messaging::AWAY,
    "BATCH" => messaging::BATCH,
    "BENCH" => admin::BENCH,
    "CAP" => registration::CAP,
    "CHGHOST" => registration::CHGHOST,
    "CHATHISTORY" => messaging::CHATHISTORY,
    "COMPRESS" => admin::COMPRESS,
    "GLOBOPS" => admin::GLOBOPS,
    "GLINE" => admin::GLINE,
    "INFO" => admin::INFO,
    "INVITE" => channel::INVITE,
    "ISON" => messaging::ISON,
    "JOIN" => channel::JOIN,
    "KICK" => channel::KICK,
    "KILL" => admin::KILL,
    "KLINE" => admin::KLINE,
    "LINKS" => admin::LINKS,
    "LIST" => channel::LIST,
    "LOGOUT" => registration::LOGOUT,
    "LUSERS" => admin::LUSERS,
    "MODE" => channel::MODE,
    "MONITOR" => messaging::MONITOR,
    "MOTD" => admin::MOTD,
    "NAMES" => channel::NAMES,
    "NICK" => registration::NICK,
    "NOTICE" => messaging::NOTICE,
    "OPER" => admin::OPER,
    "PART" => channel::PART,
    "PASS" => registration::PASS,
    "PING" => registration::PING,
    "PONG" => registration::PONG,
    "PRIVMSG" => messaging::PRIVMSG,
    "QUIT" => registration::QUIT,
    "REHASH" => admin::REHASH,
    "SAMODE" => admin::SAMODE,
    "SETNAME" => registration::SETNAME,
    "SHUN" => admin::SHUN,
    "SNOMASK" => admin::SNOMASK,
    "STATS" => admin::STATS,
    "TAGMSG" => messaging::TAGMSG,
    "TIME" => admin::TIME,
    "TOPIC" => channel::TOPIC,
    "USER" => registration::USER,
    "UNBAN" => admin::UNBAN,
    "USERHOST" => messaging::USERHOST,
    "VERSION" => admin::VERSION,
    "WALLOPS" => admin::WALLOPS,
    "WHO" => messaging::WHO,
    "WHOIS" => messaging::WHOIS,
    "WHOWAS" => messaging::WHOWAS,
    "ZLINE" => admin::ZLINE,
}

/// Every registered command name, mostly useful for diagnostics.
pub fn names() -> Vec<&'static str> {
    CLIENT_COMMANDS.iter().map(|spec| spec.name).collect()
}

/// True when `name` carries a channel prefix (`#` or `&`).
pub fn is_channel_name(name: &str) -> bool {
    name.starts_with('#') || name.starts_with('&')
}

/// Validate a nickname per RFC 1459 §2.3.1 and the configured length.
pub fn valid_nickname(nick: &str, max_length: usize) -> bool {
    if nick.is_empty() || nick.len() > max_length {
        return false;
    }
    let mut chars = nick.chars();
    let first = chars.next().unwrap_or(' ');
    let first_ok = first.is_ascii_alphabetic()
        || matches!(first, '[' | ']' | '\\' | '`' | '_' | '^' | '{' | '}');
    if !first_ok {
        return false;
    }
    chars.all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                '-' | '[' | ']' | '\\' | '`' | '_' | '^' | '{' | '}' | '|'
            )
    })
}

/// Validate a `USER` name: no spaces, no `@`, printable ASCII.
pub fn valid_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 18
        && user
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'@' && byte != b'!' && byte != b':')
}

/// Validate a channel name.
pub fn valid_channel_name(name: &str) -> bool {
    if name.len() < 2 || name.len() > 64 {
        return false;
    }
    if !is_channel_name(name) {
        return false;
    }
    name.bytes()
        .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b' ' | b',' | b'\x07' | b':'))
}

impl Cmd {
    /// Parameter accessor.
    pub fn param(&self, index: usize) -> Option<&str> {
        self.msg.param(index)
    }

    /// Sender nickname, or `*`.
    pub fn nick(&self) -> String {
        self.client.nick_or_star()
    }

    /// Sender mask `nick!user@host`.
    pub fn mask(&self) -> String {
        self.client.mask()
    }

    /// Numeric reply.
    pub fn reply(&self, code: Numeric, text: impl AsRef<str>) {
        self.server.numeric(&self.client, code, text);
    }

    /// Build a command error without sending it.
    pub fn fail(&self, code: Numeric, text: impl Into<String>) -> CommandError {
        CommandError::new(code, text)
    }

    /// Send a message to the issuing client.
    pub fn send(&self, message: &Message) {
        self.client.send(message, self.server.max_line());
    }

    /// Maximum wire line length.
    pub fn max_line(&self) -> usize {
        self.server.max_line()
    }

    /// Nickname casemapping.
    pub fn casemap(&self) -> CaseMapping {
        self.server.casemap()
    }

    /// Look up a client by nickname.
    pub fn find(&self, nick: &str) -> Option<Arc<ClientHandle>> {
        self.server.find_nick(nick)
    }

    /// Look up a channel.
    pub fn channel(&self, name: &str) -> Option<Arc<RwLock<Channel>>> {
        self.server.find_channel(name)
    }

    /// True when the sender is an operator.
    pub fn is_oper(&self) -> bool {
        self.client.session(|session| session.modes.oper)
    }

    /// True when the sender holds every privilege in `wanted`.
    pub fn has_privilege(&self, wanted: OperPrivilege) -> bool {
        self.server.has_privilege(&self.client, wanted)
    }

    /// Send a `PRIVMSG`-style payload with the sender's mask.
    pub fn message_to(&self, target: &str, command: &str, text: &str) {
        let mut message = Message::command(command);
        message.prefix = Some(self.mask());
        message.params.push(target.to_owned());
        message.params.push(text.to_owned());
        if let Some(recipient) = self.server.find_nick(target) {
            recipient.send(&message, self.max_line());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nickname_validation_matches_rfc() {
        assert!(valid_nickname("alice", 30));
        assert!(valid_nickname("[weird]", 30));
        assert!(!valid_nickname("1alice", 30));
        assert!(!valid_nickname("", 30));
        assert!(!valid_nickname("alice1234567890123456789012345678901", 30));
        assert!(!valid_nickname("a b", 30));
    }

    #[test]
    fn channel_validation() {
        assert!(valid_channel_name("#rust"));
        assert!(valid_channel_name("&local"));
        assert!(!valid_channel_name("#"));
        assert!(!valid_channel_name("rust"));
        assert!(!valid_channel_name("#with space"));
        assert!(!valid_channel_name("#with,comma"));
    }

    #[test]
    fn username_validation() {
        assert!(valid_username("user"));
        assert!(!valid_username("us er"));
        assert!(!valid_username("us@er"));
        assert!(!valid_username(""));
    }

    #[test]
    fn every_command_is_reachable() {
        for name in names() {
            assert!(lookup(name).is_some(), "{name} missing from the table");
        }
        assert!(lookup("NOSUCHCOMMAND").is_none());
    }
    #[test]
    fn every_spec_lookup_matches_its_own_name() {
        for spec in CLIENT_COMMANDS {
            let found = lookup(spec.name).unwrap_or_else(|| panic!("{} unreachable", spec.name));
            assert_eq!(found.name, spec.name);
            assert_eq!(found.min_params, spec.min_params);
            assert_eq!(found.access, spec.access);
        }
        assert_eq!(CLIENT_COMMANDS.len(), 53);
    }

    #[test]
    fn table_has_no_duplicate_specs() {
        let mut seen = std::collections::HashSet::new();
        for name in names() {
            let spec = lookup(name).expect("lookup");
            assert_eq!(spec.name, name);
            assert!(seen.insert(spec.name));
        }
    }
}
