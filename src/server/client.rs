//! Per-connection state.
//!
//! Each accepted socket owns one [`ClientHandle`]. The handle is shared with
//! the rest of the server through `Arc` so that messages can be delivered
//! without holding a global registry lock. Writes go through a bounded queue:
//! a peer that stops reading is disconnected rather than allowed to consume
//! unbounded memory.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::warn;

use crate::casemap::CaseMapping;
use crate::config::OperPrivilege;
use crate::protocol::Message;
use crate::util::now_unix;

/// Unique identifier of a connection (local or shadowed remote user).
pub type ClientId = u64;

tokio::task_local! {
    /// Command currently being handled for one client.
    ///
    /// Every delivery funnels through [`ClientHandle::enqueue`], which uses
    /// this to attach the IRCv3 `label` tag to the issuing client's own
    /// replies only.
    pub static RESPONSE: Arc<ResponseContext>;
}

/// The `label` a command's responses must carry.
#[derive(Debug)]
pub struct ResponseContext {
    /// Client whose command is running.
    pub client: ClientId,
    /// Label the client attached to the command.
    pub label: String,
    /// Responses queued for that client so far.
    pub sent: AtomicUsize,
}

/// Work item for the connection writer task.
#[derive(Debug)]
pub enum Outbound {
    /// A fully serialised line.
    Line(Bytes),
    /// Compress everything after this point.
    EnableCompression,
    /// Close the connection after flushing.
    Close,
}

/// IRCv3 capabilities this server implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapSet(u16);

impl std::ops::BitOr for CapSet {
    type Output = CapSet;

    fn bitor(self, rhs: CapSet) -> CapSet {
        CapSet(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CapSet {
    fn bitor_assign(&mut self, rhs: CapSet) {
        self.0 |= rhs.0;
    }
}

impl CapSet {
    /// `multi-prefix`: several status prefixes in `NAMES`/`WHO`.
    pub const MULTI_PREFIX: CapSet = CapSet(1 << 0);
    /// `away-notify`: push `AWAY` when a peer changes state.
    pub const AWAY_NOTIFY: CapSet = CapSet(1 << 1);
    /// `server-time`: attach `@time` to messages.
    pub const SERVER_TIME: CapSet = CapSet(1 << 2);
    /// `extended-join`: include account and real name in `JOIN`.
    pub const EXTENDED_JOIN: CapSet = CapSet(1 << 3);
    /// `userhost-in-names`: `nick!user@host` in `NAMES`.
    pub const USERHOST_IN_NAMES: CapSet = CapSet(1 << 4);
    /// `cap-notify`: announce capability changes.
    pub const CAP_NOTIFY: CapSet = CapSet(1 << 5);
    /// `echo-message`: echo a client's own `PRIVMSG`/`NOTICE` back to it.
    pub const ECHO_MESSAGE: CapSet = CapSet(1 << 6);
    /// `sasl`: account authentication before or after registration.
    pub const SASL: CapSet = CapSet(1 << 7);
    /// `account-tag`: attach the sender's account to messages.
    pub const ACCOUNT_TAG: CapSet = CapSet(1 << 8);
    /// `message-tags`: accept and relay client-only (`+`) tags.
    pub const MESSAGE_TAGS: CapSet = CapSet(1 << 9);
    /// `labeled-response`: echo the command's `label` tag on its responses.
    pub const LABELED_RESPONSE: CapSet = CapSet(1 << 10);

    /// Every capability together with its wire name.
    pub const TABLE: [(&'static str, CapSet); 11] = [
        ("multi-prefix", CapSet::MULTI_PREFIX),
        ("away-notify", CapSet::AWAY_NOTIFY),
        ("server-time", CapSet::SERVER_TIME),
        ("extended-join", CapSet::EXTENDED_JOIN),
        ("userhost-in-names", CapSet::USERHOST_IN_NAMES),
        ("cap-notify", CapSet::CAP_NOTIFY),
        ("echo-message", CapSet::ECHO_MESSAGE),
        ("sasl", CapSet::SASL),
        ("account-tag", CapSet::ACCOUNT_TAG),
        ("message-tags", CapSet::MESSAGE_TAGS),
        ("labeled-response", CapSet::LABELED_RESPONSE),
    ];

    /// Look a capability up by its advertised name.
    pub fn from_name(name: &str) -> Option<CapSet> {
        CapSet::TABLE
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, capability)| *capability)
    }

    /// True when every capability in `other` is enabled.
    pub fn contains(self, other: CapSet) -> bool {
        self.0 & other.0 == other.0
    }

    /// Enable `other`.
    pub fn insert(&mut self, other: CapSet) {
        self.0 |= other.0;
    }

    /// Disable `other`.
    pub fn remove(&mut self, other: CapSet) {
        self.0 &= !other.0;
    }

    /// Wire names of the enabled capabilities, in table order.
    pub fn enabled_names(&self) -> Vec<&'static str> {
        CapSet::TABLE
            .iter()
            .filter(|(_, capability)| self.contains(*capability))
            .map(|(name, _)| *name)
            .collect()
    }
}

/// True when a serialised line already carries a `label` tag.
fn carries_label(bytes: &[u8]) -> bool {
    let Some(rest) = bytes.strip_prefix(b"@") else {
        return false;
    };
    let end = rest
        .iter()
        .position(|byte| *byte == b' ')
        .unwrap_or(rest.len());
    rest[..end]
        .split(|byte| *byte == b';')
        .any(|tag| tag == b"label" || tag.starts_with(b"label="))
}

/// Server notice categories an operator can subscribe to.
///
/// One bit per category, so filtering a notice is a single masked test per
/// recipient instead of a list scan. The letters match the `SNOMASK` argument
/// and are what `MODE +s` prints back, which is how other IRCds spell them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Snomask(u16);

impl Snomask {
    /// Nothing subscribed.
    pub const NONE: Snomask = Snomask(0);
    /// `c`: local client connections.
    pub const CONNECT: Snomask = Snomask(1 << 0);
    /// `q`: local disconnects and quits.
    pub const QUIT: Snomask = Snomask(1 << 1);
    /// `k`: kills and ban enforcement.
    pub const KILL: Snomask = Snomask(1 << 2);
    /// `o`: operator authentication.
    pub const OPER: Snomask = Snomask(1 << 3);
    /// `r`: configuration reloads.
    pub const REHASH: Snomask = Snomask(1 << 4);
    /// `l`: link establishment and loss.
    pub const LINK: Snomask = Snomask(1 << 5);
    /// `b`: server bans set, lifted or triggered.
    pub const BAN: Snomask = Snomask(1 << 6);
    /// `g`: `GLOBOPS` traffic.
    pub const GLOBAL: Snomask = Snomask(1 << 7);
    /// Every category.
    pub const ALL: Snomask = Snomask(0xFF);

    /// Parse a letter list, returning `None` for an unknown letter.
    pub fn from_letters(letters: &str) -> Option<Self> {
        let mut mask = Snomask::NONE;
        for letter in letters.chars() {
            let bit = match letter {
                'c' => Snomask::CONNECT,
                'q' => Snomask::QUIT,
                'k' => Snomask::KILL,
                'o' => Snomask::OPER,
                'r' => Snomask::REHASH,
                'l' => Snomask::LINK,
                'b' => Snomask::BAN,
                'g' => Snomask::GLOBAL,
                '*' => Snomask::ALL,
                _ => return None,
            };
            mask = mask.union(bit);
        }
        Some(mask)
    }

    /// Canonical letter string, or `*` when every category is enabled.
    pub fn letters(self) -> String {
        if self.contains(Snomask::ALL) {
            return "*".to_owned();
        }
        const TABLE: [(char, Snomask); 8] = [
            ('c', Snomask::CONNECT),
            ('q', Snomask::QUIT),
            ('k', Snomask::KILL),
            ('o', Snomask::OPER),
            ('r', Snomask::REHASH),
            ('l', Snomask::LINK),
            ('b', Snomask::BAN),
            ('g', Snomask::GLOBAL),
        ];
        TABLE
            .iter()
            .filter(|(_, bit)| self.contains(*bit))
            .map(|(letter, _)| *letter)
            .collect()
    }

    /// True when every bit in `other` is enabled.
    pub fn contains(self, other: Snomask) -> bool {
        self.0 & other.0 == other.0
    }

    /// Add every bit in `other`.
    pub fn union(self, other: Snomask) -> Self {
        Snomask(self.0 | other.0)
    }

    /// Remove every bit in `other`.
    pub fn difference(self, other: Snomask) -> Self {
        Snomask(self.0 & !other.0)
    }

    /// True when nothing is subscribed.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// User mode flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserModes {
    /// `+i`: hidden from `WHO`/`NAMES` for non-members.
    pub invisible: bool,
    /// `+w`: receives `WALLOPS`.
    pub wallops: bool,
    /// `+o`: operator.
    pub oper: bool,
    /// `+s`: receives the server notices named by [`Session::snomasks`].
    pub snomask: bool,
}

impl UserModes {
    /// Serialise as the argument of numeric `221`, e.g. `+iw`.
    pub fn to_flags(self) -> String {
        let mut flags = String::from("+");
        if self.invisible {
            flags.push('i');
        }
        if self.wallops {
            flags.push('w');
        }
        if self.snomask {
            flags.push('s');
        }
        if self.oper {
            flags.push('o');
        }
        flags
    }

    /// Apply one mode letter, returning `false` for unknown letters.
    pub fn apply(&mut self, mode: char, adding: bool) -> bool {
        let slot = match mode {
            'i' => &mut self.invisible,
            'w' => &mut self.wallops,
            's' => &mut self.snomask,
            'o' => &mut self.oper,
            _ => return false,
        };
        *slot = adding;
        true
    }
}

/// SASL mechanisms the protocol layer can decode.
///
/// Whether a mechanism can actually be verified is decided by the account
/// backend; this type only names the wire protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslMechanism {
    /// Two NUL-separated strings carried in one base64 blob.
    Plain,
    /// A TLS client certificate, optionally with an authorisation identity.
    External,
}

impl SaslMechanism {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            SaslMechanism::Plain => "PLAIN",
            SaslMechanism::External => "EXTERNAL",
        }
    }

    /// Parse a wire name, ignoring case.
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_uppercase().as_str() {
            "PLAIN" => Some(SaslMechanism::Plain),
            "EXTERNAL" => Some(SaslMechanism::External),
            _ => None,
        }
    }
}

/// A SASL exchange that has selected a mechanism but not finished.
#[derive(Debug, Clone)]
pub struct SaslSession {
    /// Negotiated mechanism.
    pub mechanism: SaslMechanism,
    /// base64 chunks received so far, concatenated.
    pub payload: String,
}

/// Mutable registration and presence data.
#[derive(Debug, Clone, Default)]
pub struct Session {
    /// Current nickname, as typed by the user.
    pub nick: Option<String>,
    /// `USER` name.
    pub user: Option<String>,
    /// `USER` real name.
    pub realname: Option<String>,
    /// Host shown to other clients (may be a cloak/resolved name).
    pub host: String,
    /// Address the connection came from.
    pub realhost: String,
    /// Registration completed.
    pub registered: bool,
    /// Connection password check passed.
    pub pass_ok: bool,
    /// Mode flags.
    pub modes: UserModes,
    /// Away message, if away.
    pub away: Option<String>,
    /// Operator account name.
    pub oper: Option<String>,
    /// Privileges granted by the operator's configuration entry, cached so an
    /// authorisation check does not search the configuration on every command.
    pub privileges: OperPrivilege,
    /// Server notice categories this session subscribed to with `+s`/`SNOMASK`.
    pub snomasks: Snomask,
    /// Account authenticated through SASL, if any.
    pub account: Option<String>,
    /// SASL exchange awaiting more input.
    pub sasl: Option<SaslSession>,
    /// Folded names of joined channels.
    pub channels: HashSet<String>,
    /// Sign-on time (Unix seconds).
    pub signon: u64,
    /// Creation timestamp used for nickname collision resolution.
    ///
    /// This is the TS of the IRC link protocol: the time the user's home
    /// server created it. It is stable for the life of the connection and is
    /// carried unchanged across links so every server breaks a collision the
    /// same way.
    pub ts: u64,
}

impl Session {
    /// Mask of the form `nick!user@host`, or a placeholder before registration.
    pub fn mask(&self) -> String {
        let nick = self.nick.as_deref().unwrap_or("*");
        let user = self.user.as_deref().unwrap_or("*");
        format!("{nick}!{user}@{}", self.host)
    }

    /// `nick` if registered, otherwise `*`.
    pub fn nick_or_star(&self) -> &str {
        self.nick.as_deref().unwrap_or("*")
    }
}

/// A local connection or a shadowed remote user.
#[derive(Debug)]
pub struct ClientHandle {
    /// Stable identifier.
    pub id: ClientId,
    /// SHA-256 fingerprint of the TLS client certificate, when one was sent.
    pub certificate: Option<Arc<str>>,
    /// Socket address of the peer.
    pub peer: SocketAddr,
    /// Connection is TLS protected.
    pub secure: bool,
    /// Connection is an RFC 2813 server link.
    pub server_link: bool,
    /// This link was dialled by us, so the peer's `SERVER` is its handshake
    /// reply and no `PASS` arrives on the socket.
    pub dialing: bool,
    /// For remote users, the server that owns them.
    pub remote_server: Option<String>,
    /// Sign-on time (Unix seconds).
    pub started: u64,
    /// Last inbound activity (Unix seconds), used by the ping timeout.
    pub last_activity: AtomicU64,
    /// Compression negotiated on this connection.
    pub compression: AtomicBool,
    /// Connection is being torn down; drop further writes.
    pub closing: AtomicBool,
    /// Set once the server has removed this handle from its registries.
    pub removed: AtomicBool,
    outbound: Option<mpsc::Sender<Outbound>>,
    session: RwLock<Session>,
    caps: RwLock<CapSet>,
}

impl ClientHandle {
    /// Create a handle for an accepted socket.
    pub fn new(
        id: ClientId,
        peer: SocketAddr,
        host: String,
        secure: bool,
        server_link: bool,
        outbound: mpsc::Sender<Outbound>,
    ) -> Self {
        let now = now_unix();
        Self {
            id,
            certificate: None,
            peer,
            secure,
            server_link,
            dialing: false,
            remote_server: None,
            started: now,
            last_activity: AtomicU64::new(now),
            compression: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            removed: AtomicBool::new(false),
            outbound: Some(outbound),
            session: RwLock::new(Session {
                host,
                realhost: peer.ip().to_string(),
                signon: now,
                ts: now,
                modes: UserModes::default(),
                ..Session::default()
            }),
            caps: RwLock::new(CapSet::default()),
        }
    }

    /// Create a shadow for a user owned by a linked server.
    pub fn shadow(
        id: ClientId,
        server: impl Into<String>,
        nick: impl Into<String>,
        user: impl Into<String>,
        host: impl Into<String>,
        realname: impl Into<String>,
        ts: u64,
    ) -> Self {
        let now = now_unix();
        let host = host.into();
        Self {
            id,
            certificate: None,
            peer: SocketAddr::from(([0, 0, 0, 0], 0)),
            secure: false,
            server_link: false,
            dialing: false,
            remote_server: Some(server.into()),
            started: now,
            last_activity: AtomicU64::new(now),
            compression: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            removed: AtomicBool::new(false),
            outbound: None,
            session: RwLock::new(Session {
                nick: Some(nick.into()),
                user: Some(user.into()),
                realname: Some(realname.into()),
                host: host.clone(),
                realhost: host,
                registered: true,
                signon: now,
                ts,
                ..Session::default()
            }),
            caps: RwLock::new(CapSet::default()),
        }
    }

    /// Fingerprint of the TLS client certificate this peer presented.
    pub fn certificate(&self) -> Option<&str> {
        self.certificate.as_deref()
    }

    /// True when this handle owns a socket.
    pub fn is_local(&self) -> bool {
        self.outbound.is_some()
    }

    /// Read the session.
    pub fn session<R>(&self, f: impl FnOnce(&Session) -> R) -> R {
        f(&self.session.read())
    }

    /// Mutate the session.
    pub fn session_mut<R>(&self, f: impl FnOnce(&mut Session) -> R) -> R {
        f(&mut self.session.write())
    }

    /// Nickname as typed, if one has been chosen.
    pub fn nick(&self) -> Option<String> {
        self.session.read().nick.clone()
    }

    /// Nickname or `*`.
    pub fn nick_or_star(&self) -> String {
        self.session.read().nick_or_star().to_owned()
    }

    /// `nick!user@host`.
    pub fn mask(&self) -> String {
        self.session.read().mask()
    }

    /// Registration completed.
    pub fn is_registered(&self) -> bool {
        self.session.read().registered
    }

    /// Enabled capabilities.
    pub fn caps(&self) -> CapSet {
        *self.caps.read()
    }

    /// True when `capability` is enabled.
    pub fn has_cap(&self, capability: CapSet) -> bool {
        self.caps.read().contains(capability)
    }

    /// Replace the enabled capability set.
    pub fn set_caps(&self, caps: CapSet) {
        *self.caps.write() = caps;
    }

    /// Enable capabilities and return the newly enabled ones.
    pub fn enable_caps(&self, caps: CapSet) -> CapSet {
        let mut guard = self.caps.write();
        let added = !guard.contains(caps);
        guard.insert(caps);
        if added {
            *guard
        } else {
            CapSet::default()
        }
    }

    /// Disable capabilities.
    pub fn disable_caps(&self, caps: CapSet) {
        self.caps.write().remove(caps);
    }

    /// Queue an already serialised command.
    ///
    /// Returns `false` when the peer is gone or its queue is saturated, in
    /// which case the connection is marked for shutdown.
    pub fn enqueue(&self, bytes: Bytes) -> bool {
        if self.closing.load(Ordering::Relaxed) {
            return false;
        }
        let Some(outbound) = &self.outbound else {
            // Shadowed remote users have no socket; nothing to do.
            return true;
        };
        let bytes = self.label_response(bytes);
        // MARK: security: high: SEC-QUEUE-001: a full send queue disconnects instead of growing the heap.
        match outbound.try_send(Outbound::Line(bytes)) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.closing.store(true, Ordering::Relaxed);
                warn!(id = self.id, "send queue full, dropping connection");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.closing.store(true, Ordering::Relaxed);
                false
            }
        }
    }

    /// Attach the in-flight command's `label` to this client's own responses.
    ///
    /// The task-local context names the client that issued the command, so a
    /// broadcast triggered by that command never leaks the label to another
    /// recipient. Returns `bytes` unchanged when this handle is not the issuer
    /// or has not negotiated `labeled-response`.
    fn label_response(&self, bytes: Bytes) -> Bytes {
        let Ok(context) = RESPONSE.try_with(Arc::clone) else {
            return bytes;
        };
        if context.client != self.id || !self.has_cap(CapSet::LABELED_RESPONSE) {
            return bytes;
        }
        if carries_label(&bytes) {
            return bytes;
        }
        context.sent.fetch_add(1, Ordering::Relaxed);
        let mut out = Vec::with_capacity(bytes.len() + context.label.len() + 8);
        out.push(b'@');
        out.extend_from_slice(b"label=");
        out.extend_from_slice(context.label.as_bytes());
        if bytes.first() == Some(&b'@') {
            out.push(b';');
            out.extend_from_slice(&bytes[1..]);
        } else {
            out.push(b' ');
            out.extend_from_slice(&bytes);
        }
        Bytes::from(out)
    }

    /// Serialise and queue `message`.
    pub fn send(&self, message: &Message, max_line: usize) -> bool {
        self.enqueue(Bytes::from(message.to_bytes_limited(max_line)))
    }

    /// Send a message, attaching the tags this client is entitled to.
    ///
    /// `account` follows `account-tag`; `tags` are the sender's client-only
    /// tags and follow `message-tags`. A client that asked for neither gets the
    /// message untouched, so tags are never leaked to a peer that cannot parse
    /// them.
    pub fn send_text(
        &self,
        message: &Message,
        account: Option<&str>,
        tags: &[(String, String)],
        max_line: usize,
    ) {
        let wants_tags = self.has_cap(CapSet::MESSAGE_TAGS) && !tags.is_empty();
        let wants_account = account.is_some() && self.has_cap(CapSet::ACCOUNT_TAG);
        if !wants_tags && !wants_account {
            self.send(message, max_line);
            return;
        }
        let mut copy = message.clone();
        if wants_account {
            if let Some(account) = account {
                copy.push_tag("account", account);
            }
        }
        if wants_tags {
            for (key, value) in tags {
                copy.push_tag(key.clone(), value.clone());
            }
        }
        self.send(&copy, max_line);
    }

    /// Queue a raw line, appending `CRLF` if missing.
    pub fn send_raw(&self, line: &str, max_line: usize) -> bool {
        let mut message = Message::command("");
        // Parse-free path: the caller already produced a complete line.
        let mut bytes = Vec::with_capacity(line.len() + 2);
        bytes.extend_from_slice(line.as_bytes());
        if !bytes.ends_with(b"\r\n") {
            if bytes.ends_with(b"\n") {
                bytes.pop();
            }
            bytes.extend_from_slice(b"\r\n");
        }
        if bytes.len() > max_line {
            bytes.truncate(max_line.saturating_sub(2));
            bytes.extend_from_slice(b"\r\n");
        }
        message.command.clear();
        self.enqueue(Bytes::from(bytes))
    }

    /// Ask the writer to enable compression.
    pub fn enable_compression(&self) -> bool {
        self.compression.store(true, Ordering::Release);
        match &self.outbound {
            Some(outbound) => outbound.try_send(Outbound::EnableCompression).is_ok(),
            None => false,
        }
    }

    /// Request connection teardown after queued writes flush.
    pub fn request_close(&self) {
        self.closing.store(true, Ordering::Relaxed);
        if let Some(outbound) = &self.outbound {
            let _ = outbound.try_send(Outbound::Close);
        }
    }

    /// Record inbound activity now.
    pub fn touch(&self) {
        self.last_activity.store(now_unix(), Ordering::Relaxed);
    }

    /// Seconds since the last inbound line.
    pub fn idle_seconds(&self) -> u64 {
        now_unix().saturating_sub(self.last_activity.load(Ordering::Relaxed))
    }

    /// The channel set, folded, cloned for iteration outside the lock.
    pub fn channels(&self) -> Vec<String> {
        self.session.read().channels.iter().cloned().collect()
    }

    /// Whether this user is visible to `viewer` in `NAMES`/`WHO`.
    pub fn is_visible_to(&self, viewer: &ClientHandle) -> bool {
        self.session(|session| {
            !session.modes.invisible || session.nick == viewer.session(|other| other.nick.clone())
        })
    }
}

impl CaseMapping {
    /// Convenience for folding a nickname with the server mapping.
    pub fn nick(self, value: &str) -> String {
        self.fold(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle() -> ClientHandle {
        let (tx, _rx) = mpsc::channel(8);
        ClientHandle::new(
            1,
            SocketAddr::from(([127, 0, 0, 1], 5000)),
            "localhost".to_owned(),
            false,
            false,
            tx,
        )
    }

    #[test]
    fn session_mask_defaults_to_placeholders() {
        let client = handle();
        assert_eq!(client.mask(), "*!*@localhost");
    }

    #[test]
    fn user_modes_round_trip() {
        let mut modes = UserModes::default();
        assert!(modes.apply('i', true));
        assert!(modes.apply('o', true));
        assert!(!modes.apply('z', true));
        assert_eq!(modes.to_flags(), "+io");
        modes.apply('i', false);
        assert_eq!(modes.to_flags(), "+o");
    }

    #[test]
    fn caps_track_inclusion() {
        let mut caps = CapSet::default();
        caps.insert(CapSet::SERVER_TIME | CapSet::MULTI_PREFIX);
        assert!(caps.contains(CapSet::SERVER_TIME));
        assert!(!caps.contains(CapSet::AWAY_NOTIFY));
        assert_eq!(caps.enabled_names(), vec!["multi-prefix", "server-time"]);
        caps.remove(CapSet::SERVER_TIME);
        assert!(!caps.contains(CapSet::SERVER_TIME));
        assert!(CapSet::from_name("server-time").is_some());
        assert!(CapSet::from_name("bogus").is_none());
    }

    #[test]
    fn queue_overflow_marks_closing() {
        let (tx, _rx) = mpsc::channel(1);
        let client = ClientHandle::new(
            2,
            SocketAddr::from(([127, 0, 0, 1], 1)),
            "localhost".to_owned(),
            false,
            false,
            tx,
        );
        assert!(client.send_raw("PING a", 512));
        let _ = client.send_raw("PING b", 512);
        assert!(client.closing.load(Ordering::Relaxed));
        assert!(!client.send_raw("PING c", 512));
    }

    #[test]
    fn shadow_clients_have_no_socket() {
        let shadow =
            ClientHandle::shadow(9, "peer.example", "bob", "u", "h", "Real", 1_700_000_000);
        assert!(!shadow.is_local());
        assert!(shadow.is_registered());
        assert_eq!(shadow.mask(), "bob!u@h");
    }
}
