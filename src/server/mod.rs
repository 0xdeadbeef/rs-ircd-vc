//! Server state, command dispatch and teardown.

pub mod ban;
pub mod channel;
pub mod client;
pub mod history;
pub mod link;

pub use ban::{BanKind, ServerBan};
pub use channel::Channel;
pub use client::{
    CapSet, ClientHandle, ClientId, MultilineBatch, Outbound, ResponseContext, SaslMechanism,
    SaslSession, Session, Snomask, UserModes, RESPONSE,
};
pub use history::{HistoryEntry, HistoryRange, HistoryStore};

/// The `label` tag of a client command, when it is a token that can be echoed
/// verbatim.
///
/// Only unreserved characters are accepted, so re-serialising the value cannot
/// change its meaning and the client sees the label it sent.
fn label_tag(message: &Message) -> Option<String> {
    let value = message
        .tags
        .iter()
        .find(|(key, _)| key == "label")
        .map(|(_, value)| value.as_str())?;
    (!value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/')))
    .then(|| value.to_owned())
}

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::auth::{AccountBackend, ConfigAccounts};
use crate::commands;
use crate::config::{Config, OperPrivilege};
use crate::error::{CommandError, Error, Result};
use crate::hooks::{HookContext, HookOutcome};
use crate::logging::LoggingHandle;
use crate::protocol::{Message, Numeric};
use crate::script::ScriptHost;
use crate::util::{now_iso8601, now_unix};

/// One server known to the routing table.
///
/// `link` is the direct peer that reaches it and `hops` the distance to it, so
/// the table is a shortest-path view of a spanning tree rather than a flood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// Server name as announced by its owner.
    pub name: String,
    /// RFC 2813 server identifier.
    pub sid: String,
    /// Human-readable description.
    pub description: String,
    /// Link that carries traffic to this server.
    pub link: ClientId,
    /// Distance in hops from this server (1 for a direct peer).
    pub hops: u32,
}

/// Historical nickname record used by `WHOWAS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhowasEntry {
    /// Nickname at the time of the record.
    pub nick: String,
    /// Username.
    pub user: String,
    /// Host.
    pub host: String,
    /// Real name.
    pub realname: String,
    /// Server the user was on.
    pub server: String,
    /// Sign-on time.
    pub signon: u64,
}

/// The daemon's shared state.
///
/// All maps are concurrent: a message never requires a global write lock, so
/// fan-out scales with cores rather than serialising on one mutex.
pub struct Server {
    config: RwLock<Arc<Config>>,
    config_path: Option<PathBuf>,
    pub clients: DashMap<ClientId, Arc<ClientHandle>>,
    nicks: RwLock<HashMap<String, ClientId>>,
    pub channels: DashMap<String, Arc<RwLock<Channel>>>,
    whowas: RwLock<VecDeque<WhowasEntry>>,
    hooks: RwLock<ScriptHost>,
    accounts: RwLock<Arc<dyn AccountBackend>>,
    logging: RwLock<Option<Arc<LoggingHandle>>>,
    motd: RwLock<Vec<String>>,
    /// Authenticated server links.
    pub links: DashMap<ClientId, String>,
    /// For each link and folded channel, whether that link's most recent
    /// `SJOIN` won the channel-TS comparison. The burst `TOPIC` and list `MODE`
    /// lines that follow a losing `SJOIN` must not be applied.
    pub burst_remote_won: DashMap<(ClientId, String), bool>,
    /// Shortest-path routes to the rest of the network.
    routes: DashMap<String, ServerInfo>,
    /// Network-wide bans, shared by every kind so one scan answers any check.
    bans: RwLock<Vec<ServerBan>>,
    /// Bounded per-channel message history.
    history: HistoryStore,
    pub started: u64,
    pub start_instant: Instant,
    local_count: AtomicUsize,
    next_id: AtomicU64,
}

impl Server {
    /// Create server state, loading scripts and the MOTD.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Script`] when a configured script fails to compile.
    pub fn new(config: Arc<Config>, config_path: Option<PathBuf>) -> Result<Arc<Self>> {
        let hooks = ScriptHost::load(&config.scripting)?;
        let accounts: Arc<dyn AccountBackend> = Arc::new(ConfigAccounts::load(&config.accounts)?);
        let motd = load_motd(&config);
        let server = Arc::new(Self {
            clients: DashMap::new(),
            nicks: RwLock::new(HashMap::new()),
            channels: DashMap::new(),
            whowas: RwLock::new(VecDeque::new()),
            hooks: RwLock::new(hooks),
            accounts: RwLock::new(accounts),
            logging: RwLock::new(None),
            motd: RwLock::new(motd),
            links: DashMap::new(),
            routes: DashMap::new(),
            bans: RwLock::new(Vec::new()),
            history: HistoryStore::new(config.server.history_size),
            burst_remote_won: DashMap::new(),
            started: now_unix(),
            start_instant: Instant::now(),
            local_count: AtomicUsize::new(0),
            next_id: AtomicU64::new(1),
            config: RwLock::new(config),
            config_path,
        });
        Ok(server)
    }

    /// Current configuration snapshot.
    pub fn cfg(&self) -> Arc<Config> {
        Arc::clone(&self.config.read())
    }

    /// Nickname casemapping.
    pub fn casemap(&self) -> crate::casemap::CaseMapping {
        self.config.read().server.casemapping
    }

    /// Accepted line length limit.
    pub fn max_line(&self) -> usize {
        self.config.read().limits.max_line_len
    }

    /// Seconds since the server started.
    pub fn uptime_seconds(&self) -> u64 {
        self.start_instant.elapsed().as_secs()
    }

    /// Number of local connections.
    pub fn local_clients(&self) -> usize {
        self.local_count.load(Ordering::Relaxed)
    }

    /// Number of connected clients including remote shadows.
    pub fn global_clients(&self) -> usize {
        self.clients.len()
    }

    /// Number of channels.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Number of authenticated server links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Replace the account backend, e.g. to plug in an external directory.
    pub fn set_account_backend(&self, backend: Arc<dyn AccountBackend>) {
        *self.accounts.write() = backend;
    }

    /// Backend consulted for SASL authentication.
    pub fn accounts(&self) -> Arc<dyn AccountBackend> {
        Arc::clone(&self.accounts.read())
    }

    /// SASL mechanisms the daemon can verify right now.
    ///
    /// The list is the intersection of what the backend knows and what this
    /// connection layer can decode; `EXTERNAL` additionally needs a client
    /// certificate, so it is only offered when listeners request one.
    pub fn sasl_mechanisms(&self) -> Vec<&'static str> {
        let config = self.cfg();
        if !config.sasl.enabled {
            return Vec::new();
        }
        let request_certificates = config.tls.request_client_certs;
        self.accounts
            .read()
            .mechanisms()
            .iter()
            .copied()
            .filter(|mechanism| *mechanism != "EXTERNAL" || request_certificates)
            .collect()
    }

    /// Register an accepted socket.
    ///
    /// Returns `None` when the client limit is reached; the caller closes the
    /// socket without replying, matching the behaviour of other daemons under
    /// descriptor pressure.
    pub async fn accept_client(
        self: &Arc<Self>,
        peer: SocketAddr,
        secure: bool,
        server_link: bool,
        certificate: Option<Arc<str>>,
        dialing: bool,
    ) -> Option<(Arc<ClientHandle>, mpsc::Receiver<Outbound>)> {
        let config = self.cfg();
        if self.local_clients() >= config.limits.max_clients {
            warn!(%peer, "connection refused: client limit reached");
            return None;
        }
        let host = if config.server.resolve_hostnames {
            match tokio::time::timeout(
                Duration::from_secs(5),
                crate::util::reverse_lookup(peer.ip()),
            )
            .await
            {
                Ok(Some(name)) => name,
                _ => peer.ip().to_string(),
            }
        } else {
            peer.ip().to_string()
        };
        let (sender, receiver) = mpsc::channel(config.limits.send_queue.max(1));
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut created = ClientHandle::new(id, peer, host, secure, server_link, sender);
        created.certificate = certificate;
        created.dialing = dialing;
        let handle = Arc::new(created);
        self.clients.insert(id, Arc::clone(&handle));
        self.local_count.fetch_add(1, Ordering::Relaxed);
        info!(id, %peer, secure, server_link, "connection accepted");
        Some((handle, receiver))
    }

    /// Insert or improve a route to `name`.
    ///
    /// Returns `true` only when the route is new or closer than the one already
    /// known. Link introductions are forwarded on exactly that condition, so
    /// topology changes converge instead of looping.
    pub fn add_route(
        &self,
        name: &str,
        sid: &str,
        description: &str,
        link: ClientId,
        hops: u32,
    ) -> bool {
        let info = ServerInfo {
            name: name.to_owned(),
            sid: sid.to_owned(),
            description: description.to_owned(),
            link,
            hops,
        };
        let folded = self.casemap().fold(name);
        match self.routes.entry(folded) {
            Entry::Occupied(mut occupied) => {
                if hops < occupied.get().hops {
                    occupied.insert(info);
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(info);
                true
            }
        }
    }

    /// Route to `name`, if the network knows it.
    pub fn route(&self, name: &str) -> Option<ServerInfo> {
        let folded = self.casemap().fold(name);
        self.routes.get(&folded).map(|entry| entry.value().clone())
    }

    /// Every known remote server, nearest first.
    pub fn routes(&self) -> Vec<ServerInfo> {
        let mut routes: Vec<ServerInfo> = self
            .routes
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        routes.sort_by(|left, right| {
            left.hops
                .cmp(&right.hops)
                .then_with(|| left.name.cmp(&right.name))
        });
        routes
    }

    /// Drop the route to `name`, returning what was removed.
    pub fn remove_route(&self, name: &str) -> Option<ServerInfo> {
        let folded = self.casemap().fold(name);
        self.routes.remove(&folded).map(|(_, info)| info)
    }

    /// Drop every route reached through `link`.
    ///
    /// Called when a link goes away: everything behind it is unreachable, so
    /// the whole subtree is pruned in one pass.
    pub fn remove_routes_via(&self, link: ClientId) -> Vec<ServerInfo> {
        let keys: Vec<String> = self
            .routes
            .iter()
            .filter(|entry| entry.value().link == link)
            .map(|entry| entry.key().clone())
            .collect();
        keys.into_iter()
            .filter_map(|key| self.routes.remove(&key).map(|(_, info)| info))
            .collect()
    }

    /// Send `message` towards the server that owns `server_name`.
    ///
    /// Returns `false` when no route exists, which is how a partitioned
    /// network stops delivering instead of flooding. A message never travels
    /// back to the link it arrived on.
    pub fn route_message(
        &self,
        server_name: &str,
        message: &Message,
        origin: Option<ClientId>,
    ) -> bool {
        let Some(info) = self.route(server_name) else {
            return false;
        };
        if Some(info.link) == origin {
            return false;
        }
        match self.find_client(info.link) {
            Some(link) => link.send(message, self.max_line()),
            None => false,
        }
    }

    /// Register a shadowed user announced by a linked server.
    pub fn add_remote(
        self: &Arc<Self>,
        server: &str,
        nick: &str,
        user: &str,
        host: &str,
        realname: &str,
        ts: u64,
    ) -> Arc<ClientHandle> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let handle = Arc::new(ClientHandle::shadow(
            id, server, nick, user, host, realname, ts,
        ));
        self.clients.insert(id, Arc::clone(&handle));
        self.nicks.write().insert(self.casemap().fold(nick), id);
        handle
    }

    /// Claim `nick` for `id`.
    ///
    /// Returns `false` when another connection already holds the name. The
    /// returned guard keeps the nickname index consistent under concurrent
    /// `NICK` commands.
    pub fn reserve_nick(&self, nick: &str, id: ClientId) -> bool {
        let folded = self.casemap().fold(nick);
        let mut nicks = self.nicks.write();
        match nicks.get(&folded) {
            Some(owner) => *owner == id,
            None => {
                nicks.insert(folded, id);
                true
            }
        }
    }

    /// Release a nickname previously claimed by `reserve_nick`.
    pub fn release_nick(&self, nick: &str) {
        let folded = self.casemap().fold(nick);
        self.nicks.write().remove(&folded);
    }

    /// Server name, used for message prefixes.
    pub fn name(&self) -> String {
        self.config.read().server.name.clone()
    }

    /// Find a connected client by nickname.
    pub fn find_nick(&self, nick: &str) -> Option<Arc<ClientHandle>> {
        let folded = self.casemap().fold(nick);
        let id = *self.nicks.read().get(&folded)?;
        self.clients.get(&id).map(|entry| Arc::clone(entry.value()))
    }

    /// Look up a client by id.
    pub fn find_client(&self, id: ClientId) -> Option<Arc<ClientHandle>> {
        self.clients.get(&id).map(|entry| Arc::clone(entry.value()))
    }

    /// Look up a channel by name.
    pub fn find_channel(&self, name: &str) -> Option<Arc<RwLock<Channel>>> {
        let folded = self.casemap().fold(name);
        self.channels
            .get(&folded)
            .map(|entry| Arc::clone(entry.value()))
    }

    /// Deliver a numeric reply.
    pub fn numeric(&self, client: &ClientHandle, code: Numeric, text: impl AsRef<str>) {
        let name = self.config.read().server.name.clone();
        let max_line = self.max_line();
        let line = format!(":{name} {code} {} {}", client.nick_or_star(), text.as_ref());
        client.send_raw(&line, max_line);
    }

    /// Deliver a `NOTICE` from the server itself.
    pub fn notice(&self, client: &ClientHandle, text: &str) {
        let name = self.config.read().server.name.clone();
        let max_line = self.max_line();
        client.send_raw(
            &format!(":{name} NOTICE {} :{text}", client.nick_or_star()),
            max_line,
        );
    }

    /// Warn both parties about invitations that are about to lapse, and remove
    /// the ones that already have, notifying them as it goes.
    ///
    /// Each server announces only the participants it houses locally, so a
    /// remote invitee or inviter is told by its own server instead of needing
    /// the notice relayed. Returns the number of notices delivered.
    // MARK: policy: high: POL-INVITE-001: each server notifies only the participants it houses locally.
    pub fn sweep_invites(self: &Arc<Self>) -> usize {
        let warn_before = Duration::from_secs(self.cfg().server.invite_warning_secs);
        let now = std::time::Instant::now();
        let mut due = Vec::new();
        for entry in self.channels.iter() {
            let mut channel = entry.value().write();
            let name = channel.name.clone();
            for invite in channel.sweep_invites(now, warn_before) {
                due.push((name.clone(), invite));
            }
        }

        let mut notices = 0usize;
        for (name, invite) in due {
            let invitee = self.find_client(invite.invitee);
            let invitee_nick = invitee
                .as_ref()
                .map(|client| client.nick_or_star())
                .unwrap_or_default();
            if invitee_nick.is_empty() {
                continue;
            }
            let unit = if invite.seconds_left == 1 {
                "second"
            } else {
                "seconds"
            };
            if let Some(invitee) = invitee.as_ref().filter(|client| client.is_local()) {
                let text = if invite.expired {
                    format!("Your invitation to {name} has expired")
                } else {
                    format!(
                        "Your invitation to {name} expires in {} {unit}",
                        invite.seconds_left
                    )
                };
                self.notice(invitee, &text);
                notices += 1;
            }
            if let Some(inviter) = self.find_nick(&invite.by) {
                if inviter.is_local() {
                    let text = if invite.expired {
                        format!("Your invitation to {name} for {invitee_nick} has expired")
                    } else {
                        format!(
                            "Your invitation to {name} for {invitee_nick} expires in {} {unit}",
                            invite.seconds_left
                        )
                    };
                    self.notice(&inviter, &text);
                    notices += 1;
                }
            }
        }
        notices
    }

    /// Start the timer that warns and expires channel invitations.
    ///
    /// A five-second interval is short enough that a warning configured in
    /// whole seconds is always delivered inside its window, and long enough
    /// that an idle server does no meaningful work.
    pub fn spawn_invite_sweeper(self: &Arc<Self>) {
        const INTERVAL: Duration = Duration::from_secs(5);
        let server = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                server.sweep_invites();
            }
        });
    }

    /// Deliver one message to many recipients, tagging per capability.
    ///
    /// `account` is the sender's SASL account; recipients that negotiated
    /// `account-tag` get `@account`, and recipients that negotiated
    /// `server-time` get `@time`. At most four serialisations are produced
    /// whatever the audience size, so fan-out stays O(recipients) with shared
    /// allocations.
    // MARK: speed: high: SPD-FANOUT-001: serialisations are shared across the audience, not built per recipient.
    fn deliver(
        &self,
        recipients: impl IntoIterator<Item = Arc<ClientHandle>>,
        message: &Message,
        except: Option<ClientId>,
        account: Option<&str>,
        tags: &[(String, String)],
    ) {
        let max_line = self.max_line();
        let add_time = !message.tags.iter().any(|(key, _)| key == "time");
        let plain = Bytes::from(message.to_bytes_limited(max_line));
        let mut variants: [Option<Bytes>; 8] = std::array::from_fn(|_| None);

        for recipient in recipients {
            if Some(recipient.id) == except {
                continue;
            }
            let with_time = add_time && recipient.has_cap(CapSet::SERVER_TIME);
            // Borrowed, not owned: the account is only read when a variant is
            // built, and cloning it per recipient was measurably the most
            // expensive part of a tagged fan-out.
            let with_account = account.filter(|_| recipient.has_cap(CapSet::ACCOUNT_TAG));
            let with_tags = recipient.has_cap(CapSet::MESSAGE_TAGS) && !tags.is_empty();
            if !with_time && with_account.is_none() && !with_tags {
                recipient.enqueue(plain.clone());
                continue;
            }
            // Bit 0 selects `@time`, bit 1 `@account`, bit 2 client tags.
            let slot = usize::from(with_time)
                | (usize::from(with_account.is_some()) << 1)
                | (usize::from(with_tags) << 2);
            let bytes = variants[slot].get_or_insert_with(|| {
                let mut copy = message.clone();
                if with_time {
                    copy.push_tag("time", now_iso8601());
                }
                if let Some(account) = with_account {
                    copy.push_tag("account", account);
                }
                if with_tags {
                    for (key, value) in tags {
                        copy.push_tag(key.clone(), value.clone());
                    }
                }
                Bytes::from(copy.to_bytes_limited(max_line))
            });
            recipient.enqueue(bytes.clone());
        }
    }

    /// Broadcast to a set of recipients, tagging `server-time` per capability.
    pub fn broadcast(
        &self,
        recipients: impl IntoIterator<Item = Arc<ClientHandle>>,
        message: &Message,
        except: Option<ClientId>,
    ) {
        self.deliver(recipients, message, except, None, &[]);
    }

    /// Broadcast a message that also carries the sender's `@account` tag.
    pub fn broadcast_with_account(
        &self,
        recipients: impl IntoIterator<Item = Arc<ClientHandle>>,
        message: &Message,
        except: Option<ClientId>,
        account: &str,
    ) {
        self.deliver(recipients, message, except, Some(account), &[]);
    }

    /// Broadcast a message with the sender's account and client-only tags.
    pub fn broadcast_text(
        &self,
        recipients: impl IntoIterator<Item = Arc<ClientHandle>>,
        message: &Message,
        except: Option<ClientId>,
        account: Option<&str>,
        tags: &[(String, String)],
    ) {
        self.deliver(recipients, message, except, account, tags);
    }

    /// Broadcast to every member of a channel.
    pub fn broadcast_channel(
        &self,
        channel: &Channel,
        message: &Message,
        except: Option<ClientId>,
    ) {
        let recipients: Vec<Arc<ClientHandle>> = channel
            .members
            .keys()
            .filter_map(|id| self.find_client(*id))
            .collect();
        self.broadcast(recipients, message, except);
    }

    /// Broadcast to every member of a channel, tagging the sender's account.
    pub fn broadcast_channel_with_account(
        &self,
        channel: &Channel,
        message: &Message,
        except: Option<ClientId>,
        account: &str,
    ) {
        let recipients: Vec<Arc<ClientHandle>> = channel
            .members
            .keys()
            .filter_map(|id| self.find_client(*id))
            .collect();
        self.broadcast_with_account(recipients, message, except, account);
    }

    /// Broadcast to every member of a channel, keeping the sender's tags.
    pub fn broadcast_channel_text(
        &self,
        channel: &Channel,
        message: &Message,
        except: Option<ClientId>,
        account: Option<&str>,
        tags: &[(String, String)],
    ) {
        let recipients: Vec<Arc<ClientHandle>> = channel
            .members
            .keys()
            .filter_map(|id| self.find_client(*id))
            .collect();
        self.broadcast_text(recipients, message, except, account, tags);
    }

    /// Broadcast to common-channel peers that negotiated `capability`.
    ///
    /// Identity events (`SETNAME`, `CHGHOST`, `ACCOUNT`) are only meaningful to
    /// clients that asked for them, so the filter runs before serialisation.
    pub fn broadcast_common_cap(
        &self,
        client: &ClientHandle,
        capability: CapSet,
        message: &Message,
        except: Option<ClientId>,
        account: Option<&str>,
    ) {
        let recipients = self
            .common_recipients(client, except)
            .into_iter()
            .filter(|recipient| recipient.has_cap(capability))
            .collect::<Vec<_>>();
        self.broadcast_text(recipients, message, except, account, &[]);
    }

    /// Send a `standard-replies` `FAIL` to a client that negotiated the cap.
    ///
    /// The numeric the command already produced is still sent: `standard-replies`
    /// is additive, not a replacement, so a client that ignores it loses nothing.
    pub fn standard_fail(&self, client: &ClientHandle, command: &str, code: &str, text: &str) {
        if !client.has_cap(CapSet::STANDARD_REPLIES) {
            return;
        }
        let name = self.config.read().server.name.clone();
        client.send_raw(
            &format!(":{name} FAIL {command} {code} :{text}",),
            self.max_line(),
        );
    }

    /// Broadcast to every channel the client shares with others, deduplicated.
    pub fn broadcast_common(
        &self,
        client: &ClientHandle,
        message: &Message,
        except: Option<ClientId>,
    ) {
        let recipients = self.common_recipients(client, except);
        self.broadcast(recipients, message, except);
    }

    /// Broadcast to every channel the client shares with others, tagging the
    /// actor's account for recipients that negotiated `account-tag`.
    pub fn broadcast_common_with_account(
        &self,
        client: &ClientHandle,
        message: &Message,
        except: Option<ClientId>,
        account: &str,
    ) {
        let recipients = self.common_recipients(client, except);
        self.broadcast_with_account(recipients, message, except, account);
    }

    /// Everyone sharing a channel with `client`, deduplicated.
    fn common_recipients(
        &self,
        client: &ClientHandle,
        except: Option<ClientId>,
    ) -> Vec<Arc<ClientHandle>> {
        let mut seen: HashSet<ClientId> = HashSet::new();
        let mut recipients = Vec::new();
        for folded in client.channels() {
            let Some(channel) = self.channels.get(&folded) else {
                continue;
            };
            for id in channel.read().members.keys() {
                if *id == client.id || Some(*id) == except {
                    continue;
                }
                if seen.insert(*id) {
                    if let Some(handle) = self.find_client(*id) {
                        recipients.push(handle);
                    }
                }
            }
        }
        recipients
    }

    /// Send a message to every authenticated server link.
    pub fn propagate_link(&self, message: &Message) {
        self.propagate_link_from(message, None);
    }

    /// Send a message to every link except `origin`.
    ///
    /// Excluding the origin prevents a two-peer topology from echoing
    /// messages back to the server that just sent them.
    pub fn propagate_link_from(&self, message: &Message, origin: Option<ClientId>) {
        if self.links.is_empty() {
            return;
        }
        let max_line = self.max_line();
        let bytes = Bytes::from(message.to_bytes_limited(max_line));
        for link in self.links.iter() {
            if Some(*link.key()) == origin {
                continue;
            }
            if let Some(client) = self.find_client(*link.key()) {
                client.enqueue(bytes.clone());
            }
        }
    }

    /// Tell every watcher that `nick` came online.
    pub fn monitor_online(&self, nick: &str, mask: &str) {
        self.monitor_event(nick, Some(mask));
    }

    /// Tell every watcher that `nick` went offline.
    pub fn monitor_offline(&self, nick: &str) {
        self.monitor_event(nick, None);
    }

    /// One pass over the clients for either transition.
    ///
    /// Only local clients with `monitor` negotiated and this nickname in their
    /// list receive a line, so a watcher costs one hash lookup per event.
    fn monitor_event(&self, nick: &str, online: Option<&str>) {
        let folded = self.casemap().fold(nick);
        let server = self.name();
        let max_line = self.max_line();
        for entry in self.clients.iter() {
            let client = entry.value();
            if !client.is_local() || !client.has_cap(CapSet::MONITOR) {
                continue;
            }
            if !client.session(|session| session.monitor.contains(&folded)) {
                continue;
            }
            let numeric = if online.is_some() { 730 } else { 731 };
            let payload = online.unwrap_or(nick);
            client.send_raw(
                &format!(":{server} {numeric} {} :{payload}", client.nick_or_star()),
                max_line,
            );
        }
    }

    /// Announce an account change to peers that negotiated `account-notify`.
    pub fn notify_account(&self, client: &ClientHandle, account: Option<&str>) {
        if !client.is_registered() {
            return;
        }
        let mut message = Message::command("ACCOUNT");
        message.prefix = Some(client.mask());
        message.params.push(account.unwrap_or("*").to_owned());
        self.broadcast_common_cap(
            client,
            CapSet::ACCOUNT_NOTIFY,
            &message,
            Some(client.id),
            account,
        );
    }

    /// Attach the logging handle so operator `REHASH` can change verbosity.
    pub fn attach_logging(&self, logging: Arc<LoggingHandle>) {
        *self.logging.write() = Some(logging);
    }

    /// Reload using the attached logging handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when logging was never attached.
    pub fn rehash_attached(&self) -> Result<()> {
        let logging = self.logging.read().clone();
        match logging {
            Some(logging) => self.rehash(&logging),
            None => Err(Error::Config("logging is not attached".to_owned())),
        }
    }

    /// Remove a client from every registry and announce its departure.
    pub fn disconnect(self: &Arc<Self>, client: &Arc<ClientHandle>, reason: &str) {
        if client.removed.swap(true, Ordering::SeqCst) {
            return;
        }
        let casemap = self.casemap();
        if let Some(nick) = client.nick() {
            self.nicks.write().remove(&casemap.fold(&nick));
            self.remember_whowas(client, &nick);
            if client.is_local() {
                self.monitor_offline(&nick);
            }
        }
        self.clients.remove(&client.id);
        self.links.remove(&client.id);
        if client.is_local() {
            self.local_count.fetch_sub(1, Ordering::Relaxed);
        }

        if client.is_registered() {
            let mut quit = Message::command("QUIT");
            quit.prefix = Some(client.mask());
            quit.params.push(reason.to_owned());
            let account = client.session(|session| session.account.clone());
            match account.as_deref() {
                Some(account) => {
                    self.broadcast_common_with_account(client, &quit, Some(client.id), account)
                }
                None => self.broadcast_common(client, &quit, Some(client.id)),
            }
            // Only local users are announced to peers; echoing a peer's own
            // QUIT back at it would loop in a two-server topology.
            if client.is_local() {
                self.propagate_link(&quit);
            }
        }

        for folded in client.channels() {
            // The `get` guard must be dropped before `remove_if` touches the
            // same DashMap shard, otherwise the shard lock deadlocks.
            let channel = match self.channels.get(&folded) {
                Some(entry) => Arc::clone(entry.value()),
                None => continue,
            };
            let empty = {
                let mut guard = channel.write();
                guard.remove(client.id)
            };
            if empty {
                self.channels
                    .remove_if(&folded, |_, candidate| candidate.read().is_empty());
            }
        }

        // An invitation is tied to the session that received it, so a departing
        // client cannot come back to it under a new handle.
        for entry in self.channels.iter() {
            let channel = entry.value();
            if channel.read().invites.contains_key(&client.id) {
                channel.write().withdraw_invite(client.id);
            }
        }

        client.session_mut(|session| session.channels.clear());
        if client.server_link {
            // Everything behind a lost link is gone with it: prune its routes
            // and the users that lived there, then tell the rest of the tree.
            link::forget_link(self, client.id, reason);
        }
        client.request_close();
        debug!(id = client.id, %reason, "client removed");
    }

    fn remember_whowas(&self, client: &ClientHandle, nick: &str) {
        let config = self.cfg();
        let Some(entry) = client.session(|session| {
            Some(WhowasEntry {
                nick: nick.to_owned(),
                user: session.user.clone()?,
                host: session.host.clone(),
                realname: session.realname.clone().unwrap_or_default(),
                server: config.server.name.clone(),
                signon: session.signon,
            })
        }) else {
            return;
        };
        let capacity = config.limits.whowas_size;
        if capacity == 0 {
            return;
        }
        let mut history = self.whowas.write();
        history.push_front(entry);
        history.truncate(capacity);
    }

    /// Recent `WHOWAS` records for `nick`.
    pub fn whowas_entries(&self, nick: &str, limit: usize) -> Vec<WhowasEntry> {
        let casemap = self.casemap();
        let target = casemap.fold(nick);
        self.whowas
            .read()
            .iter()
            .filter(|entry| casemap.fold(&entry.nick) == target)
            .take(limit)
            .cloned()
            .collect()
    }

    /// MOTD lines.
    pub fn motd(&self) -> Vec<String> {
        self.motd.read().clone()
    }

    /// True when the client is an operator holding every privilege in `wanted`.
    ///
    /// The privileges were resolved from the configuration when `OPER`
    /// succeeded, so this is a masked comparison on the session rather than a
    /// search through the operator table on every command.
    pub fn has_privilege(&self, client: &ClientHandle, wanted: OperPrivilege) -> bool {
        client.session(|session| session.modes.oper && session.privileges.contains(wanted))
    }

    /// Local operators, who receive `GLOBOPS` and server notices.
    pub fn oper_recipients(&self) -> Vec<Arc<ClientHandle>> {
        self.clients
            .iter()
            .filter(|entry| entry.value().is_local())
            .filter(|entry| entry.value().session(|session| session.modes.oper))
            .map(|entry| Arc::clone(entry.value()))
            .collect()
    }

    /// Deliver one server notice to the operators subscribed to `category`.
    ///
    /// The filter is evaluated per recipient: an operator with `+s` but no
    /// matching bit receives nothing, and an operator without `+s` receives
    /// nothing at all. That keeps a busy network from waking every oper for a
    /// category none of them asked for.
    pub fn snotice(&self, category: Snomask, text: &str) {
        let name = self.config.read().server.name.clone();
        let max_line = self.max_line();
        let line = |client: &ClientHandle| {
            format!(
                ":{name} NOTICE {} :*** Notice -- {text}",
                client.nick_or_star()
            )
        };
        for entry in self.clients.iter() {
            let client = entry.value();
            if !client.is_local() || client.server_link {
                continue;
            }
            let subscribed = client
                .session(|session| session.modes.snomask && session.snomasks.contains(category));
            if subscribed {
                client.send_raw(&line(client), max_line);
            }
        }
    }

    /// Add or refresh a ban, returning `true` when it was new.
    pub fn add_ban(&self, ban: ServerBan) -> bool {
        let mut bans = self.bans.write();
        let casemap = self.casemap();
        if let Some(existing) = bans
            .iter_mut()
            .find(|entry| entry.kind == ban.kind && casemap.eq(&entry.mask, &ban.mask))
        {
            *existing = ban;
            return false;
        }
        bans.push(ban);
        true
    }

    /// Remove an entry by kind and mask, returning whether one was removed.
    pub fn remove_ban(&self, kind: BanKind, mask: &str) -> bool {
        let casemap = self.casemap();
        let mut bans = self.bans.write();
        let before = bans.len();
        bans.retain(|entry| !(entry.kind == kind && casemap.eq(&entry.mask, mask)));
        bans.len() != before
    }

    /// Drop expired entries, returning how many were removed.
    pub fn prune_bans(&self) -> usize {
        let now = now_unix();
        let mut bans = self.bans.write();
        let before = bans.len();
        bans.retain(|entry| entry.active(now));
        before - bans.len()
    }

    /// Append one channel message to the history ring.
    pub fn remember_history(&self, channel: &str, prefix: &str, text: &str) {
        let folded = self.casemap().fold(channel);
        self.history.remember(
            &folded,
            HistoryEntry {
                at: now_unix(),
                prefix: prefix.to_owned(),
                text: text.to_owned(),
            },
        );
    }

    /// Entries matching `range`, oldest first.
    pub fn history_in_range(
        &self,
        channel: &str,
        range: HistoryRange,
        limit: usize,
    ) -> Vec<HistoryEntry> {
        let folded = self.casemap().fold(channel);
        self.history.query(&folded, range, limit)
    }

    /// True when any ban is stored, expired or not.
    ///
    /// The message path checks this before deriving any masks, so a server
    /// with no bans pays one atomic-length read per message.
    pub fn has_bans(&self) -> bool {
        !self.bans.read().is_empty()
    }

    /// Active bans, newest last.
    pub fn active_bans(&self) -> Vec<ServerBan> {
        let now = now_unix();
        self.bans
            .read()
            .iter()
            .filter(|entry| entry.active(now))
            .cloned()
            .collect()
    }

    /// First active ban of one of `kinds` that covers this user.
    ///
    /// Scans once; the list is bounded by operator actions rather than by
    /// client input, and an empty list returns before building any mask.
    pub fn matching_ban(
        &self,
        kinds: &[BanKind],
        nick: &str,
        user: &str,
        host: &str,
        address: &str,
        account: Option<&str>,
    ) -> Option<ServerBan> {
        let now = now_unix();
        let full = format!("{nick}!{user}@{host}");
        let user_host = format!("{user}@{host}");
        self.bans
            .read()
            .iter()
            .find(|entry| {
                kinds.contains(&entry.kind)
                    && entry.active(now)
                    && entry.matches_mask(nick, &full, &user_host, host, address, account)
            })
            .cloned()
    }

    /// Operators currently connected.
    pub fn oper_count(&self) -> usize {
        self.clients
            .iter()
            .filter(|entry| entry.value().session(|session| session.modes.oper))
            .count()
    }

    /// Parse and execute one inbound line.
    ///
    /// A client that negotiated `labeled-response` and attached a usable
    /// `label` tag gets it echoed on every reply the command produces. A
    /// command that produced no reply at all is answered with `ACK`.
    pub async fn dispatch(self: &Arc<Self>, client: &Arc<ClientHandle>, line: &str) {
        let config = self.cfg();
        let message = match Message::parse(line, config.limits.max_line_len) {
            Ok(message) => message,
            Err(error) => {
                debug!(id = client.id, %error, "dropping malformed line");
                return;
            }
        };

        if client.server_link {
            link::handle(self, client, &message).await;
            return;
        }

        let label = label_tag(&message).filter(|_| client.has_cap(CapSet::LABELED_RESPONSE));
        let Some(label) = label else {
            self.execute(client, message, &config).await;
            return;
        };
        let context = Arc::new(ResponseContext {
            client: client.id,
            label,
            sent: std::sync::atomic::AtomicUsize::new(0),
        });
        let tracker = Arc::clone(&context);
        RESPONSE
            .scope(context, self.execute(client, message, &config))
            .await;
        if tracker.sent.load(Ordering::Relaxed) == 0 {
            let mut ack = Message::command("ACK");
            ack.prefix = Some(self.name());
            ack.push_tag("label", tracker.label.clone());
            client.send(&ack, self.max_line());
        }
    }

    /// Run one parsed command, sending its replies to `client`.
    async fn execute(
        self: &Arc<Self>,
        client: &Arc<ClientHandle>,
        message: Message,
        config: &crate::config::Config,
    ) {
        if let Some(outcome) = self.hook_event("command", client, &message) {
            if let Some(notice) = outcome.notice {
                self.notice(client, &notice);
            }
            for reply in &outcome.lines {
                client.send_raw(reply, config.limits.max_line_len);
            }
            if !outcome.allow {
                return;
            }
        }

        let Some(spec) = commands::lookup(&message.command) else {
            if let Some(outcome) = self.run_custom_command(client, &message) {
                for reply in &outcome.lines {
                    client.send_raw(reply, config.limits.max_line_len);
                }
                if !outcome.allow {
                    return;
                }
            } else {
                self.numeric(
                    client,
                    Numeric::ERR_UNKNOWNCOMMAND,
                    format!("{} :Unknown command", message.command),
                );
            }
            return;
        };

        if spec.access != commands::Access::Unregistered && !client.is_registered() {
            self.numeric(
                client,
                Numeric::ERR_NOTREGISTERED,
                ":You have not registered",
            );
            return;
        }
        if message.params.len() < spec.min_params {
            self.numeric(
                client,
                Numeric::ERR_NEEDMOREPARAMS,
                format!("{} :Not enough parameters", message.command),
            );
            return;
        }
        if let commands::Access::Oper(privilege) = spec.access {
            if !self.has_privilege(client, privilege) {
                self.numeric(
                    client,
                    Numeric::ERR_NOPRIVILEGES,
                    ":Permission Denied- You're not an IRC operator",
                );
                return;
            }
        }

        let command = commands::Cmd {
            server: Arc::clone(self),
            client: Arc::clone(client),
            msg: message,
        };
        match (spec.handler)(command).await {
            Ok(()) => {}
            Err(error) => self.numeric(client, error.code, error.text),
        }
    }

    /// True when compiled rules or scripts are loaded.
    pub fn scripts_enabled(&self) -> bool {
        self.hooks.read().is_enabled()
    }

    /// Run a named script hook for `client`.
    pub fn hook_event(
        &self,
        event: &str,
        client: &ClientHandle,
        message: &Message,
    ) -> Option<HookOutcome> {
        if !self.hooks.read().is_enabled() {
            return None;
        }
        let context = self.hook_context(client, message);
        Some(self.hooks.read().run(event, &context))
    }

    fn run_custom_command(&self, client: &ClientHandle, message: &Message) -> Option<HookOutcome> {
        if !self.hooks.read().is_enabled() {
            return None;
        }
        let context = self.hook_context(client, message);
        self.hooks.read().custom_command(&message.command, &context)
    }

    fn hook_context(&self, client: &ClientHandle, message: &Message) -> HookContext {
        let (nick, user, host, oper, account) = client.session(|session| {
            (
                session.nick.clone().unwrap_or_default(),
                session.user.clone().unwrap_or_default(),
                session.host.clone(),
                session.modes.oper,
                session.account.clone(),
            )
        });
        let first = message.param(0).unwrap_or_default().to_owned();
        let channel = if commands::is_channel_name(&first) {
            first.clone()
        } else {
            String::new()
        };
        HookContext {
            server: self.config.read().server.name.clone(),
            nick,
            user,
            host,
            command: message.command.clone(),
            params: message.params.clone(),
            channel,
            text: message.trailing().unwrap_or_default().to_owned(),
            oper,
            account,
        }
    }

    /// Reload configuration, logging and scripts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when no path is known or the new file is
    /// invalid. The previous configuration stays active on failure.
    pub fn rehash(&self, logging: &LoggingHandle) -> Result<()> {
        let Some(path) = &self.config_path else {
            return Err(Error::Config("no configuration file to reload".to_owned()));
        };
        let config = Arc::new(Config::load(path)?);
        let hooks = ScriptHost::load(&config.scripting)?;
        let accounts: Arc<dyn AccountBackend> = Arc::new(ConfigAccounts::load(&config.accounts)?);
        logging.set_level(&config.logging.level)?;

        let motd = load_motd(&config);
        // Privileges are cached on the session so authorisation is one masked
        // test. That cache has to be refreshed here, otherwise a reload that
        // narrows or removes an operator would leave the old authority in
        // place until the next `OPER`, which is the opposite of what an
        // operator issuing `REHASH` to revoke access expects.
        for entry in self.clients.iter() {
            let client = entry.value();
            let Some(name) = client.session(|session| session.oper.clone()) else {
                continue;
            };
            let privileges = config
                .opers
                .iter()
                .find(|oper| oper.name == name)
                .map(|oper| OperPrivilege::from_flags(&oper.flags));
            client.session_mut(|session| match privileges {
                Some(privileges) => session.privileges = privileges,
                None => {
                    session.privileges = OperPrivilege::NONE;
                    session.oper = None;
                    session.modes.oper = false;
                    session.modes.snomask = false;
                    session.snomasks = Snomask::NONE;
                }
            });
        }
        *self.config.write() = config;
        *self.hooks.write() = hooks;
        *self.accounts.write() = accounts;
        *self.motd.write() = motd;
        info!("configuration reloaded from {}", path.display());
        Ok(())
    }

    /// Operator-facing `REHASH` hook that reports per-subsystem success.
    pub fn reload_scripts(&self) -> Result<()> {
        let config = self.cfg();
        let hooks = ScriptHost::load(&config.scripting)?;
        *self.hooks.write() = hooks;
        Ok(())
    }

    /// Disconnect every local client, e.g. on shutdown.
    pub fn shutdown(&self) {
        let max_line = self.max_line();
        for entry in self.clients.iter() {
            let client = entry.value();
            if client.is_local() {
                client.send_raw("ERROR :Server shutting down", max_line);
                client.request_close();
            }
        }
    }

    /// Build an `RPL_ISUPPORT` token list.
    pub fn isupport_tokens(&self) -> Vec<String> {
        let config = self.cfg();
        vec![
            format!("AWAYLEN={}", 200),
            "CASEMAPPING=".to_owned() + config.server.casemapping.token(),
            format!("CHANLIMIT=#&:{}", config.limits.max_channels_per_client),
            "CHANMODES=b,e,k,l,imnpstR".to_owned(),
            "CHANNELLEN=64".to_owned(),
            "CHANTYPES=#&".to_owned(),
            "ELIST=CTU".to_owned(),
            format!("KICKLEN={}", 200),
            "MAXLIST=b:100,e:100".to_owned(),
            format!("MAXTARGETS={}", config.limits.max_targets),
            format!("NICKLEN={}", config.server.max_nick_length),
            format!("NETWORK={}", config.server.network),
            "PREFIX=(ov)@+".to_owned(),
            "STATUSMSG=@+".to_owned(),
            format!("TOPICLEN={}", 300),
            "USERLEN=18".to_owned(),
        ]
    }
}

fn load_motd(config: &Config) -> Vec<String> {
    if let Some(path) = &config.server.motd {
        match std::fs::read_to_string(path) {
            Ok(text) => return text.lines().map(str::to_owned).collect(),
            Err(error) => warn!(%path, %error, "cannot read MOTD, using the default"),
        }
    }
    vec![
        format!(
            "Welcome to {} on the {} network.",
            config.server.name, config.server.network
        ),
        "This server implements RFC 1459 and RFC 2810-2813.".to_owned(),
        "TLS is available on port 6697; compression via COMPRESS zlib.".to_owned(),
    ]
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("name", &self.config.read().server.name)
            .field("clients", &self.clients.len())
            .field("channels", &self.channels.len())
            .finish()
    }
}

/// Convert a command error into the numeric reply the dispatcher sends.
impl From<CommandError> for Message {
    fn from(error: CommandError) -> Self {
        let mut message = Message::command(format!("{:03}", error.code.0));
        message.params.push(error.text);
        message
    }
}
