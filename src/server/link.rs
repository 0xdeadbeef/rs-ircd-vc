//! RFC 2813 server links: authentication, multi-hop routing and timestamp
//! collision resolution.
//!
//! The topology is a spanning tree. Each server learns the network from
//! `SERVER <name> <hops> <sid> :<description>` introductions carrying a hop
//! count; the lowest-hop route wins and only improvements are forwarded, so
//! introductions converge instead of looping. User events are relayed to every
//! other link, which is loop-free on a tree, while private messages follow the
//! route to the recipient's server instead of flooding.
//!
//! Every user carries a creation timestamp (TS). When two servers introduce the
//! same nickname, the lower TS wins; a tie breaks on the lexicographically
//! lower server name, as TS6 does. The loser is removed with `KILL`, so every
//! server converges on the same state instead of keeping a duplicate.

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::commands::is_channel_name;
use crate::config::LinkSection;
use crate::protocol::{Message, Numeric};
use crate::server::channel::{BanEntry, MemberMode};
use crate::server::{Channel, ClientHandle, ClientId, Server};
use crate::util::{now_unix, secret_matches};

/// Longest chain of servers an introduction may cross.
const MAX_HOPS: u32 = 16;

/// A parsed full user introduction.
#[derive(Debug, Clone)]
struct Introduction {
    nick: String,
    hops: u32,
    ts: u64,
    user: String,
    host: String,
    server: String,
    modes: String,
    realname: String,
}

/// Announce a freshly registered local user to every peer.
pub fn introduce(server: &Arc<Server>, client: &Arc<ClientHandle>) {
    if server.links.is_empty() {
        return;
    }
    let Some(nick) = client.nick() else {
        return;
    };
    let (user, host, realname, modes, ts) = client.session(|session| {
        (
            session.user.clone().unwrap_or_default(),
            session.host.clone(),
            session.realname.clone().unwrap_or_default(),
            session.modes.to_flags(),
            session.ts,
        )
    });
    let introduction = Introduction {
        nick,
        hops: 1,
        ts,
        user,
        host,
        server: server.name(),
        modes,
        realname,
    };
    server.propagate_link(&introduction_message(client.mask(), &introduction));
    if let Some(message) = account_message(client) {
        server.propagate_link(&message);
    }
}

/// Announce a local nickname change with the full RFC 2813 form.
pub fn propagate_nick(
    server: &Arc<Server>,
    client: &Arc<ClientHandle>,
    new_nick: &str,
    old_mask: &str,
) {
    if server.links.is_empty() {
        return;
    }
    let (user, host, realname, modes, ts) = client.session(|session| {
        (
            session.user.clone().unwrap_or_default(),
            session.host.clone(),
            session.realname.clone().unwrap_or_default(),
            session.modes.to_flags(),
            session.ts,
        )
    });
    let introduction = Introduction {
        nick: new_nick.to_owned(),
        hops: 1,
        ts,
        user,
        host,
        server: server.name(),
        modes,
        realname,
    };
    server.propagate_link(&introduction_message(old_mask.to_owned(), &introduction));
    if let Some(message) = account_message(client) {
        server.propagate_link(&message);
    }
}

fn introduction_message(prefix: String, user: &Introduction) -> Message {
    let mut message = Message::command("NICK");
    message.prefix = Some(prefix);
    message.params = vec![
        user.nick.clone(),
        user.hops.to_string(),
        user.ts.to_string(),
        user.user.clone(),
        user.host.clone(),
        user.server.clone(),
        user.modes.clone(),
        user.realname.clone(),
    ];
    message
}

/// The `ACCOUNT` companion of a user introduction, when the user is logged in.
///
/// The account is a separate message rather than another field of `NICK`, which
/// keeps the positional introduction format usable by peers that do not know
/// the extension. A receiver applies it to the shadow the preceding `NICK`
/// created.
fn account_message(client: &ClientHandle) -> Option<Message> {
    let account = client.session(|session| session.account.clone())?;
    let mut message = Message::command("ACCOUNT");
    message.prefix = Some(client.mask());
    message.params.push(account);
    Some(message)
}

/// Relay a post-registration account change to the other servers.
///
/// Users who authenticated before registering already carry their account in
/// the introduction; this covers a login that happens after the user is
/// visible, and clears the account with `*` on logout.
pub fn account_changed(server: &Arc<Server>, client: &Arc<ClientHandle>) {
    if server.links.is_empty() || !client.is_registered() || !client.is_local() {
        return;
    }
    let account = client
        .session(|session| session.account.clone())
        .unwrap_or_else(|| "*".to_owned());
    let mut message = Message::command("ACCOUNT");
    message.prefix = Some(client.mask());
    message.params.push(account);
    server.propagate_link(&message);
}

/// Handle one message from an authenticated or pending server link.
pub async fn handle(server: &Arc<Server>, link: &Arc<ClientHandle>, message: &Message) {
    if !server.links.contains_key(&link.id) {
        handshake(server, link, message);
        return;
    }
    let origin = link.id;
    match message.command.as_str() {
        "NICK" => inbound_nick(server, origin, message),
        "SERVER" => inbound_server(server, origin, message),
        "SJOIN" => inbound_sjoin(server, origin, message),
        "EOB" => {
            // The burst is over, so its per-channel verdicts are no longer
            // needed; later changes to those channels are ordinary traffic.
            server
                .burst_remote_won
                .retain(|(link, _), _| *link != origin);
            debug!(id = origin, "netburst complete");
        }
        "SQUIT" => inbound_squit(server, origin, message),
        "KILL" => inbound_kill(server, origin, message),
        "JOIN" => inbound_join(server, origin, message),
        "PART" => inbound_part(server, origin, message),
        "KICK" => inbound_kick(server, origin, message),
        "INVITE" => inbound_invite(server, origin, message),
        "QUIT" => inbound_quit(server, origin, message),
        "PRIVMSG" | "NOTICE" => inbound_text(server, origin, message),
        "TOPIC" => inbound_topic(server, origin, message),
        "MODE" => inbound_mode(server, origin, message),
        "ACCOUNT" => inbound_account(server, origin, message),
        "PING" => {
            let token = message.param(0).unwrap_or_default();
            let name = server.name();
            link.send_raw(&format!(":{name} PONG {name} :{token}"), server.max_line());
        }
        "PONG" => {}
        "ERROR" => server.disconnect(link, "Link closed"),
        other => debug!(command = other, "unimplemented link command ignored"),
    }
}

/// Why a `SERVER` introduction was refused.
///
/// The variants exist so the admission policy can be tested without a socket:
/// [`admit`] decides, and the handshake only turns the result into wire text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// An inbound peer sent `SERVER` before a successful `PASS`.
    PassRequired,
    /// The introduction carried no server name.
    MissingName,
    /// The peer allowlist is configured and does not contain this name.
    NotAPeer,
    /// The peer claimed this server's own name.
    SelfLink,
    /// A dialled link named a server that is not configured.
    NotAConfiguredLink,
    /// A route to this server already exists, so accepting it would form a
    /// cycle.
    AlreadyConnected,
}

impl Refusal {
    /// Wire text sent to the refused peer.
    ///
    /// These strings are part of the operator-visible behaviour, so they are
    /// defined once here rather than in the handshake.
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::PassRequired => "PASS required before SERVER",
            Refusal::MissingName => "SERVER requires a name",
            Refusal::NotAPeer => "Server is not configured as a peer",
            Refusal::SelfLink => "Cannot link to myself",
            Refusal::NotAConfiguredLink => "Server is not a configured link",
            Refusal::AlreadyConnected => "Server is already connected",
        }
    }
}

/// What the handshake knows about a connection that has sent `SERVER`.
#[derive(Debug, Clone, Copy)]
pub struct ServerIntroduction<'a> {
    /// Server name the peer claims.
    pub name: &'a str,
    /// True when this server opened the connection.
    pub dialing: bool,
    /// True when `PASS` already matched this connection.
    pub pass_ok: bool,
    /// True when a route to `name` already exists.
    pub already_connected: bool,
}

/// Decide whether a peer may be admitted.
///
/// The order is deliberate and matches the wire behaviour: authentication is
/// checked before anything the peer said, then the name, then the allowlist and
/// topology rules. A dialled link has already authenticated when it opened the
/// socket, so it does not need `PASS`; an inbound peer does.
///
/// # Errors
///
/// Returns the first [`Refusal`] that applies.
pub fn admit(
    server_name: &str,
    peers: &[String],
    links: &[LinkSection],
    introduction: &ServerIntroduction<'_>,
) -> std::result::Result<(), Refusal> {
    if !introduction.dialing && !introduction.pass_ok {
        return Err(Refusal::PassRequired);
    }
    if introduction.name.is_empty() {
        return Err(Refusal::MissingName);
    }
    if !peers.is_empty()
        && !peers
            .iter()
            .any(|peer| peer.eq_ignore_ascii_case(introduction.name))
    {
        return Err(Refusal::NotAPeer);
    }
    if introduction.name.eq_ignore_ascii_case(server_name) {
        return Err(Refusal::SelfLink);
    }
    if introduction.dialing
        && !links
            .iter()
            .any(|link| link.name.eq_ignore_ascii_case(introduction.name))
    {
        return Err(Refusal::NotAConfiguredLink);
    }
    if introduction.already_connected {
        return Err(Refusal::AlreadyConnected);
    }
    Ok(())
}

/// Resolve the configured link password.
///
/// A missing variable and an empty variable both mean the same thing: links are
/// refused until the operator configures one. Reporting this as "not
/// configured" rather than "invalid password" matters, because it tells an
/// operator what to fix.
pub fn usable_link_password(configured: Option<&str>) -> Option<&str> {
    configured.filter(|password| !password.is_empty())
}

// MARK: security: critical: SEC-LINK-001: a link is refused unless the configured password matches.
fn handshake(server: &Arc<Server>, link: &Arc<ClientHandle>, message: &Message) {
    match message.command.as_str() {
        "PASS" => {
            let config = server.cfg();
            let configured = config
                .server
                .link_password_env
                .as_deref()
                .and_then(|variable| std::env::var(variable).ok());
            let Some(expected) = usable_link_password(configured.as_deref()) else {
                reject(server, link, "Link authentication is not configured");
                return;
            };
            let supplied = message.param(0).unwrap_or_default();
            // MARK: security: high: SEC-LINK-002: digests are compared, so neither content nor length leaks.
            if secret_matches(expected, supplied) {
                link.session_mut(|session| session.pass_ok = true);
            } else {
                reject(server, link, "Invalid link password");
            }
        }
        "SERVER" => {
            let config = server.cfg();
            let name = message.param(0).unwrap_or_default().to_owned();
            // The policy lives in `admit`, so every rule below is exercised by
            // the audit harness without opening a socket.
            let introduction = ServerIntroduction {
                name: &name,
                dialing: link.dialing,
                pass_ok: link.session(|session| session.pass_ok),
                already_connected: server.route(&name).is_some(),
            };
            if let Err(refusal) = admit(
                &config.server.name,
                &config.server.peers,
                &config.links,
                &introduction,
            ) {
                reject(server, link, refusal.reason());
                return;
            }

            let sid = message.param(2).unwrap_or("000").to_owned();
            let description = message.param(3).unwrap_or_default().to_owned();
            server.add_route(&name, &sid, &description, link.id, 1);
            server.links.insert(link.id, name.clone());
            link.session_mut(|session| session.registered = true);

            // A burst only reaches the newcomer, so the rest of the tree has
            // to be told about it as well; otherwise a server one hop further
            // out never learns the route and the network stays partitioned.
            // The published count is relative to this server, and receivers
            // add their own hop before forwarding.
            let mut introduced = Message::command("SERVER");
            introduced.prefix = message.prefix.clone().or_else(|| Some(name.clone()));
            introduced.params = vec![
                name.clone(),
                "1".to_owned(),
                sid.clone(),
                description.clone(),
            ];
            server.propagate_link_from(&introduced, Some(link.id));

            // A dialled link already learned who we are from our opening
            // SERVER, so only the accepting side replies.
            if !link.dialing {
                let mut reply = Message::command("SERVER");
                reply.prefix = Some(config.server.name.clone());
                reply.params = vec![
                    config.server.name.clone(),
                    "1".to_owned(),
                    config.server.sid.clone(),
                    config.server.description.clone(),
                ];
                link.send(&reply, server.max_line());
            }
            // A peer starts from an empty view after a split, so the handshake
            // is followed immediately by a burst of everything this server has.
            send_burst(server, link);
            info!(peer = %name, id = link.id, "server link established");
        }
        "PING" => {
            let token = message.param(0).unwrap_or_default();
            let name = server.name();
            link.send_raw(&format!(":{name} PONG {name} :{token}"), server.max_line());
        }
        "ERROR" => server.disconnect(link, "Link closed"),
        other => {
            debug!(command = other, "unexpected pre-handshake command");
            reject(server, link, "Handshake required");
        }
    }
}

fn reject(server: &Arc<Server>, link: &Arc<ClientHandle>, reason: &str) {
    warn!(id = link.id, reason, "server link rejected");
    link.send_raw(&format!("ERROR :{reason}"), server.max_line());
    server.disconnect(link, reason);
}

fn prefix_nick(message: &Message) -> String {
    message
        .prefix
        .as_deref()
        .unwrap_or_default()
        .split('!')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// `SERVER` introduction of another server behind a peer.
fn inbound_server(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let Some(name) = message.param(0).filter(|name| !name.is_empty()) else {
        return;
    };
    if name.eq_ignore_ascii_case(&server.name()) {
        warn!(%name, "peer tried to introduce this server");
        return;
    }
    let published: u32 = message
        .param(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    if published >= MAX_HOPS {
        debug!(%name, published, "server introduction exceeded the hop limit");
        return;
    }
    let hops = published + 1;
    let sid = message.param(2).unwrap_or_default();
    let description = message.param(3).unwrap_or_default();
    if !server.add_route(name, sid, description, origin, hops) {
        // Same distance or worse: nothing changed, so nothing is forwarded.
        return;
    }
    let mut forwarded = Message::command("SERVER");
    forwarded.prefix = message.prefix.clone();
    forwarded.params = vec![
        name.to_owned(),
        hops.to_string(),
        sid.to_owned(),
        description.to_owned(),
    ];
    server.propagate_link_from(&forwarded, Some(origin));
    info!(%name, hops, "server route learned");
}

/// Remove a nickname from the network after losing a collision.
fn kill_user(server: &Arc<Server>, target: &Arc<ClientHandle>, reason: &str) {
    let mut kill = Message::command("KILL");
    kill.prefix = Some(server.name());
    kill.params.push(target.nick_or_star());
    kill.params.push(reason.to_owned());
    server.propagate_link(&kill);
    if target.is_local() {
        target.send_raw(
            &format!("ERROR :Closing link: Killed ({reason})"),
            server.max_line(),
        );
    }
    server.disconnect(target, reason);
}

fn parse_introduction(message: &Message) -> Option<Introduction> {
    Some(Introduction {
        nick: message.param(0)?.to_owned(),
        hops: message
            .param(1)
            .and_then(|value| value.parse().ok())
            .unwrap_or(1),
        ts: message
            .param(2)
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(now_unix),
        user: message.param(3).unwrap_or("user").to_owned(),
        host: message.param(4).unwrap_or("host").to_owned(),
        server: message.param(5).unwrap_or("remote").to_owned(),
        modes: message.param(6).unwrap_or_default().to_owned(),
        realname: message.params.get(7).cloned().unwrap_or_default(),
    })
}

fn inbound_nick(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let Some(new_nick) = message.param(0).filter(|nick| !nick.is_empty()) else {
        return;
    };
    if message.params.len() >= 7 {
        let Some(introduction) = parse_introduction(message) else {
            return;
        };
        if introduction.hops >= MAX_HOPS {
            debug!(nick = %introduction.nick, "introduction exceeded the hop limit");
            return;
        }
        if server.route(&introduction.server).is_none() {
            // A user cannot live on a server the network cannot reach.
            debug!(
                server = %introduction.server,
                nick = %introduction.nick,
                "introduction for a server that is not in the routing table"
            );
            return;
        }
        match server.find_nick(new_nick) {
            Some(existing) => collide(server, origin, &introduction, existing),
            None => accept(server, origin, introduction),
        }
        return;
    }

    let previous = prefix_nick(message);
    let shrunk = previous.to_owned();
    let Some(shadow) = server.find_nick(&shrunk) else {
        debug!(%shrunk, "nick change for an unknown user ignored");
        return;
    };
    if shadow.is_local() {
        debug!(%shrunk, "peer attempted to rename a local user");
        return;
    }
    if let Some(existing) = server.find_nick(new_nick) {
        if existing.id != shadow.id && !rename_wins(server, &shadow, new_nick, &existing) {
            // The renaming user loses; its owner is the link it came from.
            let mut kill = Message::command("KILL");
            kill.prefix = Some(server.name());
            kill.params.push(shrunk);
            kill.params.push(format!("Nick collision on {new_nick}"));
            if let Some(link) = server.find_client(origin) {
                link.send(&kill, server.max_line());
            }
            return;
        }
    }
    let old_mask = shadow.mask();
    shadow.session_mut(|session| session.nick = Some(new_nick.to_owned()));
    server.release_nick(&shrunk);
    if !server.reserve_nick(new_nick, shadow.id) {
        warn!(%new_nick, "remote nickname collision");
    }

    let mut notice = Message::command("NICK");
    notice.prefix = Some(old_mask);
    notice.params.push(new_nick.to_owned());
    let account = shadow.session(|session| session.account.clone());
    match account.as_deref() {
        Some(account) => {
            server.broadcast_common_with_account(&shadow, &notice, Some(shadow.id), account)
        }
        None => server.broadcast_common(&shadow, &notice, Some(shadow.id)),
    }
    server.propagate_link_from(&notice, Some(origin));
}

/// True when the renaming user keeps the nickname it is moving to.
fn rename_wins(
    server: &Arc<Server>,
    renamer: &Arc<ClientHandle>,
    target_nick: &str,
    existing: &Arc<ClientHandle>,
) -> bool {
    let (renamer_ts, renamer_server) = (
        renamer.session(|session| session.ts),
        renamer
            .remote_server
            .clone()
            .unwrap_or_else(|| server.name()),
    );
    let (existing_ts, existing_server) = (
        existing.session(|session| session.ts),
        existing
            .remote_server
            .clone()
            .unwrap_or_else(|| server.name()),
    );
    let wins = (renamer_ts, renamer_server.as_str()) < (existing_ts, existing_server.as_str());
    if wins {
        kill_user(
            server,
            existing,
            &format!("Nick collision on {target_nick}"),
        );
    }
    wins
}

/// Resolve a nickname collision between an incoming user and an existing one.
///
/// The lower TS wins. Equal timestamps are broken by the lower server name so
/// that every server makes the same choice without another round trip.
fn collide(
    server: &Arc<Server>,
    origin: ClientId,
    introduction: &Introduction,
    existing: Arc<ClientHandle>,
) {
    let existing_ts = existing.session(|session| session.ts);
    let existing_server = existing
        .remote_server
        .clone()
        .unwrap_or_else(|| server.name());
    // The same user re-announced (a netburst for a user we already hold) is
    // not a collision: refreshing it must never kill the original.
    if introduction.ts == existing_ts && introduction.server.eq_ignore_ascii_case(&existing_server)
    {
        return;
    }
    let reason = format!(
        "Nick collision on {} (TS {} vs {})",
        introduction.nick, introduction.ts, existing_ts
    );
    let incoming_wins =
        (introduction.ts, introduction.server.as_str()) < (existing_ts, existing_server.as_str());

    if incoming_wins {
        warn!(nick = %introduction.nick, %reason, winner = %introduction.server, "collision: incoming user wins");
        kill_user(server, &existing, &reason);
        accept(server, origin, introduction.clone());
    } else {
        warn!(nick = %introduction.nick, %reason, winner = %existing_server, "collision: existing user wins");
        let mut kill = Message::command("KILL");
        kill.prefix = Some(server.name());
        kill.params.push(introduction.nick.clone());
        kill.params.push(reason);
        if let Some(link) = server.find_client(origin) {
            link.send(&kill, server.max_line());
        }
    }
}

/// Introduce a remote user and forward the introduction with a higher hop count.
fn accept(server: &Arc<Server>, origin: ClientId, introduction: Introduction) {
    let shadow = server.add_remote(
        &introduction.server,
        &introduction.nick,
        &introduction.user,
        &introduction.host,
        &introduction.realname,
        introduction.ts,
    );
    apply_modes(&shadow, &introduction.modes);

    let forwarded = Introduction {
        hops: introduction.hops + 1,
        ..introduction
    };
    server.propagate_link_from(
        &introduction_message(shadow.mask(), &forwarded),
        Some(origin),
    );
}

/// Apply the propagatable user modes from an introduction.
fn apply_modes(shadow: &Arc<ClientHandle>, modes: &str) {
    let mut adding = true;
    let mut invisible = false;
    let mut wallops = false;
    for character in modes.chars() {
        match character {
            '+' => adding = true,
            '-' => adding = false,
            'i' => invisible = adding,
            'w' => wallops = adding,
            _ => {}
        }
    }
    shadow.session_mut(|session| {
        session.modes.invisible = invisible;
        session.modes.wallops = wallops;
    });
}

/// `SQUIT` from a peer: a server left the network.
fn inbound_squit(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let Some(name) = message.param(0).filter(|name| !name.is_empty()) else {
        return;
    };
    let reason = message.param(1).unwrap_or("Server quit");

    let direct = server
        .links
        .iter()
        .find(|entry| entry.value().eq_ignore_ascii_case(name))
        .map(|entry| *entry.key());
    if let Some(link_id) = direct {
        // A peer announcing its own departure: dropping the link prunes the
        // whole subtree it carried.
        if let Some(link) = server.find_client(link_id) {
            server.disconnect(&link, reason);
        }
        return;
    }

    let Some(info) = server.remove_route(name) else {
        debug!(%name, "SQUIT for an unknown server ignored");
        return;
    };
    let mut names = HashSet::with_capacity(1);
    names.insert(server.casemap().fold(&info.name));
    prune_users(server, &names, reason);
    server.propagate_link_from(message, Some(origin));
    info!(%name, reason, "server removed by SQUIT");
}

/// `KILL` from a peer: remove one user everywhere.
fn inbound_kill(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let Some(nick) = message.param(0) else {
        return;
    };
    let reason = message.param(1).unwrap_or("Killed");
    let Some(target) = server.find_nick(nick) else {
        return;
    };
    server.propagate_link_from(message, Some(origin));
    if target.is_local() {
        target.send_raw(
            &format!("ERROR :Closing link: Killed ({reason})"),
            server.max_line(),
        );
    }
    server.disconnect(&target, reason);
    info!(%nick, reason, "user killed over the link");
}

/// Reason a remote join must be refused, if any.
///
/// Only rules whose state can differ between servers are applied: account-only
/// channels and account/mask bans. The joining server already ran its own copy
/// of these checks, so a refusal here means the copies diverged and the two
/// servers have to be reconciled with a `KICK`.
fn remote_join_refusal(
    channel: &Channel,
    user: &ClientHandle,
    key: Option<&str>,
) -> Option<&'static str> {
    if channel
        .limit
        .is_some_and(|limit| channel.members.len() >= limit)
    {
        return Some("Cannot join channel (+l)");
    }
    if let Some(expected) = channel.key.as_deref() {
        if key != Some(expected) {
            return Some("Cannot join channel (+k)");
        }
    }
    if channel.invite_only && !channel.invited(user.id) {
        return Some("Cannot join channel (+i)");
    }
    let (nick, name, host, account) = user.session(|session| {
        (
            session.nick.clone().unwrap_or_default(),
            session.user.clone().unwrap_or_default(),
            session.host.clone(),
            session.account.clone(),
        )
    });
    if channel.account_only && account.is_none() {
        return Some("Cannot join channel (+R) - you need to be authenticated");
    }
    if channel.is_banned(&nick, &name, &host, account.as_deref()) {
        return Some("Cannot join channel (+b)");
    }
    None
}

/// Send a refused join back along the link it arrived on as a `KICK`.
///
/// The user's home server removes the membership, tells the client and forwards
/// the `KICK`, so the whole tree converges on the refusal.
fn refuse_join(
    server: &Arc<Server>,
    origin: ClientId,
    user: &ClientHandle,
    channel: &str,
    reason: &str,
) {
    let nick = user.nick_or_star();
    debug!(%nick, %channel, %reason, "remote join refused");
    let mut kick = Message::command("KICK");
    kick.prefix = Some(server.name());
    kick.params = vec![channel.to_owned(), nick, reason.to_owned()];
    if let Some(link) = server.find_client(origin) {
        link.send(&kick, server.max_line());
    }
}

fn inbound_join(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let nick = prefix_nick(message);
    let Some(user) = server.find_nick(&nick) else {
        return;
    };
    if user.is_local() {
        return;
    }
    let account = user.session(|session| session.account.clone());
    let Some(channels) = message.param(0) else {
        return;
    };
    let keys = message
        .param(1)
        .map(|keys| keys.split(',').collect::<Vec<_>>())
        .unwrap_or_default();
    for (index, name) in channels.split(',').enumerate() {
        if !is_channel_name(name) {
            continue;
        }
        // Keys pair with channels by position, as in the client syntax.
        let key = keys.get(index).copied().filter(|key| !key.is_empty());
        let folded = server.casemap().fold(name);
        // An existing channel here may be stricter than the copy the joining
        // server saw, so the join is re-checked. Refusing silently is not
        // enough: the user has already been told they joined, so the refusal
        // travels back to that server as a `KICK`.
        if let Some(entry) = server.channels.get(&folded) {
            let refusal = {
                let channel = entry.value().read();
                remote_join_refusal(&channel, &user, key)
            };
            if let Some(reason) = refusal {
                refuse_join(server, origin, &user, name, reason);
                continue;
            }
        }
        let entry = server
            .channels
            .entry(folded.clone())
            .or_insert_with(|| Arc::new(RwLock::new(Channel::new(name))));
        let (recipients, channel_name) = {
            let mut channel = entry.value().write();
            channel.add(user.id);
            let recipients = channel
                .members
                .keys()
                .filter_map(|id| server.find_client(*id))
                .collect::<Vec<_>>();
            (recipients, channel.name.clone())
        };
        drop(entry);
        user.session_mut(|session| session.channels.insert(folded));

        let mut join = Message::command("JOIN");
        join.prefix = Some(user.mask());
        join.params.push(channel_name);
        match account.as_deref() {
            Some(account) => {
                server.broadcast_with_account(recipients, &join, Some(user.id), account)
            }
            None => server.broadcast(recipients, &join, Some(user.id)),
        }
        // The next hop needs the key to apply the same rule; members do not.
        if let Some(key) = key {
            join.params.push(key.to_owned());
        }
        server.propagate_link_from(&join, Some(origin));
    }
}

/// `INVITE` from a peer: record the invitation where the invitee lives.
///
/// `+i` is per-server state, so each server keeps its own invite set keyed by
/// its own handle id. Relaying the invitation lets a remote user actually pass
/// the `+i` check instead of being refused by every other server.
fn inbound_invite(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let Some(nick) = message.param(0) else {
        return;
    };
    let Some(channel_name) = message.param(1) else {
        return;
    };
    let Some(target) = server.find_nick(nick) else {
        return;
    };
    let folded = server.casemap().fold(channel_name);
    let Some(entry) = server.channels.get(&folded) else {
        return;
    };
    let ttl = std::time::Duration::from_secs(server.cfg().server.invite_expiry_secs);
    entry
        .value()
        .write()
        .invite(target.id, prefix_nick(message), ttl);
    drop(entry);
    // A burst replays an invitation as channel state, so the invitee must not
    // be told again; only a live invitation, which carries a user prefix, is
    // delivered. Both forms are forwarded so the next hop records it too.
    if message
        .prefix
        .as_deref()
        .is_some_and(|prefix| prefix.contains('!'))
    {
        target.send(message, server.max_line());
    }
    server.propagate_link_from(message, Some(origin));
}

/// `KICK` from a peer: remove the target from the channel everywhere.
///
/// A refusal for a remote join arrives through here, but so does an ordinary
/// kick issued by a remote operator, including one aimed at a local client.
fn inbound_kick(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let Some(channel_name) = message.param(0) else {
        return;
    };
    let Some(nick) = message.param(1) else {
        return;
    };
    let reason = message.param(2).unwrap_or("Kicked").to_owned();
    let folded = server.casemap().fold(channel_name);
    let Some(entry) = server.channels.get(&folded) else {
        return;
    };
    let Some(target) = server.find_nick(nick) else {
        return;
    };
    let (recipients, name) = {
        let mut channel = entry.value().write();
        if channel.members.remove(&target.id).is_none() {
            return;
        }
        let recipients = channel
            .members
            .keys()
            .filter_map(|id| server.find_client(*id))
            .collect::<Vec<_>>();
        let name = channel.name.clone();
        (recipients, name)
    };
    drop(entry);
    target.session_mut(|session| session.channels.remove(&folded));

    let mut kick = Message::command("KICK");
    kick.prefix = message.prefix.clone().or_else(|| Some(server.name()));
    kick.params = vec![name, target.nick_or_star(), reason];
    // The target is no longer a member, so it is added to the audience
    // explicitly; otherwise a kicked client would never be told.
    let mut audience = recipients;
    if target.is_local() {
        audience.push(Arc::clone(&target));
    }
    server.broadcast(audience, &kick, None);
    server.propagate_link_from(message, Some(origin));
}

fn inbound_part(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let nick = prefix_nick(message);
    let Some(user) = server.find_nick(&nick) else {
        return;
    };
    let Some(channels) = message.param(0) else {
        return;
    };
    let account = user.session(|session| session.account.clone());
    for name in channels.split(',') {
        let folded = server.casemap().fold(name);
        let Some(channel) = server.find_channel(name) else {
            continue;
        };
        let (recipients, channel_name) = {
            let mut guard = channel.write();
            guard.remove(user.id);
            (
                guard
                    .members
                    .keys()
                    .filter_map(|id| server.find_client(*id))
                    .collect::<Vec<_>>(),
                guard.name.clone(),
            )
        };
        user.session_mut(|session| session.channels.remove(&folded));

        let mut part = Message::command("PART");
        part.prefix = Some(user.mask());
        part.params.push(channel_name);
        if let Some(reason) = message.param(1) {
            part.params.push(reason.to_owned());
        }
        match account.as_deref() {
            Some(account) => server.broadcast_with_account(recipients, &part, None, account),
            None => server.broadcast(recipients, &part, None),
        }
        server.propagate_link_from(&part, Some(origin));

        let empty = server
            .channels
            .get(&folded)
            .is_some_and(|candidate| candidate.read().is_empty());
        if empty {
            server
                .channels
                .remove_if(&folded, |_, candidate| candidate.read().is_empty());
        }
    }
}

fn inbound_quit(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let nick = prefix_nick(message);
    let Some(shadow) = server.find_nick(&nick) else {
        return;
    };
    if shadow.is_local() {
        return;
    }
    let reason = message.param(0).unwrap_or("Remote quit");
    // Peers further along the tree need the quit too; without this only the
    // first hop would forget the user.
    server.propagate_link_from(message, Some(origin));
    server.disconnect(&shadow, reason);
}

fn inbound_text(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let nick = prefix_nick(message);
    let Some(source) = server.find_nick(&nick) else {
        return;
    };
    let Some(target) = message.param(0) else {
        return;
    };
    let Some(text) = message.param(1) else {
        return;
    };
    let mut relay = Message::command(message.command.clone());
    relay.prefix = Some(source.mask());
    relay.params.push(target.to_owned());
    relay.params.push(text.to_owned());
    // The subscription is per delivery: a local recipient only sees `@account`
    // or client tags when it asked for the matching capability.
    let account = source.session(|session| session.account.clone());
    let config = server.cfg();
    let tags = message.client_tags(&config.server.client_tag_allowlist);

    if is_channel_name(target) {
        let Some(channel) = server.find_channel(target) else {
            return;
        };
        {
            let guard = channel.read();
            server.broadcast_channel_text(
                &guard,
                &relay,
                Some(source.id),
                account.as_deref(),
                &tags,
            );
        }
        // Channel traffic must cross the whole tree, not just the first hop.
        // Only tags this server accepts are forwarded, so an unconfigured peer
        // cannot push arbitrary vendor tags through the tree.
        let mut forward = relay.clone();
        forward.tags.extend(tags.iter().cloned());
        server.propagate_link_from(&forward, Some(origin));
    } else if let Some(recipient) = server.find_nick(target) {
        if recipient.is_local() {
            recipient.send_text(&relay, account.as_deref(), &tags, server.max_line());
        } else if let Some(home) = recipient.remote_server.clone() {
            server.route_message(&home, &relay, Some(origin));
        }
    }
}

fn inbound_topic(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let prefix = message.prefix.clone().unwrap_or_default();
    let actor = server.find_nick(&prefix_nick(message));
    // Bursts carry server-prefixed topics; anything else must come from a user
    // the network already knows.
    if actor.is_none() && !peer_prefix_matches(server, origin, &prefix) {
        return;
    }
    // The next hop only accepts a server prefix naming its direct peer, so a
    // burst change relayed from further away is re-signed by this server.
    let actor_mask = match &actor {
        Some(user) => user.mask(),
        None => server.name(),
    };
    let setter = actor
        .as_ref()
        .map(|user| user.nick_or_star())
        .unwrap_or_else(|| prefix.clone());
    let Some(name) = message.param(0) else {
        return;
    };
    let Some(text) = message.param(1) else {
        return;
    };
    let Some(channel) = server.find_channel(name) else {
        return;
    };
    if burst_lost(server, origin, name) {
        return;
    }
    let (recipients, channel_name) = {
        let mut guard = channel.write();
        guard.topic = if text.is_empty() {
            None
        } else {
            Some(text.to_owned())
        };
        guard.topic_setter = Some(setter);
        guard.topic_time = now_unix();
        (
            guard
                .members
                .keys()
                .filter_map(|id| server.find_client(*id))
                .collect::<Vec<_>>(),
            guard.name.clone(),
        )
    };
    let mut topic = Message::command("TOPIC");
    topic.prefix = Some(actor_mask);
    topic.params.push(channel_name);
    topic.params.push(text.to_owned());
    server.broadcast(recipients, &topic, None);
    server.propagate_link_from(&topic, Some(origin));
}

/// `ACCOUNT` from a peer: the subject's SASL account was set or cleared.
///
/// Only the server that owns the user may change its account; anything else is
/// dropped rather than letting a peer speak for another server's users. The
/// new value is forwarded on so every server converges in one pass.
fn inbound_account(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let Some(prefix) = message.prefix.as_deref() else {
        return;
    };
    let nick = prefix
        .split_once('!')
        .map_or(prefix, |(nick, _)| nick)
        .to_owned();
    let Some(shadow) = server.find_nick(&nick) else {
        debug!(%nick, "account change for an unknown user ignored");
        return;
    };
    if shadow.is_local() {
        debug!(%nick, "account change for a local user ignored");
        return;
    }
    let home = shadow.remote_server.clone().unwrap_or_default();
    if !server.route(&home).is_some_and(|info| info.link == origin) {
        debug!(%nick, %home, "account change did not come from the owning server");
        return;
    }
    let account = message
        .param(0)
        .filter(|value| !value.is_empty() && *value != "*");
    shadow.session_mut(|session| session.account = account.map(str::to_owned));
    debug!(
        %nick,
        account = account.unwrap_or("*"),
        "account updated from link"
    );
    server.propagate_link_from(message, Some(origin));
}

fn inbound_mode(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let prefix = message.prefix.clone().unwrap_or_default();
    let actor = server.find_nick(&prefix_nick(message));
    // Bursts carry server-prefixed mode changes; anything else must come from
    // a user the network already knows.
    if actor.is_none() && !peer_prefix_matches(server, origin, &prefix) {
        return;
    }
    // The next hop only accepts a server prefix naming its direct peer, so a
    // burst change relayed from further away is re-signed by this server.
    let actor_mask = match &actor {
        Some(user) => user.mask(),
        None => server.name(),
    };
    let setter = actor
        .as_ref()
        .map(|user| user.nick_or_star())
        .unwrap_or_else(|| prefix.clone());
    let Some(name) = message.param(0) else {
        return;
    };
    let Some(spec) = message.param(1) else {
        return;
    };
    let Some(channel) = server.find_channel(name) else {
        return;
    };
    let mut rendered = String::new();
    let mut rendered_arguments: Vec<String> = Vec::new();
    let mut last: Option<bool> = None;
    let mut adding = true;
    let mut argument = 2usize;
    {
        let mut guard = channel.write();
        let channel_name = guard.name.clone();
        for character in spec.chars() {
            match character {
                '+' => adding = true,
                '-' => adding = false,
                'i' | 'm' | 'n' | 'p' | 's' | 't' | 'R' => {
                    let flag = match character {
                        'i' => &mut guard.invite_only,
                        'm' => &mut guard.moderated,
                        'n' => &mut guard.no_external,
                        'p' => &mut guard.private,
                        's' => &mut guard.secret,
                        'R' => &mut guard.account_only,
                        _ => &mut guard.topic_lock,
                    };
                    if *flag != adding {
                        *flag = adding;
                        push_mode(&mut rendered, &mut last, adding, character);
                    }
                }
                'b' | 'e' => {
                    let Some(mask) = message.param(argument) else {
                        continue;
                    };
                    argument += 1;
                    let list = if character == 'e' {
                        &mut guard.exceptions
                    } else {
                        &mut guard.bans
                    };
                    if adding {
                        if list.len() < 100 && !list.iter().any(|entry| entry.mask == *mask) {
                            list.push(BanEntry {
                                mask: mask.to_owned(),
                                set_by: setter.clone(),
                                set_at: now_unix(),
                            });
                        }
                    } else {
                        list.retain(|entry| entry.mask != *mask);
                    }
                    push_mode(&mut rendered, &mut last, adding, character);
                    rendered_arguments.push(mask.to_owned());
                }
                _ => {}
            }
        }
        if rendered.is_empty() {
            return;
        }
        let recipients = guard
            .members
            .keys()
            .filter_map(|id| server.find_client(*id))
            .collect::<Vec<_>>();
        let mut mode = Message::command("MODE");
        mode.prefix = Some(actor_mask);
        mode.params.push(channel_name);
        mode.params.push(rendered);
        mode.params.extend(rendered_arguments);
        server.broadcast(recipients, &mode, None);
        server.propagate_link_from(&mode, Some(origin));
    }
}

fn push_mode(out: &mut String, last: &mut Option<bool>, adding: bool, mode: char) {
    if *last != Some(adding) {
        out.push(if adding { '+' } else { '-' });
        *last = Some(adding);
    }
    out.push(mode);
}

/// True when `prefix` is the server name of the link the message came from.
fn peer_prefix_matches(server: &Arc<Server>, origin: ClientId, prefix: &str) -> bool {
    server
        .links
        .get(&origin)
        .map(|peer| peer.eq_ignore_ascii_case(prefix))
        .unwrap_or(false)
}

/// Send this server's complete state to a freshly linked peer.
///
/// The burst is `SERVER` for every server behind another link, `NICK` for every
/// user this server knows, one `SJOIN` per channel followed by its topic and its
/// ban and exception lists, and finally `EOB`. Applying a burst is idempotent, so a
/// peer that already knows part of the state simply refreshes it.
pub fn send_burst(server: &Arc<Server>, link: &Arc<ClientHandle>) {
    let Some(peer) = server
        .links
        .get(&link.id)
        .map(|entry| entry.value().clone())
    else {
        return;
    };
    let name = server.name();
    let max_line = server.max_line();
    let mut messages = 0usize;

    for route in server.routes() {
        if route.link == link.id || route.name.eq_ignore_ascii_case(&peer) {
            continue;
        }
        let mut message = Message::command("SERVER");
        message.prefix = Some(name.clone());
        message.params = vec![
            route.name,
            route.hops.to_string(),
            route.sid,
            route.description,
        ];
        link.send(&message, max_line);
        messages += 1;
    }

    // Every user this server knows, not just its own. A server that reconnects
    // to a hub in the middle of a chain would otherwise never hear about users
    // two hops away: their home server is not the one it linked to, so only the
    // hub can hand them over. Refreshing a user the peer already holds carries
    // the same timestamp and home server, which the receiver treats as a no-op.
    for entry in server.clients.iter() {
        let client = entry.value();
        if !client.is_registered() {
            continue;
        }
        let Some(nick) = client.nick() else {
            continue;
        };
        let home = client.remote_server.clone().unwrap_or_else(|| name.clone());
        let hops = server.route(&home).map_or(1, |route| route.hops);
        let (user, host, realname, modes, ts) = client.session(|session| {
            (
                session.user.clone().unwrap_or_default(),
                session.host.clone(),
                session.realname.clone().unwrap_or_default(),
                session.modes.to_flags(),
                session.ts,
            )
        });
        let introduction = Introduction {
            nick,
            hops,
            ts,
            user,
            host,
            server: home,
            modes,
            realname,
        };
        link.send(
            &introduction_message(client.mask(), &introduction),
            max_line,
        );
        messages += 1;
        if let Some(message) = account_message(client) {
            link.send(&message, max_line);
            messages += 1;
        }
    }

    for entry in server.channels.iter() {
        let channel = entry.value().read();
        if channel.is_empty() {
            continue;
        }
        let mut members = Vec::with_capacity(channel.members.len());
        for (id, mode) in &channel.members {
            let Some(client) = server.find_client(*id) else {
                continue;
            };
            let nick = client.nick_or_star();
            let mut token = String::with_capacity(nick.len() + 1);
            if mode.op {
                token.push('@');
            } else if mode.voice {
                token.push('+');
            }
            token.push_str(&nick);
            members.push(token);
        }
        if members.is_empty() {
            continue;
        }
        let (flags, arguments) = channel.burst_modes();
        let mut sjoin = Message::command("SJOIN");
        sjoin.prefix = Some(name.clone());
        sjoin.params.push(channel.name.clone());
        sjoin.params.push(channel.created.to_string());
        sjoin.params.push(flags);
        sjoin.params.extend(arguments);
        sjoin.params.push(members.join(" "));
        link.send(&sjoin, max_line);
        messages += 1;

        if let Some(topic) = &channel.topic {
            let mut message = Message::command("TOPIC");
            message.prefix = Some(name.clone());
            message.params.push(channel.name.clone());
            message.params.push(topic.clone());
            link.send(&message, max_line);
            messages += 1;
        }
        for (flag, entries) in [('b', &channel.bans), ('e', &channel.exceptions)] {
            for entry in entries {
                let mut message = Message::command("MODE");
                message.prefix = Some(name.clone());
                message.params.push(channel.name.clone());
                message.params.push(format!("+{flag}"));
                message.params.push(entry.mask.clone());
                link.send(&message, max_line);
                messages += 1;
            }
        }
        // Invitations are per-server state keyed by handle id, so they travel
        // by nick once per invitee. Without this a peer would refuse a user the
        // network already invited, which is exactly what a split produces.
        let mut invitees: Vec<String> = channel
            .invites
            .keys()
            .filter(|id| channel.invited(**id))
            .filter_map(|id| server.find_client(*id))
            .map(|client| client.nick_or_star())
            .collect();
        invitees.sort_unstable();
        for nick in invitees {
            let mut message = Message::command("INVITE");
            message.prefix = Some(name.clone());
            message.params.push(nick);
            message.params.push(channel.name.clone());
            link.send(&message, max_line);
            messages += 1;
        }
    }

    let mut end = Message::command("EOB");
    end.prefix = Some(name);
    link.send(&end, max_line);
    info!(peer = %peer, messages, "netburst sent");
}

/// Apply a `SJOIN` from a peer's burst.
///
/// Modes merge per mode rather than by channel ownership: booleans are unioned,
/// `+k`/`+l` keep the older channel's argument, and lists are united. The
/// channel `TS` still decides who owns the topic, and membership is only ever
/// added.
fn inbound_sjoin(server: &Arc<Server>, origin: ClientId, message: &Message) {
    let Some(name) = message.param(0).filter(|name| is_channel_name(name)) else {
        return;
    };
    let ts = message
        .param(1)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(now_unix);
    let modes = message.param(2).unwrap_or("+").to_owned();
    let member_list = message.params.last().cloned().unwrap_or_default();
    let arguments: Vec<String> = message
        .params
        .iter()
        .skip(3)
        .take(message.params.len().saturating_sub(4))
        .cloned()
        .collect();

    let existed = server.find_channel(name).is_some();
    let folded = server.casemap().fold(name);
    let entry = server
        .channels
        .entry(folded.clone())
        .or_insert_with(|| Arc::new(RwLock::new(Channel::new(name))));
    let channel = Arc::clone(entry.value());
    drop(entry);

    let mut joined: Vec<Arc<ClientHandle>> = Vec::new();
    let mut retransmitted: Option<String> = None;
    let recipients;
    let channel_name;
    let remote_won;
    {
        let mut guard = channel.write();
        let local_ts = guard.created;
        // The channel timestamp no longer decides modes, only the topic: the
        // older copy owns it, as does the copy that introduces the channel.
        remote_won = !existed || ts < local_ts;
        if remote_won {
            guard.created = ts;
        }
        let changed = merge_burst_modes(&mut guard, local_ts, ts, &modes, &arguments);
        if changed || !existed {
            let (mut flags, arguments) = guard.burst_modes();
            for argument in arguments {
                flags.push(' ');
                flags.push_str(&argument);
            }
            retransmitted = Some(flags);
        }
        for token in member_list.split(' ') {
            let Some((mode, nick)) = parse_member(token) else {
                continue;
            };
            let Some(client) = server.find_nick(nick) else {
                continue;
            };
            if guard.members.contains_key(&client.id) {
                continue;
            }
            guard.members.insert(client.id, mode);
            client.session_mut(|session| {
                session.channels.insert(folded.clone());
            });
            joined.push(client);
        }
        channel_name = guard.name.clone();
        recipients = guard
            .members
            .keys()
            .filter_map(|id| server.find_client(*id))
            .collect::<Vec<_>>();
    }

    // The burst's `TOPIC` line follows this `SJOIN`, so the verdict has to be
    // remembered until it arrives. List `MODE` lines merge as they come, so
    // they need no verdict.
    server
        .burst_remote_won
        .insert((origin, folded.clone()), remote_won);

    for member in &joined {
        let mut join = Message::command("JOIN");
        join.prefix = Some(member.mask());
        join.params.push(channel_name.clone());
        server.broadcast(recipients.iter().cloned(), &join, None);
    }
    if let Some(rendered) = retransmitted {
        let mut mode = Message::command("MODE");
        mode.prefix = Some(server.name());
        mode.params.push(channel_name);
        mode.params.push(rendered);
        server.broadcast(recipients, &mode, None);
    }
    server.propagate_link_from(message, Some(origin));
}

/// True when `origin`'s burst copy of `name` does not own the topic.
///
/// Only the burst `TOPIC` is affected: modes and lists merge entry by entry,
/// and live changes carry a user prefix and are evaluated on their own merits.
fn burst_lost(server: &Arc<Server>, origin: ClientId, name: &str) -> bool {
    let folded = server.casemap().fold(name);
    server
        .burst_remote_won
        .get(&(origin, folded))
        .is_some_and(|won| !*won)
}

/// Merge a burst's channel modes into the local copy, mode by mode.
///
/// Boolean modes are additive: a mode set on either side of a split survives,
/// which is the only rule that needs no per-mode timestamp. `k` and `l` carry
/// one argument each, so the older channel keeps its argument and an equal
/// timestamp falls back to a total order on the values, giving both servers the
/// same verdict without a round trip.
///
/// # Arguments
///
/// * `channel` - Local channel state, updated in place
/// * `local_ts` - Channel timestamp before this burst was applied
/// * `remote_ts` - Timestamp announced by the burst
/// * `modes` - Mode flags from the burst, e.g. `+mntkl`
/// * `arguments` - Arguments for `k` and `l`, in flag order
///
/// # Returns
///
/// `true` when the local state changed, so an agreeing burst stays silent.
fn merge_burst_modes(
    channel: &mut Channel,
    local_ts: u64,
    remote_ts: u64,
    modes: &str,
    arguments: &[String],
) -> bool {
    let mut adding = true;
    let mut argument = 0usize;
    let mut changed = false;
    for character in modes.chars() {
        match character {
            '+' => adding = true,
            '-' => adding = false,
            'i' | 'm' | 'n' | 'p' | 's' | 't' | 'R' => {
                if !adding {
                    continue;
                }
                let flag = match character {
                    'i' => &mut channel.invite_only,
                    'm' => &mut channel.moderated,
                    'n' => &mut channel.no_external,
                    'p' => &mut channel.private,
                    's' => &mut channel.secret,
                    'R' => &mut channel.account_only,
                    _ => &mut channel.topic_lock,
                };
                if !*flag {
                    *flag = true;
                    changed = true;
                }
            }
            'k' => {
                let Some(value) = arguments.get(argument) else {
                    continue;
                };
                argument += 1;
                if !adding {
                    continue;
                }
                let take = match channel.key.as_deref() {
                    None => true,
                    Some(local) if local == value => false,
                    Some(local) => {
                        remote_ts < local_ts || (remote_ts == local_ts && value.as_str() < local)
                    }
                };
                if take {
                    channel.key = Some(value.clone());
                    changed = true;
                }
            }
            'l' => {
                let Some(value) = arguments.get(argument) else {
                    continue;
                };
                argument += 1;
                if !adding {
                    continue;
                }
                let Ok(remote) = value.parse::<usize>() else {
                    continue;
                };
                let take = match channel.limit {
                    None => true,
                    Some(local) => {
                        local != remote
                            && (remote_ts < local_ts || (remote_ts == local_ts && remote < local))
                    }
                };
                if take {
                    channel.limit = Some(remote);
                    changed = true;
                }
            }
            _ => {}
        }
    }
    changed
}

/// Split an `SJOIN` member token such as `@nick` or `+nick`.
fn parse_member(token: &str) -> Option<(MemberMode, &str)> {
    if token.is_empty() {
        return None;
    }
    let (op, rest) = match token.strip_prefix('@') {
        Some(rest) => (true, rest),
        None => (false, token),
    };
    let (voice, nick) = match rest.strip_prefix('+') {
        Some(rest) => (true, rest),
        None => (false, rest),
    };
    (!nick.is_empty()).then_some((MemberMode { op, voice }, nick))
}

/// Prune the routes and users that a lost link took with it.
///
/// Called from [`Server::disconnect`] for every inbound link, which means a
/// closed socket, a `SQUIT` about a direct peer and a shutdown all converge on
/// the same cleanup: the subtree is unreachable, its users are gone, and the
/// remaining peers are told which servers disappeared.
pub fn forget_link(server: &Arc<Server>, link: ClientId, reason: &str) {
    server
        .burst_remote_won
        .retain(|(owner, _), _| *owner != link);
    let removed = server.remove_routes_via(link);
    if removed.is_empty() {
        return;
    }
    let names: HashSet<String> = removed
        .iter()
        .map(|info| server.casemap().fold(&info.name))
        .collect();
    prune_users(server, &names, reason);
    for info in &removed {
        let mut squit = Message::command("SQUIT");
        squit.prefix = Some(server.name());
        squit.params.push(info.name.clone());
        squit.params.push(reason.to_owned());
        server.propagate_link(&squit);
    }
    let peers: Vec<&str> = removed.iter().map(|info| info.name.as_str()).collect();
    warn!(link, servers = ?peers, reason, "link lost, subtree pruned");
}

fn prune_users(server: &Arc<Server>, names: &HashSet<String>, reason: &str) {
    let casemap = server.casemap();
    let users: Vec<Arc<ClientHandle>> = server
        .clients
        .iter()
        .filter(|entry| {
            entry
                .value()
                .remote_server
                .as_deref()
                .is_some_and(|home| names.contains(&casemap.fold(home)))
        })
        .map(|entry| Arc::clone(entry.value()))
        .collect();
    for user in users {
        server.disconnect(&user, reason);
    }
}

/// Report whether a numeric reply code belongs to the link layer's acceptable
/// set. Kept small so the link module shares the protocol vocabulary.
pub fn is_link_error(code: Numeric) -> bool {
    code.is_error()
}
