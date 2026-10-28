//! Messaging and informational commands.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::commands::{is_channel_name, Access, Cmd, CmdFuture, CommandSpec};
use crate::error::CommandError;
use crate::protocol::{Message, Numeric};
use crate::server::{CapSet, Channel, ClientHandle, HistoryRange, MultilineBatch};
use crate::util::{iso8601, now_unix, wildcard_match};

/// `PRIVMSG` sends a message to a user or channel.
pub const PRIVMSG: CommandSpec = CommandSpec {
    name: "PRIVMSG",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_privmsg,
};

/// `NOTICE` is `PRIVMSG` without automatic error replies.
pub const NOTICE: CommandSpec = CommandSpec {
    name: "NOTICE",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_notice,
};

/// `AWAY` sets or clears the away state.
pub const AWAY: CommandSpec = CommandSpec {
    name: "AWAY",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_away,
};

/// `WHO` lists users.
pub const WHO: CommandSpec = CommandSpec {
    name: "WHO",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_who,
};

/// `WHOIS` describes a user.
pub const WHOIS: CommandSpec = CommandSpec {
    name: "WHOIS",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_whois,
};

/// `WHOWAS` describes a departed user.
pub const WHOWAS: CommandSpec = CommandSpec {
    name: "WHOWAS",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_whowas,
};

/// `ISON` tests whether nicknames are online.
pub const ISON: CommandSpec = CommandSpec {
    name: "ISON",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_ison,
};

/// `USERHOST` returns short user records.
pub const USERHOST: CommandSpec = CommandSpec {
    name: "USERHOST",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_userhost,
};

/// `BATCH` frames a group of messages (`draft/multiline` on input).
pub const BATCH: CommandSpec = CommandSpec {
    name: "BATCH",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_batch,
};

/// `CHATHISTORY` replays recent channel messages (`draft/chathistory`).
pub const CHATHISTORY: CommandSpec = CommandSpec {
    name: "CHATHISTORY",
    min_params: 2,
    access: Access::Registered,
    handler: cmd_chathistory,
};

/// Tag marking a message assembled from a multiline batch.
const MULTILINE_CONCAT: &str = "draft/multiline-concat";
/// Lines one multiline batch may hold.
const MULTILINE_LINES: usize = 32;
/// Bytes one multiline batch may hold, including the joining newlines.
const MULTILINE_BYTES: usize = 4096;
/// Refs for server-generated batches.
static BATCH_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// `TAGMSG` delivers tags with no body.
///
/// Typing indicators and reactions travel this way, so the message is only
/// meaningful to a recipient that negotiated `message-tags`; the delivery path
/// drops it for everybody else without building a second serialisation.
pub const TAGMSG: CommandSpec = CommandSpec {
    name: "TAGMSG",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_tagmsg,
};

/// `MONITOR` maintains a server-side presence list.
pub const MONITOR: CommandSpec = CommandSpec {
    name: "MONITOR",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_monitor,
};

/// Nicknames one session may watch. Bounded so the list cannot be used as a
/// memory amplifier or a per-event scan of the whole server.
const MONITOR_LIMIT: usize = 100;

fn cmd_tagmsg(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let target = cx.param(0).unwrap_or_default().to_owned();
        let config = cx.server.cfg();
        let tags = cx.msg.client_tags(&config.server.client_tag_allowlist);
        if tags.is_empty() {
            // Without a tag there is nothing to send; the spec makes the body
            // mandatory, and this server never invents one.
            return Ok(());
        }
        let account = cx.client.session(|session| session.account.clone());
        let mut message = Message::command("TAGMSG");
        message.prefix = Some(cx.mask());
        message.params.push(target.clone());

        if is_channel_name(&target) {
            let Some(channel) = cx.channel(&target) else {
                return Err(cx.fail(
                    Numeric::ERR_NOSUCHCHANNEL,
                    format!("{target} :No such channel"),
                ));
            };
            let (recipients, channel_name) = {
                let guard = channel.read();
                let (nick, user, host) = cx.client.session(|session| {
                    (
                        session.nick.clone().unwrap_or_default(),
                        session.user.clone().unwrap_or_default(),
                        session.host.clone(),
                    )
                });
                let member = guard.member(cx.client.id);
                if member.is_none() && guard.no_external {
                    return Err(cx.fail(
                        Numeric::ERR_CANNOTSENDTOCHAN,
                        format!("{target} :Cannot send to channel (no external messages, +n)"),
                    ));
                }
                if guard.account_only && account.is_none() {
                    return Err(cx.fail(
                        Numeric::ERR_CANNOTSENDTOCHAN,
                        format!("{target} :Cannot send to channel (+R)"),
                    ));
                }
                if guard.moderated && member.is_some_and(|mode| !mode.can_speak()) {
                    return Err(cx.fail(
                        Numeric::ERR_CANNOTSENDTOCHAN,
                        format!("{target} :Cannot send to channel (+m)"),
                    ));
                }
                if guard.is_banned(&nick, &user, &host, account.as_deref()) {
                    return Err(cx.fail(
                        Numeric::ERR_CANNOTSENDTOCHAN,
                        format!("{target} :Cannot send to channel (you are banned)"),
                    ));
                }
                (
                    guard
                        .members
                        .keys()
                        .filter_map(|id| cx.server.find_client(*id))
                        .collect::<Vec<_>>(),
                    guard.name.clone(),
                )
            };
            message.params[0] = channel_name;
            cx.server.broadcast_text(
                recipients,
                &message,
                Some(cx.client.id),
                account.as_deref(),
                &tags,
            );
            if cx.client.is_local() {
                let mut relay = message.clone();
                relay.tags.extend(tags.iter().cloned());
                cx.server.propagate_link(&relay);
            }
            return Ok(());
        }

        let Some(recipient) = cx.find(&target) else {
            return Err(cx.fail(
                Numeric::ERR_NOSUCHNICK,
                format!("{target} :No such nick/channel"),
            ));
        };
        message.params[0] = recipient.nick_or_star();
        if recipient.is_local() {
            recipient.send_text(&message, account.as_deref(), &tags, cx.max_line());
        } else if let Some(home) = recipient.remote_server.clone() {
            let mut relay = message.clone();
            relay.tags.extend(tags.iter().cloned());
            cx.server.route_message(&home, &relay, None);
        }
        Ok(())
    })
}

fn cmd_monitor(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let argument = cx.param(0).unwrap_or_default().to_owned();
        match argument.as_str() {
            "C" => {
                cx.client.session_mut(|session| session.monitor.clear());
                cx.reply(Numeric(733), ":End of MONITOR list");
            }
            "L" => {
                let names = cx.client.session(|session| {
                    let mut names = session.monitor.iter().cloned().collect::<Vec<_>>();
                    names.sort_unstable();
                    names
                });
                for chunk in names.chunks(50) {
                    cx.reply(Numeric(732), format!(":{}", chunk.join(",")));
                }
                cx.reply(Numeric(733), ":End of MONITOR list");
            }
            "S" => {
                let names = cx
                    .client
                    .session(|session| session.monitor.iter().cloned().collect::<Vec<_>>());
                let mut online = Vec::new();
                let mut offline = Vec::new();
                for folded in names {
                    match cx.server.find_nick(&folded) {
                        Some(client) => online.push(client.mask()),
                        None => offline.push(folded),
                    }
                }
                if !online.is_empty() {
                    cx.reply(Numeric(730), format!(":{}", online.join(",")));
                }
                if !offline.is_empty() {
                    cx.reply(Numeric(731), format!(":{}", offline.join(",")));
                }
            }
            _ => {
                let adding = argument.starts_with('+');
                if !adding && !argument.starts_with('-') {
                    return Err(
                        cx.fail(Numeric::ERR_NEEDMOREPARAMS, "MONITOR :Use +, -, C, L or S")
                    );
                }
                let list = &argument[1..];
                let mut online = Vec::new();
                let mut offline = Vec::new();
                for nick in list.split(',').filter(|nick| !nick.is_empty()) {
                    let folded = cx.casemap().fold(nick);
                    if adding {
                        let inserted = cx.client.session_mut(|session| {
                            if session.monitor.len() >= MONITOR_LIMIT
                                && !session.monitor.contains(&folded)
                            {
                                return false;
                            }
                            session.monitor.insert(folded.clone());
                            true
                        });
                        if !inserted {
                            return Err(
                                cx.fail(Numeric(734), format!("{nick} :Monitor list is full"))
                            );
                        }
                        match cx.server.find_nick(nick) {
                            Some(client) => online.push(client.mask()),
                            None => offline.push(folded),
                        }
                    } else {
                        cx.client
                            .session_mut(|session| session.monitor.remove(&folded));
                    }
                }
                if !online.is_empty() {
                    cx.reply(Numeric(730), format!(":{}", online.join(",")));
                }
                if !offline.is_empty() {
                    cx.reply(Numeric(731), format!(":{}", offline.join(",")));
                }
            }
        }
        Ok(())
    })
}

fn cmd_batch(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let argument = cx.param(0).unwrap_or_default().to_owned();
        if let Some(reference) = argument.strip_prefix('+') {
            if cx.param(1).unwrap_or_default() != "draft/multiline" {
                return Err(cx.fail(Numeric(417), "BATCH :Unsupported batch type"));
            }
            if !cx.client.has_cap(CapSet::MULTILINE) {
                return Err(cx.fail(
                    Numeric::ERR_NOPRIVILEGES,
                    "BATCH :Negotiate draft/multiline first",
                ));
            }
            if reference.is_empty()
                || reference.len() > 32
                || !reference
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(cx.fail(Numeric(417), "BATCH :Bad reference"));
            }
            let target = cx.param(2).unwrap_or_default().to_owned();
            if target.is_empty() {
                return Err(cx.fail(Numeric::ERR_NEEDMOREPARAMS, "BATCH :Not enough parameters"));
            }
            let already_open = cx.client.session(|session| session.multiline.is_some());
            if already_open {
                return Err(cx.fail(Numeric(417), "BATCH :A batch is already open"));
            }
            cx.client.session_mut(|session| {
                session.multiline = Some(MultilineBatch {
                    reference: reference.to_owned(),
                    target,
                    lines: Vec::new(),
                    bytes: 0,
                });
            });
            return Ok(());
        }

        let Some(reference) = argument.strip_prefix('-') else {
            return Err(cx.fail(Numeric(417), "BATCH :Expected +reference or -reference"));
        };
        let batch = cx.client.session_mut(|session| {
            let matches = session
                .multiline
                .as_ref()
                .is_some_and(|batch| batch.reference == reference);
            if matches {
                session.multiline.take()
            } else {
                None
            }
        });
        let Some(batch) = batch else {
            return Ok(());
        };
        if batch.lines.is_empty() {
            return Ok(());
        }
        let text = batch.lines.join("\n");
        let mut message = Message::command("PRIVMSG");
        message.params.push(batch.target);
        message.params.push(text);
        let command = Cmd {
            server: Arc::clone(&cx.server),
            client: Arc::clone(&cx.client),
            msg: message,
        };
        deliver(
            &command,
            "PRIVMSG",
            &[(MULTILINE_CONCAT.to_owned(), String::new())],
        )
    })
}

fn cmd_chathistory(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        if !cx.client.has_cap(CapSet::CHATHISTORY) {
            return Err(cx.fail(
                Numeric::ERR_NOPRIVILEGES,
                "CHATHISTORY :Negotiate draft/chathistory first",
            ));
        }
        let subcommand = cx.param(0).unwrap_or_default().to_ascii_uppercase();
        let target = cx.param(1).unwrap_or_default().to_owned();
        if !is_channel_name(&target) {
            return Err(cx.fail(
                Numeric::ERR_NOSUCHCHANNEL,
                format!("{target} :No such channel"),
            ));
        }
        let Some(channel) = cx.channel(&target) else {
            return Err(cx.fail(
                Numeric::ERR_NOSUCHCHANNEL,
                format!("{target} :No such channel"),
            ));
        };
        if !channel.read().contains(cx.client.id) {
            return Err(cx.fail(
                Numeric::ERR_NOTONCHANNEL,
                format!("{target} :You're not on that channel"),
            ));
        }
        let limit = cx
            .param(if subcommand == "BETWEEN" { 4 } else { 3 })
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(50)
            .clamp(1, 100);
        let timestamp = |index: usize| {
            parse_timestamp(cx.param(index).unwrap_or_default())
                .ok_or_else(|| cx.fail(Numeric(417), "CHATHISTORY :Bad timestamp"))
        };
        let range = match subcommand.as_str() {
            "LATEST" => match parse_timestamp(cx.param(2).unwrap_or("*")) {
                Some(at) => HistoryRange::Before(at.saturating_add(1)),
                None => HistoryRange::Latest,
            },
            "BEFORE" => HistoryRange::Before(timestamp(2)?),
            "AFTER" => HistoryRange::After(timestamp(2)?),
            "AROUND" => HistoryRange::Around(timestamp(2)?),
            "BETWEEN" => HistoryRange::Between(timestamp(2)?, timestamp(3)?),
            other => {
                return Err(cx.fail(
                    Numeric::ERR_UNKNOWNCOMMAND,
                    format!("CHATHISTORY :Unknown subcommand {other}"),
                ));
            }
        };
        let channel_name = channel.read().name.clone();
        let entries = cx.server.history_in_range(&channel_name, range, limit);
        let reference = format!(
            "chathistory{}",
            BATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let server_name = cx.server.name();
        let max_line = cx.max_line();
        cx.client.send_raw(
            &format!(":{server_name} BATCH +{reference} draft/chathistory {channel_name}"),
            max_line,
        );
        for entry in entries {
            cx.client.send_raw(
                &format!(
                    "@time={} :{} PRIVMSG {} :{}",
                    iso8601(entry.at),
                    entry.prefix,
                    channel_name,
                    entry.text
                ),
                max_line,
            );
        }
        cx.client
            .send_raw(&format!(":{server_name} BATCH -{reference}"), max_line);
        Ok(())
    })
}

/// Parse a `CHATHISTORY` timestamp: RFC 3339, optionally prefixed with
/// `timestamp=`, or plain Unix seconds.
fn parse_timestamp(text: &str) -> Option<u64> {
    let text = text.strip_prefix("timestamp=").unwrap_or(text);
    if text.is_empty() || text == "*" {
        return None;
    }
    if let Ok(seconds) = text.parse::<u64>() {
        return Some(seconds);
    }
    time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|at| at.unix_timestamp().max(0) as u64)
}

fn cmd_privmsg(cx: Cmd) -> CmdFuture {
    Box::pin(async move { deliver(&cx, "PRIVMSG", &[]) })
}

fn cmd_notice(cx: Cmd) -> CmdFuture {
    Box::pin(async move { deliver(&cx, "NOTICE", &[]) })
}

fn deliver(cx: &Cmd, command: &str, extra: &[(String, String)]) -> Result<(), CommandError> {
    let targets = cx.param(0).unwrap_or_default().to_owned();
    let notice = command == "NOTICE";
    if targets.is_empty() {
        if notice {
            return Ok(());
        }
        return Err(cx.fail(Numeric::ERR_NORECIPIENT, ":No recipient given"));
    }
    let Some(text) = cx.param(1).map(str::to_owned) else {
        if notice {
            return Ok(());
        }
        return Err(cx.fail(Numeric::ERR_NOTEXTTOSEND, ":No text to send"));
    };
    if text.is_empty() {
        if notice {
            return Ok(());
        }
        return Err(cx.fail(Numeric::ERR_NOTEXTTOSEND, ":No text to send"));
    }
    // A shun silences a client without disconnecting it. The ban list is empty
    // on almost every server, so the check bails out before building masks.
    if cx.server.has_bans() {
        let (nick, user, host, account) = cx.client.session(|session| {
            (
                session.nick.clone().unwrap_or_default(),
                session.user.clone().unwrap_or_default(),
                session.host.clone(),
                session.account.clone(),
            )
        });
        // MARK: security: medium: SEC-BAN-003: a shun drops speech at the delivery point.
        if cx
            .server
            .matching_ban(
                &[crate::server::BanKind::Shun],
                &nick,
                &user,
                &host,
                &cx.client.peer.ip().to_string(),
                account.as_deref(),
            )
            .is_some()
        {
            return Ok(());
        }
    }
    // A line carrying a `batch` tag belongs to a client-opened batch, so it is
    // collected instead of delivered. The reference must match the open batch,
    // and the target was fixed when the batch opened, so a line cannot retarget
    // the message halfway through.
    if let Some(reference) = cx
        .msg
        .tags
        .iter()
        .find(|(key, _)| key == "batch")
        .map(|(_, value)| value.clone())
    {
        let outcome = cx.client.session_mut(|session| {
            let batch = session.multiline.as_mut()?;
            if batch.reference != reference {
                return None;
            }
            if batch.lines.len() >= MULTILINE_LINES || batch.bytes + text.len() > MULTILINE_BYTES {
                return Some(false);
            }
            batch.lines.push(text.clone());
            batch.bytes += text.len();
            Some(true)
        });
        match outcome {
            Some(true) => return Ok(()),
            Some(false) => {
                cx.client.session_mut(|session| session.multiline = None);
                return Err(cx.fail(Numeric(417), "Multiline batch is too large"));
            }
            None => {}
        }
    }
    let limit = cx.server.cfg().limits.max_targets.max(1);
    for target in targets.split(',').take(limit) {
        let result = if is_channel_name(target) {
            talk_channel(cx, target, &text, command, extra)
        } else {
            talk_user(cx, target, &text, command, extra)
        };
        if let Err(error) = result {
            if !notice {
                cx.reply(error.code, error.text);
            }
        }
    }
    Ok(())
}

fn talk_channel(
    cx: &Cmd,
    name: &str,
    text: &str,
    command: &str,
    extra: &[(String, String)],
) -> Result<(), CommandError> {
    let Some(channel) = cx.channel(name) else {
        return Err(cx.fail(
            Numeric::ERR_NOSUCHCHANNEL,
            format!("{name} :No such channel"),
        ));
    };
    let config = cx.server.cfg();
    let mut tags = cx.msg.client_tags(&config.server.client_tag_allowlist);
    tags.extend_from_slice(extra);
    let mut message = Message::command(command);
    message.prefix = Some(cx.mask());
    message.params.push(String::new());
    message.params.push(text.to_owned());

    let guard = channel.write();
    let channel_name = guard.name.clone();
    let account = cx.client.session(|session| session.account.clone());
    // MARK: security: high: SEC-SPEAK-001: speaking is gated by +R, +m, +n and bans.
    if guard.account_only && account.is_none() {
        return Err(cx.fail(
            Numeric::ERR_CANNOTSENDTOCHAN,
            format!("{channel_name} :Cannot send to channel (+R) - you need to be authenticated"),
        ));
    }
    match guard.member(cx.client.id) {
        Some(mode) => {
            if guard.moderated && !mode.can_speak() {
                return Err(cx.fail(
                    Numeric::ERR_CANNOTSENDTOCHAN,
                    format!("{channel_name} :Cannot send to channel (channel is moderated, +m)"),
                ));
            }
        }
        None => {
            if guard.no_external {
                return Err(cx.fail(
                    Numeric::ERR_CANNOTSENDTOCHAN,
                    format!("{channel_name} :Cannot send to channel (no external messages, +n)"),
                ));
            }
            let (nick, user, host) = cx.client.session(|session| {
                (
                    session.nick.clone().unwrap_or_default(),
                    session.user.clone().unwrap_or_default(),
                    session.host.clone(),
                )
            });
            if guard.is_banned(&nick, &user, &host, account.as_deref()) {
                return Err(cx.fail(
                    Numeric::ERR_CANNOTSENDTOCHAN,
                    format!("{channel_name} :Cannot send to channel (you are banned)"),
                ));
            }
        }
    }
    if let Some(slot) = message.params.first_mut() {
        *slot = channel_name.clone();
    }
    cx.server.remember_history(&channel_name, &cx.mask(), text);
    cx.server.broadcast_channel_text(
        &guard,
        &message,
        Some(cx.client.id),
        account.as_deref(),
        &tags,
    );
    drop(guard);

    if cx.client.has_cap(CapSet::ECHO_MESSAGE) {
        cx.client
            .send_text(&message, account.as_deref(), &tags, cx.max_line());
    }
    if cx.client.is_local() {
        // Links receive the tags too; each server re-applies the recipient
        // gating for its own clients.
        let mut relay = message.clone();
        relay.tags.extend(tags.iter().cloned());
        cx.server.propagate_link(&relay);
    }
    Ok(())
}

fn talk_user(
    cx: &Cmd,
    nick: &str,
    text: &str,
    command: &str,
    extra: &[(String, String)],
) -> Result<(), CommandError> {
    let Some(target) = cx.find(nick) else {
        return Err(cx.fail(
            Numeric::ERR_NOSUCHNICK,
            format!("{nick} :No such nick/channel"),
        ));
    };
    if command == "PRIVMSG" {
        if let Some(away) = target.session(|session| session.away.clone()) {
            if target.is_local() {
                cx.reply(
                    Numeric::RPL_AWAY,
                    format!("{} :{away}", target.nick_or_star()),
                );
            }
        }
    }
    let mut message = Message::command(command);
    message.prefix = Some(cx.mask());
    message.params.push(target.nick_or_star());
    message.params.push(text.to_owned());

    let account = cx.client.session(|session| session.account.clone());
    let config = cx.server.cfg();
    let mut tags = cx.msg.client_tags(&config.server.client_tag_allowlist);
    tags.extend_from_slice(extra);
    if target.is_local() {
        target.send_text(&message, account.as_deref(), &tags, cx.max_line());
    } else if let Some(home) = target.remote_server.clone() {
        // Follow the route to the recipient's server instead of flooding the
        // message to every link. The receiving server tags the delivery with
        // the account it holds for this user and re-applies tag gating.
        let mut relay = message.clone();
        relay.tags.extend(tags.iter().cloned());
        cx.server.route_message(&home, &relay, None);
    }
    if cx.client.has_cap(CapSet::ECHO_MESSAGE) {
        cx.client
            .send_text(&message, account.as_deref(), &tags, cx.max_line());
    }
    Ok(())
}

fn cmd_away(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let message = cx
            .param(0)
            .map(|text| text.chars().take(200).collect::<String>());
        let max_line = cx.max_line();
        match message {
            Some(text) if !text.is_empty() => {
                cx.client
                    .session_mut(|session| session.away = Some(text.clone()));
                cx.reply(Numeric::RPL_NOWAWAY, ":You have been marked as being away");
                notify_away(&cx, Some(text), max_line);
            }
            _ => {
                cx.client.session_mut(|session| session.away = None);
                cx.reply(
                    Numeric::RPL_UNAWAY,
                    ":You are no longer marked as being away",
                );
                notify_away(&cx, None, max_line);
            }
        }
        Ok(())
    })
}

fn notify_away(cx: &Cmd, message: Option<String>, max_line: usize) {
    let mut away = Message::command("AWAY");
    away.prefix = Some(cx.mask());
    if let Some(text) = message {
        away.params.push(text);
    }
    let mut seen: HashSet<u64> = HashSet::new();
    for folded in cx.client.channels() {
        let Some(channel) = cx.server.channels.get(&folded) else {
            continue;
        };
        for id in channel.read().members.keys() {
            if *id == cx.client.id || !seen.insert(*id) {
                continue;
            }
            if let Some(member) = cx.server.find_client(*id) {
                if member.has_cap(CapSet::AWAY_NOTIFY) {
                    member.send(&away, max_line);
                }
            }
        }
    }
}

fn cmd_who(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let mask = cx.param(0).unwrap_or("*").to_owned();
        let server_name = cx.server.name();

        if is_channel_name(&mask) {
            if let Some(channel) = cx.channel(&mask) {
                let guard = channel.read();
                let channel_name = guard.name.clone();
                let members = guard
                    .members
                    .iter()
                    .filter_map(|(id, mode)| {
                        cx.server.find_client(*id).map(|client| (*mode, client))
                    })
                    .collect::<Vec<_>>();
                drop(guard);
                for (mode, client) in members {
                    let flags = who_flags(Some(mode), &client);
                    send_who_reply(&cx, &channel_name, &client, &flags, &server_name);
                }
            }
        } else {
            for entry in cx.server.clients.iter() {
                let client = Arc::clone(entry.value());
                let nick = client.nick_or_star();
                if mask != "*" && !wildcard_match(&mask, &nick) {
                    continue;
                }
                if !client.is_visible_to(&cx.client) && client.id != cx.client.id {
                    continue;
                }
                let flags = who_flags(None, &client);
                send_who_reply(&cx, "*", &client, &flags, &server_name);
            }
        }
        cx.reply(Numeric::RPL_ENDOFWHO, format!("{mask} :End of /WHO list."));
        Ok(())
    })
}

fn who_flags(mode: Option<crate::server::channel::MemberMode>, client: &ClientHandle) -> String {
    let away = client.session(|session| session.away.is_some());
    let oper = client.session(|session| session.modes.oper);
    let mut flags = String::with_capacity(4);
    flags.push(if away { 'G' } else { 'H' });
    if oper {
        flags.push('*');
    }
    if let Some(mode) = mode {
        flags.push_str(&mode.prefixes(false));
    }
    flags
}

fn send_who_reply(cx: &Cmd, channel: &str, client: &ClientHandle, flags: &str, server: &str) {
    let (user, host, realname) = client.session(|session| {
        (
            session.user.clone().unwrap_or_default(),
            session.host.clone(),
            session.realname.clone().unwrap_or_default(),
        )
    });
    cx.reply(
        Numeric::RPL_WHOREPLY,
        format!(
            "{channel} {user} {host} {server} {} {flags} :0 {realname}",
            client.nick_or_star()
        ),
    );
}

fn cmd_whois(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let target_nick = cx
            .param(cx.msg.params.len().saturating_sub(1))
            .unwrap_or_default()
            .to_owned();
        let Some(target) = cx.find(&target_nick) else {
            cx.reply(
                Numeric::ERR_NOSUCHNICK,
                format!("{target_nick} :No such nick/channel"),
            );
            cx.reply(
                Numeric::RPL_ENDOFWHOIS,
                format!("{target_nick} :End of /WHOIS list."),
            );
            return Ok(());
        };
        let nick = target.nick_or_star();
        let server_name = cx.server.name();
        let (user, host, realname, signon, away, oper, account) = target.session(|session| {
            (
                session.user.clone().unwrap_or_default(),
                session.host.clone(),
                session.realname.clone().unwrap_or_default(),
                session.signon,
                session.away.clone(),
                session.modes.oper,
                session.account.clone(),
            )
        });
        cx.reply(
            Numeric::RPL_WHOISUSER,
            format!("{nick} {user} {host} * :{realname}"),
        );
        if let Some(account) = account {
            cx.reply(
                Numeric::RPL_WHOISACCOUNT,
                format!("{nick} {account} :is logged in as"),
            );
        }
        let channels = whois_channels(&cx, &target);
        if !channels.is_empty() {
            cx.reply(
                Numeric::RPL_WHOISCHANNELS,
                format!("{nick} :{}", channels.join(" ")),
            );
        }
        cx.reply(
            Numeric::RPL_WHOISSERVER,
            format!("{nick} {server_name} :rs-ircd"),
        );
        if oper {
            cx.reply(
                Numeric::RPL_WHOISOPERATOR,
                format!("{nick} :is an IRC operator"),
            );
        }
        if let Some(text) = away {
            cx.reply(Numeric::RPL_AWAY, format!("{nick} :{text}"));
        }
        cx.reply(
            Numeric::RPL_WHOISIDLE,
            format!(
                "{nick} {} {signon} :seconds idle, signon time",
                target.idle_seconds()
            ),
        );
        cx.reply(
            Numeric::RPL_ENDOFWHOIS,
            format!("{nick} :End of /WHOIS list."),
        );
        Ok(())
    })
}

fn whois_channels(cx: &Cmd, target: &ClientHandle) -> Vec<String> {
    let mut channels = Vec::new();
    let shared = |channel: &Channel| channel.contains(cx.client.id);
    for folded in target.channels() {
        let Some(channel) = cx.server.channels.get(&folded) else {
            continue;
        };
        let guard = channel.read();
        if (guard.secret || guard.private) && !shared(&guard) {
            continue;
        }
        let prefix = guard
            .member(target.id)
            .map(|mode| mode.prefixes(false))
            .unwrap_or_default();
        channels.push(format!("{prefix}{}", guard.name));
    }
    channels.sort_unstable();
    channels
}

fn cmd_whowas(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let nick = cx.param(0).unwrap_or_default().to_owned();
        let entries = cx.server.whowas_entries(&nick, 10);
        if entries.is_empty() {
            cx.reply(
                Numeric::ERR_WASNOSUCHNICK,
                format!("{nick} :There was no such nickname"),
            );
        }
        let server_name = cx.server.name();
        for entry in entries {
            cx.reply(
                Numeric::RPL_WHOWASUSER,
                format!(
                    "{} {} {} * :{}",
                    entry.nick, entry.user, entry.host, entry.realname
                ),
            );
            cx.reply(
                Numeric::RPL_WHOISSERVER,
                format!("{} {server_name} :{}", entry.nick, iso8601(entry.signon)),
            );
        }
        cx.reply(Numeric::RPL_ENDOFWHOWAS, format!("{nick} :End of WHOWAS"));
        Ok(())
    })
}

fn cmd_ison(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let mut online = Vec::new();
        for nick in cx.msg.params.iter() {
            if let Some(client) = cx.find(nick) {
                online.push(client.nick_or_star());
            }
        }
        if online.is_empty() {
            cx.reply(Numeric::RPL_USERHOST, ":");
        } else {
            cx.reply(Numeric::RPL_USERHOST, format!(":{}", online.join(" ")));
        }
        Ok(())
    })
}

fn cmd_userhost(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let mut entries = Vec::new();
        for nick in cx.msg.params.iter().take(5) {
            let Some(client) = cx.find(nick) else {
                continue;
            };
            let (user, host, oper, away) = client.session(|session| {
                (
                    session.user.clone().unwrap_or_default(),
                    session.host.clone(),
                    session.modes.oper,
                    session.away.is_some(),
                )
            });
            entries.push(format!(
                "{}={}{}{user}@{host}",
                client.nick_or_star(),
                if away { '-' } else { '+' },
                if oper { "*" } else { "" }
            ));
        }
        cx.reply(Numeric::RPL_USERHOST, format!(":{}", entries.join(" ")));
        Ok(())
    })
}

/// Exposed for tests: current wall clock used in topic timestamps.
pub fn now() -> u64 {
    now_unix()
}
