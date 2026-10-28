//! Channel commands: `JOIN`, `PART`, `MODE`, `TOPIC`, `NAMES`, `LIST`,
//! `INVITE` and `KICK`.

use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;

use crate::commands::{is_channel_name, valid_channel_name, Access, Cmd, CmdFuture, CommandSpec};
use crate::error::CommandError;
use crate::protocol::{Message, Numeric};
use crate::server::channel::{BanEntry, JoinRefusal, JoinRequest, MemberMode};
use crate::server::{CapSet, Channel, ClientHandle};
use crate::util::now_unix;

/// `JOIN` enters one or more channels.
pub const JOIN: CommandSpec = CommandSpec {
    name: "JOIN",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_join,
};

/// `PART` leaves channels.
pub const PART: CommandSpec = CommandSpec {
    name: "PART",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_part,
};

/// `MODE` reads or changes channel and user modes.
pub const MODE: CommandSpec = CommandSpec {
    name: "MODE",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_mode,
};

/// `TOPIC` reads or sets a channel topic.
pub const TOPIC: CommandSpec = CommandSpec {
    name: "TOPIC",
    min_params: 1,
    access: Access::Registered,
    handler: cmd_topic,
};

/// `NAMES` lists channel members.
pub const NAMES: CommandSpec = CommandSpec {
    name: "NAMES",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_names,
};

/// `LIST` lists channels.
pub const LIST: CommandSpec = CommandSpec {
    name: "LIST",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_list,
};

/// `INVITE` invites a client to a channel.
pub const INVITE: CommandSpec = CommandSpec {
    name: "INVITE",
    min_params: 2,
    access: Access::Registered,
    handler: cmd_invite,
};

/// `KICK` removes a member from a channel.
pub const KICK: CommandSpec = CommandSpec {
    name: "KICK",
    min_params: 2,
    access: Access::Registered,
    handler: cmd_kick,
};

fn cmd_join(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let names = cx.param(0).unwrap_or_default().to_owned();
        let keys = cx.param(1).unwrap_or_default().to_owned();
        let keys: Vec<&str> = keys.split(',').collect();
        for (index, raw) in names.split(',').enumerate().take(20) {
            if raw.is_empty() {
                continue;
            }
            let key = keys.get(index).copied().unwrap_or_default();
            if let Err(error) = join_one(&cx, raw, key) {
                cx.reply(error.code, error.text);
            }
        }
        Ok(())
    })
}

fn join_one(cx: &Cmd, name: &str, key: &str) -> Result<(), CommandError> {
    if !valid_channel_name(name) {
        return Err(cx.fail(
            Numeric::ERR_BADCHANMASK,
            format!("{name} :Bad channel mask"),
        ));
    }
    let config = cx.server.cfg();
    let folded = config.server.casemapping.fold(name);
    if cx
        .client
        .session(|session| session.channels.contains(&folded))
    {
        return Ok(());
    }
    if cx.client.channels().len() >= config.limits.max_channels_per_client {
        return Err(cx.fail(
            Numeric::ERR_TOOMANYCHANNELS,
            format!("{name} :You have joined too many channels"),
        ));
    }

    let entry = cx
        .server
        .channels
        .entry(folded.clone())
        .or_insert_with(|| Arc::new(RwLock::new(Channel::new(name))));

    let (recipients, members, topic, channel_name) = {
        let mut channel = entry.value().write();
        let (nick, user, host, account) = cx.client.session(|session| {
            (
                session.nick.clone().unwrap_or_default(),
                session.user.clone().unwrap_or_default(),
                session.host.clone(),
                session.account.clone(),
            )
        });
        let request = JoinRequest {
            id: cx.client.id,
            nick: &nick,
            user: &user,
            host: &host,
            account: account.as_deref(),
            key,
        };
        // MARK: security: high: SEC-JOIN-001: every channel mode is enforced in one ordered gate.
        // An operator holding `admin` may override the gate, and the channel
        // operators are told which rule was overridden. The privilege is
        // checked here rather than in the command so a relayed join cannot
        // take a different path.
        let mut overrode = None;
        if let Err(refusal) = channel.join_check(&request, std::time::Instant::now()) {
            if cx.has_privilege(crate::config::OperPrivilege::ADMIN) {
                overrode = Some(refusal);
            } else {
                let numeric = match refusal {
                    JoinRefusal::Full => Numeric::ERR_CHANNELISFULL,
                    JoinRefusal::BadKey => Numeric::ERR_BADCHANNELKEY,
                    JoinRefusal::InviteOnly => Numeric::ERR_INVITEONLYCHAN,
                    JoinRefusal::AccountOnly => Numeric::ERR_NEEDREGGEDNICK,
                    JoinRefusal::Banned => Numeric::ERR_BANNEDFROMCHAN,
                };
                return Err(cx.fail(numeric, format!("{name} :{}", refusal.reason())));
            }
        }
        channel.add(cx.client.id);
        if let Some(refusal) = overrode {
            let server_name = cx.server.name();
            let oper = cx.nick();
            for (id, mode) in &channel.members {
                if *id == cx.client.id || !mode.op {
                    continue;
                }
                if let Some(channel_op) = cx.server.find_client(*id) {
                    channel_op.send_raw(
                        &format!(
                            ":{server_name} NOTICE {} :Oper {oper} overrode {} on {}",
                            channel_op.nick_or_star(),
                            refusal.reason(),
                            channel.name
                        ),
                        cx.max_line(),
                    );
                }
            }
        }
        let members = channel
            .sorted_members(|id| cx.server.find_client(id).and_then(|client| client.nick()))
            .into_iter()
            .map(|(_, mode, nick)| (nick, mode))
            .collect::<Vec<_>>();
        let recipients = channel
            .members
            .keys()
            .filter_map(|id| cx.server.find_client(*id))
            .collect::<Vec<_>>();
        let topic = channel.topic.clone().map(|topic| {
            (
                topic,
                channel.topic_setter.clone().unwrap_or_default(),
                channel.topic_time,
            )
        });
        (recipients, members, topic, channel.name.clone())
    };
    drop(entry);

    cx.client
        .session_mut(|session| session.channels.insert(folded.clone()));

    let mut join = Message::command("JOIN");
    join.prefix = Some(cx.mask());
    join.params.push(channel_name.clone());

    let (account, realname) = cx.client.session(|session| {
        (
            session.account.clone().unwrap_or_else(|| "*".to_owned()),
            session.realname.clone().unwrap_or_default(),
        )
    });
    let mut extended = join.clone();
    extended.params.push(account);
    extended.params.push(realname);

    let max_line = cx.max_line();
    let account_name = cx.client.session(|session| session.account.clone());
    // `extended-join` adds parameters, `account-tag` adds a tag, so there are
    // at most four forms of this one event.
    let mut variants: [Option<Bytes>; 4] = std::array::from_fn(|_| None);
    for recipient in &recipients {
        let extended_join = recipient.has_cap(CapSet::EXTENDED_JOIN);
        let tagged = account_name.is_some() && recipient.has_cap(CapSet::ACCOUNT_TAG);
        let slot = usize::from(extended_join) | (usize::from(tagged) << 1);
        let bytes = variants[slot].get_or_insert_with(|| {
            let mut message = if extended_join {
                extended.clone()
            } else {
                join.clone()
            };
            if tagged {
                if let Some(account) = account_name.as_deref() {
                    message.push_tag("account", account);
                }
            }
            Bytes::from(message.to_bytes_limited(max_line))
        });
        recipient.enqueue(bytes.clone());
    }

    match topic {
        None => cx.reply(
            Numeric::RPL_NOTOPIC,
            format!("{channel_name} :No topic is set"),
        ),
        Some((text, setter, time)) => {
            cx.reply(Numeric::RPL_TOPIC, format!("{channel_name} :{text}"));
            cx.reply(
                Numeric::RPL_TOPICWHOTIME,
                format!("{channel_name} {setter} {time}"),
            );
        }
    }

    send_names(
        cx,
        &channel_name,
        &members,
        std::slice::from_ref(&cx.client),
    );

    if let Some(outcome) = cx.server.hook_event("join", &cx.client, &join) {
        for line in outcome.lines {
            cx.client.send_raw(&line, max_line);
        }
    }
    // The key is not echoed to members, but the next server needs it to apply
    // the same `+k` rule instead of trusting this one blindly.
    if key.is_empty() {
        cx.server.propagate_link(&join);
    } else {
        let mut relay = join.clone();
        relay.params.push(key.to_owned());
        cx.server.propagate_link(&relay);
    }
    Ok(())
}

fn cmd_part(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let names = cx.param(0).unwrap_or_default().to_owned();
        let reason = cx.param(1).unwrap_or_default().to_owned();
        let account = cx.client.session(|session| session.account.clone());
        for name in names.split(',') {
            let Some(channel) = cx.channel(name) else {
                cx.reply(
                    Numeric::ERR_NOSUCHCHANNEL,
                    format!("{name} :No such channel"),
                );
                continue;
            };
            let folded = cx.casemap().fold(name);
            let (channel_name, recipients) = {
                let mut guard = channel.write();
                if !guard.contains(cx.client.id) {
                    cx.reply(
                        Numeric::ERR_NOTONCHANNEL,
                        format!("{name} :You're not on that channel"),
                    );
                    continue;
                }
                let recipients = guard
                    .members
                    .keys()
                    .filter_map(|id| cx.server.find_client(*id))
                    .collect::<Vec<_>>();
                guard.remove(cx.client.id);
                (guard.name.clone(), recipients)
            };
            cx.client
                .session_mut(|session| session.channels.remove(&folded));

            let mut part = Message::command("PART");
            part.prefix = Some(cx.mask());
            part.params.push(channel_name);
            if !reason.is_empty() {
                part.params.push(reason.clone());
            }
            match account.as_deref() {
                Some(account) => cx
                    .server
                    .broadcast_with_account(recipients, &part, None, account),
                None => cx.server.broadcast(recipients, &part, None),
            }
            cx.server.propagate_link(&part);

            let empty = cx
                .server
                .channels
                .get(&folded)
                .is_some_and(|candidate| candidate.read().is_empty());
            if empty {
                cx.server
                    .channels
                    .remove_if(&folded, |_, candidate| candidate.read().is_empty());
            }
        }
        Ok(())
    })
}

fn cmd_topic(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let name = cx.param(0).unwrap_or_default().to_owned();
        let Some(channel) = cx.channel(&name) else {
            return Err(cx.fail(
                Numeric::ERR_NOSUCHCHANNEL,
                format!("{name} :No such channel"),
            ));
        };
        let Some(text) = cx.param(1).map(str::to_owned) else {
            let guard = channel.read();
            return match &guard.topic {
                None => {
                    cx.reply(
                        Numeric::RPL_NOTOPIC,
                        format!("{} :No topic is set", guard.name),
                    );
                    Ok(())
                }
                Some(topic) => {
                    cx.reply(Numeric::RPL_TOPIC, format!("{} :{topic}", guard.name));
                    cx.reply(
                        Numeric::RPL_TOPICWHOTIME,
                        format!(
                            "{} {} {}",
                            guard.name,
                            guard.topic_setter.clone().unwrap_or_default(),
                            guard.topic_time
                        ),
                    );
                    Ok(())
                }
            };
        };
        let text = text.chars().take(300).collect::<String>();
        let (channel_name, recipients) = {
            let mut guard = channel.write();
            if !guard.contains(cx.client.id) {
                return Err(cx.fail(
                    Numeric::ERR_NOTONCHANNEL,
                    format!("{} :You're not on that channel", guard.name),
                ));
            }
            if guard.topic_lock && !guard.is_op(cx.client.id) {
                return Err(cx.fail(
                    Numeric::ERR_CHANOPRIVSNEEDED,
                    format!("{} :You're not channel operator", guard.name),
                ));
            }
            guard.topic = if text.is_empty() {
                None
            } else {
                Some(text.clone())
            };
            guard.topic_setter = Some(cx.nick());
            guard.topic_time = now_unix();
            (
                guard.name.clone(),
                guard
                    .members
                    .keys()
                    .filter_map(|id| cx.server.find_client(*id))
                    .collect::<Vec<_>>(),
            )
        };
        let mut message = Message::command("TOPIC");
        message.prefix = Some(cx.mask());
        message.params.push(channel_name);
        message.params.push(text);
        cx.server.broadcast(recipients, &message, None);
        cx.server.propagate_link(&message);
        Ok(())
    })
}

fn cmd_names(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        match cx.param(0) {
            Some(name) if !name.is_empty() => {
                let Some(channel) = cx.channel(name) else {
                    cx.reply(
                        Numeric::RPL_ENDOFNAMES,
                        format!("{name} :End of /NAMES list."),
                    );
                    return Ok(());
                };
                let guard = channel.read();
                if !guard.contains(cx.client.id) && (guard.secret || guard.private) {
                    cx.reply(
                        Numeric::RPL_ENDOFNAMES,
                        format!("{} :End of /NAMES list.", guard.name),
                    );
                    return Ok(());
                }
                let members = guard
                    .sorted_members(|id| cx.server.find_client(id).and_then(|client| client.nick()))
                    .into_iter()
                    .map(|(_, mode, nick)| (nick, mode))
                    .collect::<Vec<_>>();
                let channel_name = guard.name.clone();
                drop(guard);
                send_names(
                    &cx,
                    &channel_name,
                    &members,
                    std::slice::from_ref(&cx.client),
                );
            }
            _ => {
                let channels = cx
                    .server
                    .channels
                    .iter()
                    .map(|entry| Arc::clone(entry.value()))
                    .collect::<Vec<_>>();
                for channel in channels {
                    let guard = channel.read();
                    if (guard.secret || guard.private) && !guard.contains(cx.client.id) {
                        continue;
                    }
                    let members = guard
                        .sorted_members(|id| {
                            cx.server.find_client(id).and_then(|client| client.nick())
                        })
                        .into_iter()
                        .map(|(_, mode, nick)| (nick, mode))
                        .collect::<Vec<_>>();
                    let channel_name = guard.name.clone();
                    drop(guard);
                    send_names(
                        &cx,
                        &channel_name,
                        &members,
                        std::slice::from_ref(&cx.client),
                    );
                }
                cx.reply(Numeric::RPL_ENDOFNAMES, "* :End of /NAMES list.");
            }
        }
        Ok(())
    })
}

fn cmd_list(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let filter = cx.param(0).map(str::to_lowercase);
        cx.reply(Numeric::RPL_LISTSTART, "Channel :Users Name");
        let channels = cx
            .server
            .channels
            .iter()
            .map(|entry| Arc::clone(entry.value()))
            .collect::<Vec<_>>();
        for channel in channels {
            let guard = channel.read();
            if (guard.secret || guard.private) && !guard.contains(cx.client.id) {
                continue;
            }
            if let Some(filter) = &filter {
                if !guard.name.to_lowercase().contains(filter) && filter != "*" {
                    continue;
                }
            }
            let topic = guard.topic.clone().unwrap_or_default();
            drop(guard);
            cx.reply(
                Numeric::RPL_LIST,
                format!(
                    "{} {} :{}",
                    channel.read().name,
                    channel.read().len(),
                    topic
                ),
            );
        }
        cx.reply(Numeric::RPL_LISTEND, ":End of /LIST");
        Ok(())
    })
}

fn cmd_invite(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let nick = cx.param(0).unwrap_or_default().to_owned();
        let name = cx.param(1).unwrap_or_default().to_owned();
        let Some(target) = cx.find(&nick) else {
            return Err(cx.fail(
                Numeric::ERR_NOSUCHNICK,
                format!("{nick} :No such nick/channel"),
            ));
        };
        let Some(channel) = cx.channel(&name) else {
            return Err(cx.fail(
                Numeric::ERR_NOSUCHCHANNEL,
                format!("{name} :No such channel"),
            ));
        };
        let (channel_name, is_op) = {
            let guard = channel.read();
            (guard.name.clone(), guard.is_op(cx.client.id))
        };
        {
            let mut guard = channel.write();
            if !guard.contains(cx.client.id) {
                return Err(cx.fail(
                    Numeric::ERR_NOTONCHANNEL,
                    format!("{channel_name} :You're not on that channel"),
                ));
            }
            if guard.contains(target.id) {
                return Err(cx.fail(
                    Numeric::ERR_USERONCHANNEL,
                    format!("{nick} {channel_name} :is already on channel"),
                ));
            }
            if guard.invite_only && !is_op {
                return Err(cx.fail(
                    Numeric::ERR_CHANOPRIVSNEEDED,
                    format!("{channel_name} :You're not channel operator"),
                ));
            }
            // MARK: policy: high: POL-INVITE-002: every invitation carries the configured lifetime.
            let ttl = std::time::Duration::from_secs(cx.server.cfg().server.invite_expiry_secs);
            guard.invite(target.id, cx.nick(), ttl);
        }
        cx.reply(Numeric::RPL_INVITING, format!("{nick} {channel_name}"));
        let mut invite = Message::command("INVITE");
        invite.prefix = Some(cx.mask());
        invite.params.push(nick);
        invite.params.push(channel_name);
        target.send(&invite, cx.max_line());
        // Every server records the invitation against its own handle for the
        // invitee; without the relay a remote user could never pass `+i`.
        if cx.client.is_local() {
            cx.server.propagate_link(&invite);
        }
        Ok(())
    })
}

fn cmd_kick(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let channel_name = cx.param(0).unwrap_or_default().to_owned();
        let targets = cx.param(1).unwrap_or_default().to_owned();
        let reason = cx.param(2).map(str::to_owned).unwrap_or_else(|| cx.nick());
        let Some(channel) = cx.channel(&channel_name) else {
            return Err(cx.fail(
                Numeric::ERR_NOSUCHCHANNEL,
                format!("{channel_name} :No such channel"),
            ));
        };
        for target_nick in targets.split(',') {
            let Some(target) = cx.find(target_nick) else {
                cx.reply(
                    Numeric::ERR_NOSUCHNICK,
                    format!("{target_nick} :No such nick/channel"),
                );
                continue;
            };
            let channel_name = {
                let mut guard = channel.write();
                if !guard.is_op(cx.client.id) {
                    return Err(cx.fail(
                        Numeric::ERR_CHANOPRIVSNEEDED,
                        format!("{} :You're not channel operator", guard.name),
                    ));
                }
                if !guard.contains(target.id) {
                    cx.reply(
                        Numeric::ERR_USERNOTINCHANNEL,
                        format!("{target_nick} {} :They aren't on that channel", guard.name),
                    );
                    continue;
                }
                let recipients = guard
                    .members
                    .keys()
                    .filter_map(|id| cx.server.find_client(*id))
                    .collect::<Vec<_>>();
                guard.remove(target.id);
                let name = guard.name.clone();
                let mut kick = Message::command("KICK");
                kick.prefix = Some(cx.mask());
                kick.params.push(name.clone());
                kick.params.push(target_nick.to_owned());
                kick.params.push(reason.clone());
                cx.server.broadcast(recipients, &kick, None);
                cx.server.propagate_link(&kick);
                name
            };
            let folded = cx.casemap().fold(&channel_name);
            target.session_mut(|session| session.channels.remove(&folded));
            let empty = cx
                .server
                .channels
                .get(&folded)
                .is_some_and(|candidate| candidate.read().is_empty());
            if empty {
                cx.server
                    .channels
                    .remove_if(&folded, |_, candidate| candidate.read().is_empty());
            }
        }
        Ok(())
    })
}

fn cmd_mode(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let target = cx.param(0).unwrap_or_default().to_owned();
        let params = cx.msg.params[1..].to_vec();
        if is_channel_name(&target) {
            channel_mode(&cx, &target, &params, false)
        } else {
            user_mode(&cx, &target, &params)
        }
    })
}

fn user_mode(cx: &Cmd, target: &str, params: &[String]) -> Result<(), CommandError> {
    if !cx.casemap().eq(target, &cx.nick()) {
        return Err(cx.fail(
            Numeric::ERR_USERSDONTMATCH,
            ":Cannot change mode for other users",
        ));
    }
    if params.is_empty() {
        cx.reply(
            Numeric::RPL_UMODEIS,
            cx.client.session(|session| session.modes.to_flags()),
        );
        return Ok(());
    }
    let mut adding = true;
    let mut rendered = String::new();
    let mut last: Option<bool> = None;
    for character in params[0].chars() {
        match character {
            '+' => adding = true,
            '-' => adding = false,
            'i' | 'w' | 's' | 'o' => {
                // Operators are granted by OPER, never self-assigned, and
                // server notices are only meaningful for an operator.
                if character == 'o' && adding {
                    continue;
                }
                if character == 's' && adding && !cx.is_oper() {
                    continue;
                }
                let changed = cx.client.session_mut(|session| {
                    let changed = session.modes.apply(character, adding);
                    // Clearing `+s` must also drop the subscription, otherwise
                    // `SNOMASK` would keep filtering notices nobody can see.
                    if changed && character == 's' && !adding {
                        session.snomasks = crate::server::Snomask::NONE;
                    }
                    changed
                });
                if changed {
                    if last != Some(adding) {
                        rendered.push(if adding { '+' } else { '-' });
                        last = Some(adding);
                    }
                    rendered.push(character);
                }
            }
            _ => {
                return Err(cx.fail(Numeric::ERR_UMODEUNKNOWNFLAG, ":Unknown MODE flag"));
            }
        }
    }
    if !rendered.is_empty() {
        let mut message = Message::command("MODE");
        message.prefix = Some(cx.mask());
        message.params.push(cx.nick());
        message.params.push(rendered);
        cx.client.send(&message, cx.max_line());
        cx.server.propagate_link(&message);
    }
    Ok(())
}

fn channel_mode(cx: &Cmd, name: &str, params: &[String], forced: bool) -> Result<(), CommandError> {
    let Some(channel) = cx.channel(name) else {
        return Err(cx.fail(
            Numeric::ERR_NOSUCHCHANNEL,
            format!("{name} :No such channel"),
        ));
    };
    if params.is_empty() {
        let guard = channel.read();
        cx.reply(
            Numeric::RPL_CHANNELMODEIS,
            format!("{} {}", guard.name, guard.mode_string()),
        );
        return Ok(());
    }
    if params.len() == 1 && matches!(params[0].as_str(), "+b" | "+e") {
        let exceptions = params[0] == "+e";
        let guard = channel.read();
        let entries = if exceptions {
            &guard.exceptions
        } else {
            &guard.bans
        };
        for entry in entries {
            let code = if exceptions {
                Numeric::RPL_EXCEPTLIST
            } else {
                Numeric::RPL_BANLIST
            };
            cx.reply(
                code,
                format!(
                    "{} {} {} {}",
                    guard.name, entry.mask, entry.set_by, entry.set_at
                ),
            );
        }
        let (code, label) = if exceptions {
            (
                Numeric::RPL_ENDOFEXCEPTLIST,
                "End of Channel Exception List",
            )
        } else {
            (Numeric::RPL_ENDOFBANLIST, "End of Channel Ban List")
        };
        cx.reply(code, format!("{} :{label}", guard.name));
        return Ok(());
    }
    if !forced && !channel.read().is_op(cx.client.id) {
        return Err(cx.fail(
            Numeric::ERR_CHANOPRIVSNEEDED,
            format!("{} :You're not channel operator", channel.read().name),
        ));
    }

    let mut changes: Vec<(bool, char, Option<String>)> = Vec::new();
    {
        let mut guard = channel.write();
        let channel_name = guard.name.clone();
        let mut adding = true;
        // `params[0]` is the mode string itself; arguments start after it.
        let mut argument = 1usize;
        for character in params[0].chars() {
            if changes.len() >= 4 {
                break;
            }
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
                        changes.push((adding, character, None));
                    }
                }
                'k' => {
                    if adding {
                        let Some(key) = params.get(argument) else {
                            return Err(
                                cx.fail(Numeric::ERR_NEEDMOREPARAMS, "MODE :Not enough parameters")
                            );
                        };
                        argument += 1;
                        guard.key = Some(key.clone());
                        changes.push((true, 'k', Some(key.clone())));
                    } else {
                        let key = params.get(argument).cloned();
                        if key.is_some() {
                            argument += 1;
                        }
                        guard.key = None;
                        changes.push((false, 'k', key));
                    }
                }
                'l' => {
                    if adding {
                        let Some(value) = params.get(argument) else {
                            return Err(
                                cx.fail(Numeric::ERR_NEEDMOREPARAMS, "MODE :Not enough parameters")
                            );
                        };
                        argument += 1;
                        let limit = value.parse::<usize>().map_err(|_| {
                            cx.fail(Numeric::ERR_UNKNOWNMODE, format!("{value} :Invalid limit"))
                        })?;
                        let limit = limit.min(100_000);
                        guard.limit = Some(limit);
                        changes.push((true, 'l', Some(limit.to_string())));
                    } else {
                        guard.limit = None;
                        changes.push((false, 'l', None));
                    }
                }
                'o' | 'v' => {
                    let Some(nick) = params.get(argument) else {
                        return Err(
                            cx.fail(Numeric::ERR_NEEDMOREPARAMS, "MODE :Not enough parameters")
                        );
                    };
                    argument += 1;
                    let Some(target) = cx.find(nick) else {
                        return Err(cx.fail(
                            Numeric::ERR_NOSUCHNICK,
                            format!("{nick} :No such nick/channel"),
                        ));
                    };
                    let Some(member) = guard.members.get_mut(&target.id) else {
                        return Err(cx.fail(
                            Numeric::ERR_USERNOTINCHANNEL,
                            format!("{nick} {channel_name} :They aren't on that channel"),
                        ));
                    };
                    let slot = if character == 'o' {
                        &mut member.op
                    } else {
                        &mut member.voice
                    };
                    if *slot == adding {
                        continue;
                    }
                    *slot = adding;
                    changes.push((adding, character, Some(nick.clone())));
                }
                'b' | 'e' => {
                    let Some(mask) = params.get(argument) else {
                        continue;
                    };
                    argument += 1;
                    let list = if character == 'e' {
                        &mut guard.exceptions
                    } else {
                        &mut guard.bans
                    };
                    if adding {
                        // The list is client-controlled, so it is bounded by
                        // the `MAXLIST` value advertised in `005`.
                        if list.len() < 100 && !list.iter().any(|entry| entry.mask == *mask) {
                            list.push(BanEntry {
                                mask: mask.clone(),
                                set_by: cx.nick(),
                                set_at: now_unix(),
                            });
                        }
                    } else {
                        list.retain(|entry| entry.mask != *mask);
                    }
                    changes.push((adding, character, Some(mask.clone())));
                }
                _ => {
                    return Err(cx.fail(
                        Numeric::ERR_UNKNOWNMODE,
                        format!("{character} :is unknown mode char to me"),
                    ));
                }
            }
        }
    }

    if changes.is_empty() {
        return Ok(());
    }

    let mut rendered = String::new();
    let mut rendered_args = Vec::new();
    let mut last: Option<bool> = None;
    for (adding, mode, argument) in &changes {
        if last != Some(*adding) {
            rendered.push(if *adding { '+' } else { '-' });
            last = Some(*adding);
        }
        rendered.push(*mode);
        if let Some(argument) = argument {
            rendered_args.push(argument.clone());
        }
    }

    let mut message = Message::command("MODE");
    message.prefix = Some(cx.mask());
    message.params.push(channel.read().name.clone());
    message.params.push(rendered);
    message.params.extend(rendered_args);

    {
        let guard = channel.read();
        cx.server.broadcast_channel(&guard, &message, None);
    }
    cx.server.propagate_link(&message);
    Ok(())
}

/// Apply a channel mode change on behalf of an operator (`SAMODE`).
///
/// The same parser and the same broadcast as `MODE`; only the channel-operator
/// requirement is bypassed, so a forced change produces exactly the wire
/// traffic an ordinary change would.
pub fn samode(cx: &Cmd, name: &str, params: &[String]) -> Result<(), CommandError> {
    channel_mode(cx, name, params, true)
}

/// Send `RPL_NAMREPLY`/`RPL_ENDOFNAMES` to `recipients`.
fn send_names(
    cx: &Cmd,
    channel_name: &str,
    members: &[(String, MemberMode)],
    recipients: &[Arc<ClientHandle>],
) {
    let multi: Vec<String> = members
        .iter()
        .map(|(nick, mode)| format!("{}{nick}", mode.prefixes(true)))
        .collect();
    let single: Vec<String> = members
        .iter()
        .map(|(nick, mode)| format!("{}{nick}", mode.prefixes(false)))
        .collect();
    let server = cx.server.name();
    let max_line = cx.max_line();

    for recipient in recipients {
        let nick = recipient.nick_or_star();
        let list = if recipient.has_cap(CapSet::MULTI_PREFIX) {
            &multi
        } else {
            &single
        };
        let mut buffer = String::new();
        for entry in list {
            if !buffer.is_empty() && buffer.len() + entry.len() + 1 > 400 {
                recipient.send_raw(
                    &format!(":{server} 353 {nick} = {channel_name} :{buffer}"),
                    max_line,
                );
                buffer.clear();
            }
            if !buffer.is_empty() {
                buffer.push(' ');
            }
            buffer.push_str(entry);
        }
        if !buffer.is_empty() {
            recipient.send_raw(
                &format!(":{server} 353 {nick} = {channel_name} :{buffer}"),
                max_line,
            );
        }
        recipient.send_raw(
            &format!(":{server} 366 {nick} {channel_name} :End of /NAMES list."),
            max_line,
        );
    }
}
