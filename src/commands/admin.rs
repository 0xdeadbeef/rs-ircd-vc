//! Operator and informational commands.

use std::time::Instant;

use crate::commands::{is_channel_name, Access, Cmd, CmdFuture, CommandSpec};
use crate::config::OperPrivilege;
use crate::error::CommandError;
use crate::protocol::{Message, Numeric};
use crate::server::ban::{describe_remaining, parse_duration, BanKind, ServerBan};
use crate::server::{link, Snomask};
use crate::util::{iso8601, now_unix, verify_password, wildcard_match};

/// `OPER` grants operator privileges.
pub const OPER: CommandSpec = CommandSpec {
    name: "OPER",
    min_params: 2,
    access: Access::Registered,
    handler: cmd_oper,
};

/// `KILL` disconnects another client.
pub const KILL: CommandSpec = CommandSpec {
    name: "KILL",
    min_params: 1,
    access: Access::Oper(OperPrivilege::KILL),
    handler: cmd_kill,
};

/// `REHASH` reloads the configuration.
pub const REHASH: CommandSpec = CommandSpec {
    name: "REHASH",
    min_params: 0,
    access: Access::Oper(OperPrivilege::REHASH),
    handler: cmd_rehash,
};

/// `STATS` reports server statistics.
pub const STATS: CommandSpec = CommandSpec {
    name: "STATS",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_stats,
};

/// `VERSION` reports the server version.
pub const VERSION: CommandSpec = CommandSpec {
    name: "VERSION",
    min_params: 0,
    access: Access::Unregistered,
    handler: cmd_version,
};

/// `TIME` reports server time.
pub const TIME: CommandSpec = CommandSpec {
    name: "TIME",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_time,
};

/// `MOTD` repeats the message of the day.
pub const MOTD: CommandSpec = CommandSpec {
    name: "MOTD",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_motd,
};

/// `LUSERS` reports user counts.
pub const LUSERS: CommandSpec = CommandSpec {
    name: "LUSERS",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_lusers,
};

/// `ADMIN` reports administrator contact details.
pub const ADMIN: CommandSpec = CommandSpec {
    name: "ADMIN",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_admin,
};

/// `INFO` reports implementation notes.
pub const INFO: CommandSpec = CommandSpec {
    name: "INFO",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_info,
};

/// `LINKS` lists server links.
pub const LINKS: CommandSpec = CommandSpec {
    name: "LINKS",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_links,
};

/// `WALLOPS` broadcasts to `+w` users.
pub const WALLOPS: CommandSpec = CommandSpec {
    name: "WALLOPS",
    min_params: 1,
    access: Access::Oper(OperPrivilege::GLOBAL),
    handler: cmd_wallops,
};

/// `COMPRESS` negotiates zlib framing.
pub const COMPRESS: CommandSpec = CommandSpec {
    name: "COMPRESS",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_compress,
};

/// `BENCH` runs hot-path micro-benchmarks.
pub const BENCH: CommandSpec = CommandSpec {
    name: "BENCH",
    min_params: 0,
    access: Access::Oper(OperPrivilege::REHASH),
    handler: cmd_bench,
};

/// `SNOMASK` subscribes an operator to server notice categories.
pub const SNOMASK: CommandSpec = CommandSpec {
    name: "SNOMASK",
    min_params: 0,
    // `NONE` matches every operator: `+o` alone is enough to filter notices.
    access: Access::Oper(OperPrivilege::NONE),
    handler: cmd_snomask,
};

/// `GLOBOPS` sends a notice to every operator on the network.
pub const GLOBOPS: CommandSpec = CommandSpec {
    name: "GLOBOPS",
    min_params: 1,
    access: Access::Oper(OperPrivilege::GLOBAL),
    handler: cmd_globops,
};

/// `SAMODE` forces a channel mode change from outside the channel.
pub const SAMODE: CommandSpec = CommandSpec {
    name: "SAMODE",
    min_params: 2,
    access: Access::Oper(OperPrivilege::ADMIN),
    handler: cmd_samode,
};

/// `KLINE` refuses a client on this server.
pub const KLINE: CommandSpec = CommandSpec {
    name: "KLINE",
    min_params: 2,
    access: Access::Oper(OperPrivilege::BAN),
    handler: cmd_kline,
};

/// `GLINE` refuses a client network-wide.
pub const GLINE: CommandSpec = CommandSpec {
    name: "GLINE",
    min_params: 2,
    access: Access::Oper(OperPrivilege::BAN),
    handler: cmd_gline,
};

/// `ZLINE` refuses an address network-wide.
pub const ZLINE: CommandSpec = CommandSpec {
    name: "ZLINE",
    min_params: 2,
    access: Access::Oper(OperPrivilege::BAN),
    handler: cmd_zline,
};

/// `SHUN` silences a client without disconnecting it.
pub const SHUN: CommandSpec = CommandSpec {
    name: "SHUN",
    min_params: 2,
    access: Access::Oper(OperPrivilege::BAN),
    handler: cmd_shun,
};

/// `UNBAN` lifts a server ban.
pub const UNBAN: CommandSpec = CommandSpec {
    name: "UNBAN",
    min_params: 2,
    access: Access::Oper(OperPrivilege::BAN),
    handler: cmd_unban,
};

fn cmd_oper(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let name = cx.param(0).unwrap_or_default().to_owned();
        let password = cx.param(1).unwrap_or_default().to_owned();
        let config = cx.server.cfg();
        let Some(oper) = config
            .opers
            .iter()
            .find(|candidate| candidate.name == name)
            .cloned()
        else {
            return Err(cx.fail(Numeric::ERR_PASSWDMISMATCH, ":Password incorrect"));
        };
        let host = cx.client.session(|session| session.host.clone());
        if let Some(mask) = &oper.host {
            if !wildcard_match(mask, &host) {
                return Err(cx.fail(Numeric::ERR_NOOPERHOST, ":No O-lines for your host"));
            }
        }
        let stored = oper
            .password_hash_env
            .as_deref()
            .and_then(|variable| std::env::var(variable).ok())
            .unwrap_or_default();
        // MARK: security: critical: SEC-OPER-001: operator passwords are verified against a SHA-256 hash.
        if stored.is_empty() || !verify_password(&password, &stored) {
            tracing::warn!(nick = %cx.nick(), %host, "failed OPER attempt");
            return Err(cx.fail(Numeric::ERR_PASSWDMISMATCH, ":Password incorrect"));
        }
        let privileges = OperPrivilege::from_flags(&oper.flags);
        cx.client.session_mut(|session| {
            session.oper = Some(oper.name.clone());
            session.modes.oper = true;
            session.privileges = privileges;
            // `+s` with no categories subscribed would advertise notices that
            // never arrive; subscribing to the operational set by default
            // makes the mode truthful the moment it is granted.
            session.snomasks = Snomask::ALL;
            session.modes.snomask = true;
        });
        cx.reply(Numeric::RPL_YOUREOPER, ":You are now an IRC operator");
        cx.server.snotice(
            Snomask::OPER,
            &format!("{}({}) is now an IRC operator", cx.nick(), oper.name),
        );
        tracing::info!(nick = %cx.nick(), account = %oper.name, "operator granted");
        Ok(())
    })
}

fn cmd_kill(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let nick = cx.param(0).unwrap_or_default().to_owned();
        let reason = cx.param(1).unwrap_or("Killed").to_owned();
        let Some(target) = cx.find(&nick) else {
            return Err(cx.fail(
                Numeric::ERR_NOSUCHNICK,
                format!("{nick} :No such nick/channel"),
            ));
        };
        let max_line = cx.max_line();
        target.send_raw(
            &format!(
                "ERROR :Closing link: {} (Killed by {}: {reason})",
                target.mask(),
                cx.nick()
            ),
            max_line,
        );
        cx.server
            .disconnect(&target, &format!("Killed by {}: {reason}", cx.nick()));
        tracing::info!(%nick, by = %cx.nick(), "client killed");
        Ok(())
    })
}

// MARK: policy: medium: POL-REHASH-001: a rejected configuration reports and keeps the running one.
fn cmd_rehash(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        match cx.server.rehash_attached() {
            Ok(()) => {
                cx.reply(Numeric::RPL_REHASHING, "ircd.toml :Rehashing");
            }
            Err(error) => {
                cx.server
                    .notice(&cx.client, &format!("REHASH failed: {error}"));
            }
        }
        Ok(())
    })
}

fn cmd_stats(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let query = cx.param(0).unwrap_or("u").to_ascii_lowercase();
        match query.as_str() {
            "l" => {
                let max_line = cx.max_line();
                let server_name = cx.server.name();
                for entry in cx.server.links.iter() {
                    cx.client.send_raw(
                        &format!(
                            ":{server_name} 211 {} {} 0 0 0 :{}",
                            entry.key(),
                            entry.value(),
                            entry.value()
                        ),
                        max_line,
                    );
                }
            }
            "k" => {
                let server = cx.server.name();
                let now = now_unix();
                for ban in cx.server.active_bans() {
                    let expires = match ban.expires {
                        Some(expires) => expires.to_string(),
                        None => "0".to_owned(),
                    };
                    cx.client.send_raw(
                        &format!(
                            ":{server} 216 {} {} {} {} {} :{}",
                            ban.mask,
                            ban.kind.letter(),
                            ban.set_by,
                            ban.set_at,
                            expires,
                            ban.reason
                        ),
                        cx.max_line(),
                    );
                    tracing::debug!(
                        mask = %ban.mask,
                        kind = %ban.kind,
                        remaining = %describe_remaining(ban.remaining(now)),
                        "active server ban"
                    );
                }
            }
            "m" => {
                let server = cx.server.name();
                for name in crate::commands::names() {
                    if let Some(spec) = crate::commands::lookup(name) {
                        cx.client.send_raw(
                            &format!(":{server} 212 {name} {} 0", spec.min_params),
                            cx.max_line(),
                        );
                    }
                }
            }
            "o" => {
                let server = cx.server.name();
                for client in cx.server.oper_recipients() {
                    let oper = client
                        .session(|session| session.oper.clone())
                        .unwrap_or_default();
                    cx.client.send_raw(
                        &format!(":{server} 243 O {} {} * *", client.nick_or_star(), oper),
                        cx.max_line(),
                    );
                }
            }
            "u" => {
                let uptime = cx.server.uptime_seconds();
                let days = uptime / 86_400;
                let hours = (uptime % 86_400) / 3_600;
                let minutes = (uptime % 3_600) / 60;
                let seconds = uptime % 60;
                cx.reply(
                    Numeric::RPL_STATSUPTIME,
                    format!(":Server Up {days} days {hours:02}:{minutes:02}:{seconds:02}"),
                );
            }
            _ => {}
        }
        cx.reply(
            Numeric::RPL_ENDOFSTATS,
            format!("{query} :End of /STATS report"),
        );
        Ok(())
    })
}

fn cmd_version(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let server = cx.server.name();
        cx.reply(
            Numeric::RPL_VERSION,
            format!(
                "rs-ircd-{} {server} :RFC 1459/2810-2813 daemon",
                env!("CARGO_PKG_VERSION")
            ),
        );
        Ok(())
    })
}

fn cmd_time(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let server = cx.server.name();
        cx.reply(
            Numeric::RPL_TIME,
            format!("{server} :{}", iso8601(crate::util::now_unix())),
        );
        Ok(())
    })
}

fn cmd_motd(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let server = cx.server.name();
        let motd = cx.server.motd();
        if motd.is_empty() {
            return Err(cx.fail(Numeric::ERR_NOMOTD, ":MOTD File is missing"));
        }
        cx.reply(
            Numeric::RPL_MOTDSTART,
            format!(":- {server} Message of the day -"),
        );
        for line in motd {
            cx.reply(Numeric::RPL_MOTD, format!(":- {line}"));
        }
        cx.reply(Numeric::RPL_ENDOFMOTD, ":End of /MOTD command.");
        Ok(())
    })
}

fn cmd_lusers(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let local = cx.server.local_clients();
        let global = cx.server.global_clients();
        let channels = cx.server.channel_count();
        let opers = cx.server.oper_count();
        cx.reply(
            Numeric::RPL_LUSERCLIENT,
            format!(
                ":There are {global} users and 0 invisible on {} servers",
                1 + cx.server.link_count()
            ),
        );
        if opers > 0 {
            cx.reply(Numeric::RPL_LUSEROP, format!("{opers} :operator(s) online"));
        }
        cx.reply(
            Numeric::RPL_LUSERCHANNELS,
            format!("{channels} :channels formed"),
        );
        cx.reply(
            Numeric::RPL_LUSERME,
            format!(
                ":I have {local} clients and {} servers",
                cx.server.link_count()
            ),
        );
        cx.reply(
            Numeric::RPL_LOCALUSERS,
            format!("{local} {local} :Current local users {local}, max {local}"),
        );
        cx.reply(
            Numeric::RPL_GLOBALUSERS,
            format!("{global} {global} :Current global users {global}, max {global}"),
        );
        Ok(())
    })
}

fn cmd_admin(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let server = cx.server.name();
        cx.reply(
            Numeric::RPL_ADMINME,
            format!("{server} :Administrative info"),
        );
        cx.reply(Numeric::RPL_ADMINLOC1, ":rs-ircd reference deployment");
        cx.reply(
            Numeric::RPL_ADMINLOC2,
            ":Set admin contact in the configuration",
        );
        cx.reply(Numeric::RPL_ADMINEMAIL, ":root@localhost");
        Ok(())
    })
}

fn cmd_info(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        for line in [
            format!("rs-ircd {}", env!("CARGO_PKG_VERSION")),
            "RFC 1459, RFC 2810, RFC 2811, RFC 2812, RFC 2813".to_owned(),
            "TLS via rustls, zlib connection compression, Rhai hooks".to_owned(),
            "Built with async Tokio and dashmap registries".to_owned(),
        ] {
            cx.reply(Numeric::RPL_INFO, format!(":{line}"));
        }
        cx.reply(Numeric::RPL_ENDOFINFO, ":End of /INFO list.");
        Ok(())
    })
}

fn cmd_links(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let server = cx.server.name();
        cx.reply(Numeric(364), format!("{server} {server} :0 {server}"));
        for route in cx.server.routes() {
            cx.reply(
                Numeric(364),
                format!(
                    "{} {} :{} {}",
                    route.name, server, route.hops, route.description
                ),
            );
        }
        for entry in cx.server.links.iter() {
            cx.reply(
                Numeric(364),
                format!("{} {} :1 peer", entry.value(), server),
            );
        }
        cx.reply(Numeric::RPL_ENDOFLINKS, "* :End of /LINKS list.");
        Ok(())
    })
}

fn cmd_wallops(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let text = cx.param(0).unwrap_or_default().to_owned();
        let mut message = Message::command("WALLOPS");
        message.prefix = Some(cx.mask());
        message.params.push(text);
        let recipients = cx
            .server
            .clients
            .iter()
            .filter(|entry| entry.value().session(|session| session.modes.wallops))
            .map(|entry| std::sync::Arc::clone(entry.value()))
            .collect::<Vec<_>>();
        cx.server.broadcast(recipients, &message, None);
        Ok(())
    })
}

fn cmd_compress(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let config = cx.server.cfg();
        let server = config.server.name.clone();
        let nick = cx.nick();
        if !config.compression.enabled {
            cx.server
                .notice(&cx.client, "COMPRESS is disabled on this server");
            return Ok(());
        }
        let method = cx.param(0).unwrap_or("zlib").to_ascii_lowercase();
        if method != "zlib" {
            cx.client.send_raw(
                &format!(":{server} NOTICE {nick} :COMPRESS UNKNOWN {method}"),
                cx.max_line(),
            );
            return Ok(());
        }
        if cx
            .client
            .compression
            .load(std::sync::atomic::Ordering::Acquire)
        {
            cx.server.notice(&cx.client, "COMPRESS is already enabled");
            return Ok(());
        }
        // The acknowledgement must be queued before the writer flips to
        // compressed framing, otherwise the peer cannot read it.
        cx.client.send_raw(
            &format!(":{server} NOTICE {nick} :COMPRESS zlib enabled"),
            cx.max_line(),
        );
        if !cx.client.enable_compression() {
            cx.server
                .notice(&cx.client, "COMPRESS could not be enabled");
        }
        Ok(())
    })
}

fn cmd_bench(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let config = cx.server.cfg();
        if !config.diagnostics.benchmarks {
            return Err(cx.fail(
                Numeric::ERR_UNKNOWNCOMMAND,
                "BENCH :Benchmarks are disabled in the configuration",
            ));
        }
        let iterations = cx
            .param(0)
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(20_000)
            .clamp(100, 2_000_000);
        let sample = ":alice!user@host PRIVMSG #channel :the quick brown fox jumps";

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = Message::parse(sample, 512);
        }
        let parse_time = start.elapsed();

        let casemap = cx.casemap();
        let start = Instant::now();
        let mut buffer = String::with_capacity(32);
        for _ in 0..iterations {
            casemap.fold_into("SomeNickname[1]", &mut buffer);
            buffer.clear();
        }
        let fold_time = start.elapsed();

        let parsed = Message::parse(sample, 512)
            .map_err(|error| cx.fail(Numeric::ERR_UNKNOWNCOMMAND, format!("BENCH :{error}")))?;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = parsed.to_bytes_limited(512);
        }
        let format_time = start.elapsed();

        cx.server.notice(
            &cx.client,
            &format!(
                "BENCH {iterations} iterations: parse {parse_time:?}, fold {fold_time:?}, format {format_time:?}"
            ),
        );
        Ok(())
    })
}

fn cmd_snomask(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let Some(argument) = cx.param(0).map(str::to_owned) else {
            let current = cx.client.session(|session| session.snomasks.letters());
            cx.server
                .notice(&cx.client, &format!("Current snomask is +{current}"));
            return Ok(());
        };
        let mut current = cx.client.session(|session| session.snomasks);
        let mut adding = true;
        for character in argument.chars() {
            match character {
                '+' => adding = true,
                '-' => adding = false,
                _ => {
                    let Some(bit) = Snomask::from_letters(&character.to_string()) else {
                        return Err(cx.fail(Numeric::ERR_UMODEUNKNOWNFLAG, ":Unknown SNOMASK flag"));
                    };
                    current = if adding {
                        current.union(bit)
                    } else {
                        current.difference(bit)
                    };
                }
            }
        }
        cx.client.session_mut(|session| {
            session.snomasks = current;
            session.modes.snomask = !current.is_empty();
        });
        let rendered = cx.client.session(|session| session.snomasks.letters());
        cx.server
            .notice(&cx.client, &format!("Snomask is now +{rendered}"));
        Ok(())
    })
}

fn cmd_globops(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let text = cx.param(0).unwrap_or_default().to_owned();
        let mut message = Message::command("GLOBOPS");
        message.prefix = Some(cx.mask());
        message.params.push(text.clone());
        cx.server
            .broadcast(cx.server.oper_recipients(), &message, None);
        // The origin server fans out to its own operators; every other server
        // does the same when the relay arrives, so one hop from this server is
        // enough for the whole tree.
        cx.server.propagate_link(&message);
        cx.server.snotice(
            Snomask::GLOBAL,
            &format!("GLOBOPS from {}: {text}", cx.nick()),
        );
        Ok(())
    })
}

fn cmd_samode(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let target = cx.param(0).unwrap_or_default().to_owned();
        if !is_channel_name(&target) {
            return Err(cx.fail(
                Numeric::ERR_USERSDONTMATCH,
                ":SAMODE only applies to channels",
            ));
        }
        let params = cx.msg.params[1..].to_vec();
        crate::commands::channel::samode(&cx, &target, &params)
    })
}

fn cmd_kline(cx: Cmd) -> CmdFuture {
    Box::pin(async move { add_server_ban(&cx, BanKind::Kline) })
}

fn cmd_gline(cx: Cmd) -> CmdFuture {
    Box::pin(async move { add_server_ban(&cx, BanKind::Gline) })
}

fn cmd_zline(cx: Cmd) -> CmdFuture {
    Box::pin(async move { add_server_ban(&cx, BanKind::Zline) })
}

fn cmd_shun(cx: Cmd) -> CmdFuture {
    Box::pin(async move { add_server_ban(&cx, BanKind::Shun) })
}

/// Add a ban, enforce it immediately and relay it when it is network-wide.
fn add_server_ban(cx: &Cmd, kind: BanKind) -> Result<(), CommandError> {
    let mask = cx.param(0).unwrap_or_default().trim().to_owned();
    if mask.is_empty() {
        return Err(cx.fail(
            Numeric::ERR_NEEDMOREPARAMS,
            format!("{} :Not enough parameters", kind.letter()),
        ));
    }
    let lifetime = parse_duration(cx.param(1).unwrap_or("0"))
        .map_err(|reason| cx.fail(Numeric::ERR_NEEDMOREPARAMS, format!(":{reason}")))?;
    let reason = cx.param(2).unwrap_or("No reason given").to_owned();
    let expires = lifetime.map(|seconds| now_unix().saturating_add(seconds));
    let ban = ServerBan::new(kind, &mask, &cx.nick(), expires, &reason);
    let is_new = cx.server.add_ban(ban.clone());
    if kind.is_global() {
        link::ban_added(&cx.server, &ban);
    }

    cx.server.snotice(
        Snomask::BAN,
        &format!(
            "{} {} added by {} ({}): {reason}",
            kind.name(),
            ban.mask,
            ban.set_by,
            describe_remaining(ban.remaining(now_unix()))
        ),
    );
    cx.server.notice(
        &cx.client,
        &format!(
            "{} on {} is now active ({})",
            kind.name(),
            ban.mask,
            describe_remaining(ban.remaining(now_unix()))
        ),
    );

    if kind.blocks_registration() || kind == BanKind::Shun {
        let casemap = cx.casemap();
        let _ = is_new;
        let now = now_unix();
        let matches = cx
            .server
            .clients
            .iter()
            .filter(|entry| entry.value().is_local())
            .filter(|entry| !entry.value().server_link)
            .filter(|entry| entry.key() != &cx.client.id)
            .filter(|entry| {
                let session = entry.value().session(|session| {
                    (
                        session.nick.clone().unwrap_or_default(),
                        session.user.clone().unwrap_or_default(),
                        session.host.clone(),
                        session.account.clone(),
                        session.registered,
                        session.realhost.clone(),
                    )
                });
                session.4
                    && !casemap.eq(&session.0, "")
                    && ban.active(now)
                    && ban.matches(
                        &session.0,
                        &session.1,
                        &session.2,
                        &session.5,
                        session.3.as_deref(),
                    )
            })
            .map(|entry| std::sync::Arc::clone(entry.value()))
            .collect::<Vec<_>>();
        for target in matches {
            if kind == BanKind::Shun {
                cx.server
                    .notice(&target, &format!("You have been silenced: {reason}"));
            } else {
                cx.server
                    .disconnect(&target, &format!("{}: {reason}", kind.name()));
            }
        }
    }
    Ok(())
}

fn cmd_unban(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let kind_text = cx.param(0).unwrap_or_default().to_owned();
        let Some(kind) = BanKind::parse(&kind_text) else {
            return Err(cx.fail(
                Numeric::ERR_UNKNOWNMODE,
                format!("{kind_text} :Unknown ban kind"),
            ));
        };
        let mask = cx.param(1).unwrap_or_default().to_owned();
        if !cx.server.remove_ban(kind, &mask) {
            return Err(cx.fail(Numeric::ERR_NOSUCHNICK, format!("{mask} :No such ban")));
        }
        if kind.is_global() {
            link::ban_removed(&cx.server, kind, &mask);
        }
        cx.server.snotice(
            Snomask::BAN,
            &format!("{} {} removed by {}", kind.name(), mask, cx.nick()),
        );
        cx.server
            .notice(&cx.client, &format!("{} {} removed", kind.name(), mask));
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_codes_keep_leading_zeroes() {
        assert_eq!(Numeric(364).to_string(), "364");
        assert_eq!(Numeric(5).to_string(), "005");
    }
}
