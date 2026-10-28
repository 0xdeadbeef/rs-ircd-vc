//! Operator and informational commands.

use std::time::Instant;

use crate::commands::{Access, Cmd, CmdFuture, CommandSpec};
use crate::config::OperFlag;
use crate::protocol::{Message, Numeric};
use crate::util::{iso8601, verify_password, wildcard_match};

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
    access: Access::Oper(OperFlag::Kill),
    handler: cmd_kill,
};

/// `REHASH` reloads the configuration.
pub const REHASH: CommandSpec = CommandSpec {
    name: "REHASH",
    min_params: 0,
    access: Access::Oper(OperFlag::Rehash),
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
    access: Access::Oper(OperFlag::Global),
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
    access: Access::Oper(OperFlag::Rehash),
    handler: cmd_bench,
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
        cx.client.session_mut(|session| {
            session.oper = Some(oper.name.clone());
            session.modes.oper = true;
        });
        cx.reply(Numeric::RPL_YOUREOPER, ":You are now an IRC operator");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_codes_keep_leading_zeroes() {
        assert_eq!(Numeric(364).to_string(), "364");
        assert_eq!(Numeric(5).to_string(), "005");
    }
}
