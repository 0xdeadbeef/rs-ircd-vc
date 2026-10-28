//! Registration handshake: `PASS`, `NICK`, `USER`, `CAP`, and keepalives.

use std::sync::Arc;

use base64::Engine as _;

use crate::auth::Credential;
use crate::commands::{valid_nickname, valid_username, Access, Cmd, CmdFuture, CommandSpec};
use crate::protocol::{Message, Numeric};
use crate::server::{link, CapSet, ClientHandle, SaslMechanism, SaslSession, Server};
use crate::util::{now_unix, secret_matches};

/// base64 characters a client may send in one `AUTHENTICATE` line.
const SASL_CHUNK: usize = 400;
/// Ceiling on the reassembled base64 payload.
// MARK: security: high: SEC-SASL-001: the reassembled payload is capped before decoding.
const SASL_MAX_PAYLOAD: usize = 8192;

/// `PASS` sets the connection password.
pub const PASS: CommandSpec = CommandSpec {
    name: "PASS",
    min_params: 1,
    access: Access::Unregistered,
    handler: cmd_pass,
};

/// `NICK` chooses or changes the nickname.
pub const NICK: CommandSpec = CommandSpec {
    name: "NICK",
    min_params: 1,
    access: Access::Unregistered,
    handler: cmd_nick,
};

/// `USER` supplies the username and real name.
pub const USER: CommandSpec = CommandSpec {
    name: "USER",
    min_params: 4,
    access: Access::Unregistered,
    handler: cmd_user,
};

/// `CAP` negotiates IRCv3 capabilities.
pub const CAP: CommandSpec = CommandSpec {
    name: "CAP",
    min_params: 1,
    access: Access::Unregistered,
    handler: cmd_cap,
};

/// `AUTHENTICATE` performs a SASL exchange.
pub const AUTHENTICATE: CommandSpec = CommandSpec {
    name: "AUTHENTICATE",
    min_params: 1,
    access: Access::Unregistered,
    handler: cmd_authenticate,
};

/// `LOGOUT` ends the SASL session started after registration.
pub const LOGOUT: CommandSpec = CommandSpec {
    name: "LOGOUT",
    min_params: 0,
    access: Access::Registered,
    handler: cmd_logout,
};

/// `QUIT` ends the session.
pub const QUIT: CommandSpec = CommandSpec {
    name: "QUIT",
    min_params: 0,
    access: Access::Unregistered,
    handler: cmd_quit,
};

/// `PING` asks the server to confirm liveness.
pub const PING: CommandSpec = CommandSpec {
    name: "PING",
    min_params: 0,
    access: Access::Unregistered,
    handler: cmd_ping,
};

/// `PONG` answers a keepalive.
pub const PONG: CommandSpec = CommandSpec {
    name: "PONG",
    min_params: 0,
    access: Access::Unregistered,
    handler: cmd_pong,
};

fn cmd_pass(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        if cx.client.is_registered() {
            return Err(cx.fail(Numeric::ERR_ALREADYREGISTRED, ":You may not reregister"));
        }
        let expected = cx.server.cfg().connection_password();
        let supplied = cx.param(0).unwrap_or_default();
        // MARK: security: high: SEC-PASS-001: the connection password is compared by digest.
        let accepted = match &expected {
            Some(password) => secret_matches(password, supplied),
            None => true,
        };
        cx.client.session_mut(|session| session.pass_ok = accepted);
        if accepted {
            Ok(())
        } else {
            Err(cx.fail(Numeric::ERR_PASSWDMISMATCH, ":Password incorrect"))
        }
    })
}

fn cmd_nick(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let requested = cx
            .param(0)
            .ok_or_else(|| cx.fail(Numeric::ERR_NONICKNAMEGIVEN, ":No nickname given"))?
            .to_owned();
        let config = cx.server.cfg();
        if !valid_nickname(&requested, config.server.max_nick_length) {
            return Err(cx.fail(
                Numeric::ERR_ERRONEUSNICKNAME,
                format!("{requested} :Erroneous nickname"),
            ));
        }
        let casemap = config.server.casemapping;
        let previous = cx.client.nick();
        if previous.as_deref() == Some(requested.as_str()) {
            return Ok(());
        }

        let new_folded = casemap.fold(&requested);
        let case_change = previous
            .as_deref()
            .is_some_and(|old| casemap.fold(old) == new_folded);

        if !case_change && !cx.server.reserve_nick(&requested, cx.client.id) {
            return Err(cx.fail(
                Numeric::ERR_NICKNAMEINUSE,
                format!("{requested} :Nickname is already in use"),
            ));
        }

        let previous_mask = cx.client.mask();
        cx.client
            .session_mut(|session| session.nick = Some(requested.clone()));
        if !case_change {
            if let Some(old) = &previous {
                cx.server.release_nick(old);
            }
        }

        if cx.client.is_registered() {
            let mut message = Message::command("NICK");
            message.prefix = Some(previous_mask.clone());
            message.params.push(requested.clone());
            let account = cx.client.session(|session| session.account.clone());
            match account.as_deref() {
                Some(account) => cx.server.broadcast_common_with_account(
                    &cx.client,
                    &message,
                    Some(cx.client.id),
                    account,
                ),
                None => cx
                    .server
                    .broadcast_common(&cx.client, &message, Some(cx.client.id)),
            }
            // The actor is also a recipient of its own change, so the echo
            // follows the same capability rule as any other event.
            let mut echo = message.clone();
            if let Some(account) = account.as_deref() {
                if cx.client.has_cap(CapSet::ACCOUNT_TAG) {
                    echo.push_tag("account", account);
                }
            }
            cx.client.send(&echo, cx.max_line());
            link::propagate_nick(&cx.server, &cx.client, &requested, &previous_mask);
        } else {
            try_register(&cx.server, &cx.client);
        }
        Ok(())
    })
}

fn cmd_user(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        if cx.client.is_registered() {
            return Err(cx.fail(Numeric::ERR_ALREADYREGISTRED, ":You may not reregister"));
        }
        let username = cx.param(0).unwrap_or_default();
        let realname = cx.param(3).unwrap_or_default();
        if !valid_username(username) {
            return Err(cx.fail(Numeric::ERR_NEEDMOREPARAMS, "USER :Invalid username"));
        }
        let realname = realname.chars().take(200).collect::<String>();
        cx.client.session_mut(|session| {
            session.user = Some(username.to_owned());
            session.realname = Some(realname);
        });
        try_register(&cx.server, &cx.client);
        Ok(())
    })
}

fn cmd_cap(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let subcommand = cx.param(0).unwrap_or_default().to_ascii_uppercase();
        match subcommand.as_str() {
            "LS" => {
                let tokens = cap_tokens(&cx.server);
                send_cap_list(&cx, "LS", &tokens);
            }
            "LIST" => {
                let tokens = cx
                    .client
                    .caps()
                    .enabled_names()
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                send_cap_list(&cx, "LIST", &tokens);
            }
            "REQ" => {
                let requested = cx.param(1).unwrap_or_default();
                let mut enable = CapSet::default();
                let mut disable = CapSet::default();
                let mut accepted = Vec::new();
                for token in requested.split(' ').filter(|token| !token.is_empty()) {
                    let (removing, name) = match token.strip_prefix('-') {
                        Some(rest) => (true, rest),
                        None => (false, token),
                    };
                    let Some(capability) = CapSet::from_name(name) else {
                        cap_reply(&cx, "NAK", requested, false);
                        return Ok(());
                    };
                    if capability == CapSet::SASL && cx.server.sasl_mechanisms().is_empty() {
                        cap_reply(&cx, "NAK", requested, false);
                        return Ok(());
                    }
                    if removing {
                        disable.insert(capability);
                    } else {
                        enable.insert(capability);
                    }
                    accepted.push(token.to_owned());
                }
                cx.client.enable_caps(enable);
                cx.client.disable_caps(disable);
                cap_reply(&cx, "ACK", &accepted.join(" "), false);
            }
            "END" => {
                if !cx.client.is_registered() {
                    try_register(&cx.server, &cx.client);
                }
            }
            other => {
                return Err(cx.fail(
                    Numeric::ERR_INVALIDCAPCMD,
                    format!("{other} :Invalid CAP command"),
                ));
            }
        }
        Ok(())
    })
}

/// `LOGOUT` clears the account and tells the network.
///
/// The relay happens before the reply: `account_changed` sends `ACCOUNT *`,
/// which is the same message a login sends with a name, so a linked server
/// clears the shadow exactly as it set it.
fn cmd_logout(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let had_account = cx.client.session(|session| session.account.is_some());
        cx.client.session_mut(|session| {
            session.account = None;
            session.sasl = None;
        });
        if had_account {
            link::account_changed(&cx.server, &cx.client);
        }
        cx.reply(
            Numeric::RPL_LOGGEDOUT,
            format!("{} :You are now logged out", cx.mask()),
        );
        tracing::info!(nick = %cx.nick(), "sasl logout");
        Ok(())
    })
}

fn cmd_authenticate(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let available = cx.server.sasl_mechanisms();
        if available.is_empty() {
            return Err(cx.fail(
                Numeric::ERR_SASLFAIL,
                ":SASL authentication is not available",
            ));
        }
        let token = cx.param(0).unwrap_or_default();
        if token == "*" {
            cx.client.session_mut(|session| session.sasl = None);
            return Err(cx.fail(Numeric::ERR_SASLABORTED, ":SASL authentication aborted"));
        }

        let Some(mut state) = cx.client.session(|session| session.sasl.clone()) else {
            let selected = SaslMechanism::parse(token)
                .filter(|mechanism| available.contains(&mechanism.as_str()));
            let Some(mechanism) = selected else {
                cx.reply(
                    Numeric::RPL_SASLMECHS,
                    format!("{} :are available SASL mechanisms", available.join(",")),
                );
                return Err(cx.fail(Numeric::ERR_SASLFAIL, ":SASL authentication failed"));
            };
            cx.client.session_mut(|session| {
                session.sasl = Some(SaslSession {
                    mechanism,
                    payload: String::with_capacity(256),
                });
            });
            cx.client.send_raw("AUTHENTICATE +", cx.max_line());
            return Ok(());
        };

        // `+` carries no data, and anything shorter than a full chunk is the
        // final piece: the spec splits the blob into 400-character chunks and
        // pads the last one.
        if token != "+" {
            state.payload.push_str(token);
        }
        if state.payload.len() > SASL_MAX_PAYLOAD {
            cx.client.session_mut(|session| session.sasl = None);
            return Err(cx.fail(Numeric::ERR_SASLTOOLONG, ":SASL message too long"));
        }
        if token.len() == SASL_CHUNK {
            cx.client.session_mut(|session| session.sasl = Some(state));
            return Ok(());
        }

        let mechanism = state.mechanism;
        cx.client.session_mut(|session| session.sasl = None);
        let account = decode_payload(&state.payload)
            .and_then(|payload| verify_payload(&cx.server, &cx.client, mechanism, &payload));
        let Some(account) = account else {
            return Err(cx.fail(Numeric::ERR_SASLFAIL, ":SASL authentication failed"));
        };

        let mask = cx.mask();
        cx.client
            .session_mut(|session| session.account = Some(account.clone()));
        // A user who was already visible keeps their account current on the
        // other servers; before registration the introduction carries it.
        crate::server::link::account_changed(&cx.server, &cx.client);
        cx.reply(
            Numeric::RPL_LOGGEDIN,
            format!("{mask} {account} :You are now logged in as {account}"),
        );
        cx.reply(Numeric::RPL_SASLSUCCESS, ":SASL authentication successful");
        tracing::info!(
            nick = %cx.nick(),
            account = %account,
            mechanism = mechanism.as_str(),
            "sasl authenticated"
        );

        if !cx.client.is_registered() {
            try_register(&cx.server, &cx.client);
        }
        Ok(())
    })
}

/// Decode one base64 SASL blob into its text payload.
fn decode_payload(encoded: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// Verify a decoded SASL payload against the account backend.
fn verify_payload(
    server: &Server,
    client: &ClientHandle,
    mechanism: SaslMechanism,
    payload: &str,
) -> Option<String> {
    let backend = server.accounts();
    match mechanism {
        SaslMechanism::Plain => {
            // `PLAIN` is `authzid NUL authcid NUL passwd`; the password may be
            // empty only if the account stores an empty hash, so the field
            // count is what distinguishes a malformed blob.
            let mut fields = payload.split('\0');
            let authzid = fields.next()?;
            let account = fields.next()?;
            let password = fields.next()?;
            if fields.next().is_some() || account.is_empty() {
                return None;
            }
            if !authzid.is_empty() && !authzid.eq_ignore_ascii_case(account) {
                return None;
            }
            backend.verify(&Credential::Plain { account, password })
        }
        SaslMechanism::External => {
            let fingerprint = client.certificate()?;
            let authzid = (!payload.is_empty()).then_some(payload);
            backend.verify(&Credential::External {
                account: authzid,
                fingerprint,
            })
        }
    }
}

fn cmd_quit(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let reason = cx.param(0).unwrap_or("Client Quit");
        let reason = format!("Quit: {}", reason.chars().take(200).collect::<String>());
        cx.server.disconnect(&cx.client, &reason);
        Ok(())
    })
}

fn cmd_ping(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        let token = cx
            .param(0)
            .ok_or_else(|| cx.fail(Numeric::ERR_NOORIGIN, ":No origin specified"))?;
        let server = cx.server.name();
        cx.client
            .send_raw(&format!(":{server} PONG {server} :{token}"), cx.max_line());
        Ok(())
    })
}

fn cmd_pong(cx: Cmd) -> CmdFuture {
    Box::pin(async move {
        // Activity timestamps are updated by the dispatcher; the payload is
        // informational only.
        let _ = cx.param(0);
        Ok(())
    })
}

fn cap_reply(cx: &Cmd, subcommand: &str, list: &str, more: bool) {
    let server = cx.server.name();
    let nick = cx.nick();
    let marker = if more { " *" } else { "" };
    let line = if list.is_empty() {
        format!(":{server} CAP {nick} {subcommand}{marker} :")
    } else {
        format!(":{server} CAP {nick} {subcommand}{marker} :{list}")
    };
    cx.client.send_raw(&line, cx.max_line());
}

/// Advertised capabilities with their values, e.g. `sasl=PLAIN,EXTERNAL`.
fn cap_tokens(server: &Server) -> Vec<String> {
    let mechanisms = server.sasl_mechanisms();
    CapSet::TABLE
        .iter()
        .filter_map(|(name, capability)| {
            if *capability == CapSet::SASL {
                return (!mechanisms.is_empty()).then(|| format!("sasl={}", mechanisms.join(",")));
            }
            Some((*name).to_owned())
        })
        .collect()
}

/// Send a capability list, splitting it across replies with the `*`
/// continuation marker so no line exceeds the 512-byte wire limit.
fn send_cap_list(cx: &Cmd, subcommand: &str, tokens: &[String]) {
    const CHUNK: usize = 400;
    let mut current = String::new();
    for token in tokens {
        if !current.is_empty() && current.len() + token.len() + 1 > CHUNK {
            cap_reply(cx, subcommand, &current, true);
            current.clear();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(token);
    }
    cap_reply(cx, subcommand, &current, false);
}

/// Complete registration once `NICK` and `USER` are both present.
///
/// Returns `true` when the connection became a registered user.
pub fn try_register(server: &Arc<Server>, client: &Arc<ClientHandle>) -> bool {
    if client.is_registered() {
        return false;
    }
    let ready = client.session(|session| session.nick.is_some() && session.user.is_some());
    if !ready {
        return false;
    }
    let config = server.cfg();
    // MARK: policy: high: POL-REG-001: SASL and connection passwords are both enforced before 001.
    if config.sasl.require && client.session(|session| session.account.is_none()) {
        server.numeric(
            client,
            Numeric::ERR_SASLFAIL,
            ":SASL authentication is required before registration",
        );
        return false;
    }
    if config.connection_password().is_some() && !client.session(|session| session.pass_ok) {
        server.numeric(client, Numeric::ERR_PASSWDMISMATCH, ":Password incorrect");
        client.request_close();
        return false;
    }
    let signon = now_unix();
    client.session_mut(|session| {
        session.registered = true;
        session.signon = signon;
        session.ts = signon;
    });

    let name = config.server.name.clone();
    let network = config.server.network.clone();
    let nick = client.nick_or_star();
    let mask = client.mask();
    let created = crate::util::iso8601(server.started);

    server.numeric(
        client,
        Numeric::RPL_WELCOME,
        format!(":Welcome to the {network} IRC Network {mask}"),
    );
    server.numeric(
        client,
        Numeric::RPL_YOURHOST,
        format!(
            ":Your host is {name}, running version rs-ircd-{}",
            env!("CARGO_PKG_VERSION")
        ),
    );
    server.numeric(
        client,
        Numeric::RPL_CREATED,
        format!(":This server was created {created}"),
    );
    server.numeric(
        client,
        Numeric::RPL_MYINFO,
        format!(
            "{name} rs-ircd-{} iow ovbklmnpstRe",
            env!("CARGO_PKG_VERSION")
        ),
    );
    let tokens = server.isupport_tokens().join(" ");
    server.numeric(
        client,
        Numeric::RPL_ISUPPORT,
        format!("{tokens} :are supported by this server"),
    );

    server.numeric(
        client,
        Numeric::RPL_LUSERCLIENT,
        format!(
            ":There are {} users and 0 invisible on 1 servers",
            server.local_clients()
        ),
    );
    let opers = server.oper_count();
    if opers > 0 {
        server.numeric(
            client,
            Numeric::RPL_LUSEROP,
            format!("{opers} :operator(s) online"),
        );
    }
    server.numeric(
        client,
        Numeric::RPL_LUSERCHANNELS,
        format!("{} :channels formed", server.channel_count()),
    );
    server.numeric(
        client,
        Numeric::RPL_LUSERME,
        format!(":I have {} clients and 0 servers", server.local_clients()),
    );
    let local = server.local_clients();
    server.numeric(
        client,
        Numeric::RPL_LOCALUSERS,
        format!(
            "{local} {} :Current local users {local}, max {local}",
            local
        ),
    );
    server.numeric(
        client,
        Numeric::RPL_GLOBALUSERS,
        format!(
            "{local} {} :Current global users {local}, max {local}",
            local
        ),
    );

    let motd = server.motd();
    if motd.is_empty() {
        server.numeric(client, Numeric::ERR_NOMOTD, ":MOTD File is missing");
    } else {
        server.numeric(
            client,
            Numeric::RPL_MOTDSTART,
            format!(":- {name} Message of the day -"),
        );
        for line in motd {
            server.numeric(client, Numeric::RPL_MOTD, format!(":- {line}"));
        }
        server.numeric(client, Numeric::RPL_ENDOFMOTD, ":End of /MOTD command.");
    }

    if let Some(outcome) = server.hook_event("connect", client, &Message::command("CONNECT")) {
        for line in outcome.lines {
            client.send_raw(&line, server.max_line());
        }
    }
    link::introduce(server, client);

    tracing::info!(id = client.id, nick = %nick, "client registered");
    true
}
