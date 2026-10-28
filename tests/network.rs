//! End-to-end tests that speak the wire protocol over TCP.
//!
//! Each test starts its own server on an ephemeral loopback port, so tests are
//! independent and can run in parallel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ircd::auth::{AccountBackend, Credential};
use ircd::config::{Config, ListenSection};
use ircd::net;
use ircd::server::Server;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

/// A raw IRC client used by the tests.
struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    seen: Vec<String>,
}

impl Client {
    async fn connect(address: SocketAddr) -> Self {
        let stream = TcpStream::connect(address).await.expect("connect");
        stream.set_nodelay(true).expect("nodelay");
        let (read, write) = stream.into_split();
        Self {
            reader: BufReader::new(read),
            writer: write,
            seen: Vec::new(),
        }
    }

    async fn send(&mut self, line: impl AsRef<str>) {
        let mut payload = line.as_ref().as_bytes().to_vec();
        payload.extend_from_slice(b"\r\n");
        self.writer.write_all(&payload).await.expect("write");
    }

    /// Read lines until one contains `needle`.
    async fn expect(&mut self, needle: &str) -> String {
        for _ in 0..100 {
            let mut line = String::new();
            let read =
                tokio::time::timeout(Duration::from_secs(3), self.reader.read_line(&mut line))
                    .await
                    .unwrap_or_else(|_| {
                        panic!("timed out waiting for {needle:?}; saw {:?}", self.seen)
                    })
                    .expect("read");
            assert_ne!(read, 0, "connection closed waiting for {needle:?}");
            let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
            if trimmed.contains(needle) {
                return trimmed;
            }
            self.seen.push(trimmed);
        }
        panic!("never saw {needle:?}; saw {:?}", self.seen);
    }

    async fn register(&mut self, nick: &str) {
        self.send(format!("NICK {nick}")).await;
        self.send(format!("USER {nick} 0 * :{nick} real")).await;
        self.expect(" 001 ").await;
    }

    /// Ask `WHOIS` and return the `330` account line, when one is sent.
    async fn whois_account(&mut self, nick: &str) -> Option<String> {
        self.send(format!("WHOIS {nick}")).await;
        let mut account = None;
        for _ in 0..60 {
            let line = self.expect_any().await;
            if line.contains(" 318 ") {
                return account;
            }
            if line.contains(" 330 ") {
                account = Some(line);
            }
        }
        panic!("WHOIS {nick} never finished; saw {:?}", self.seen);
    }

    /// Read one line without matching anything.
    async fn expect_any(&mut self) -> String {
        let mut line = String::new();
        let read = tokio::time::timeout(Duration::from_secs(3), self.reader.read_line(&mut line))
            .await
            .unwrap_or_else(|_| panic!("timed out reading a line; saw {:?}", self.seen))
            .expect("read");
        assert_ne!(read, 0, "connection closed; saw {:?}", self.seen);
        line.trim_end_matches(['\r', '\n']).to_owned()
    }

    async fn close(mut self) {
        let _ = self.writer.shutdown().await;
    }
}

fn base_config() -> Config {
    let mut config = Config::default();
    config.server.name = "irc.test".to_owned();
    config.server.network = "TestNet".to_owned();
    config.server.description = "test server".to_owned();
    config.listen.push(ListenSection {
        addresses: vec!["127.0.0.1".parse().expect("ipv4")],
        port: 0,
        tls: false,
        server_link: false,
    });
    config
}

async fn start(config: Config) -> (Arc<Server>, SocketAddr) {
    let config = Arc::new(config);
    let server = Server::new(Arc::clone(&config), None).expect("server state");
    let listeners = net::bind(&config).expect("bind");
    let address = listeners[0].local;
    for listener in listeners {
        net::spawn_accept_loop(Arc::clone(&server), listener);
    }
    (server, address)
}

/// Account backend standing in for an external directory service.
#[derive(Debug)]
struct FixedAccounts {
    password: String,
}

impl AccountBackend for FixedAccounts {
    fn name(&self) -> &'static str {
        "test"
    }

    fn mechanisms(&self) -> &'static [&'static str] {
        &["PLAIN"]
    }

    fn verify(&self, credential: &Credential<'_>) -> Option<String> {
        match credential {
            Credential::Plain { account, password }
                if *account == "alice" && *password == self.password =>
            {
                Some((*account).to_owned())
            }
            Credential::Plain { .. } | Credential::External { .. } => None,
        }
    }
}

fn base64_encode(payload: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(payload)
}

#[tokio::test]
async fn registration_sends_welcome_and_isupport() {
    let (_server, address) = start(base_config()).await;
    let mut client = Client::connect(address).await;
    client.send("NICK alice").await;
    client.send("USER alice 0 * :Alice").await;
    let welcome = client.expect(" 001 ").await;
    assert!(welcome.contains("alice"), "welcome was {welcome:?}");
    let isupport = client.expect(" 005 ").await;
    assert!(
        isupport.contains("CHANTYPES=#&"),
        "isupport was {isupport:?}"
    );
    assert!(isupport.contains("CASEMAPPING=rfc1459"));
    client.expect(" 376 ").await;
    client.close().await;
}

#[tokio::test]
async fn direct_messages_reach_the_recipient() {
    let (_server, address) = start(base_config()).await;
    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    let mut bob = Client::connect(address).await;
    bob.register("bob").await;

    alice.send("PRIVMSG bob :hello bob").await;
    let delivered = bob.expect("PRIVMSG bob :hello bob").await;
    assert!(delivered.starts_with(":alice!alice@"), "got {delivered:?}");
    alice.close().await;
    bob.close().await;
}

#[tokio::test]
async fn channel_membership_and_broadcast() {
    let (_server, address) = start(base_config()).await;
    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    let mut bob = Client::connect(address).await;
    bob.register("bob").await;

    alice.send("JOIN #test").await;
    alice.expect("JOIN #test").await;
    let names = alice.expect(" 353 ").await;
    assert!(names.contains("@alice"), "names were {names:?}");
    alice.expect(" 366 ").await;

    bob.send("JOIN #test").await;
    bob.expect("JOIN #test").await;
    let seen_by_alice = alice.expect("bob").await;
    assert!(
        seen_by_alice.contains("JOIN #test"),
        "got {seen_by_alice:?}"
    );

    bob.send("PRIVMSG #test :hi everyone").await;
    alice.expect("PRIVMSG #test :hi everyone").await;

    // The second joiner is not an operator, so MODE must be refused.
    bob.send("MODE #test +m").await;
    bob.expect(" 482 ").await;

    alice.send("MODE #test +m").await;
    alice.expect("MODE #test +m").await;
    bob.send("PRIVMSG #test :should be blocked").await;
    bob.expect(" 404 ").await;

    alice.close().await;
    bob.close().await;
}

#[tokio::test]
async fn nick_changes_and_quits_are_announced() {
    let (_server, address) = start(base_config()).await;
    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    let mut bob = Client::connect(address).await;
    bob.register("bob").await;

    alice.send("JOIN #room").await;
    alice.expect("JOIN #room").await;
    bob.send("JOIN #room").await;
    bob.expect("JOIN #room").await;
    alice.expect("bob").await;

    bob.send("NICK robert").await;
    let rename = alice.expect("NICK robert").await;
    assert!(rename.contains(":bob!"), "rename was {rename:?}");

    bob.send("QUIT :bye now").await;
    alice.expect("QUIT :Quit: bye now").await;
    alice.close().await;
}

#[tokio::test]
async fn topic_and_ban_list_round_trip() {
    let (_server, address) = start(base_config()).await;
    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    alice.send("JOIN #ops").await;
    alice.expect(" 366 ").await;

    alice.send("TOPIC #ops :release planning").await;
    alice.expect("TOPIC #ops :release planning").await;
    alice.send("TOPIC #ops").await;
    let topic = alice.expect(" 332 ").await;
    assert!(topic.contains("release planning"), "topic was {topic:?}");

    alice.send("MODE #ops +b *!*@bad.example").await;
    alice.expect("MODE #ops +b").await;
    alice.send("MODE #ops +b").await;
    let ban = alice.expect(" 367 ").await;
    assert!(ban.contains("*!*@bad.example"), "ban list was {ban:?}");
    alice.expect(" 368 ").await;
    alice.close().await;
}

#[tokio::test]
async fn compression_is_acknowledged() {
    let (_server, address) = start(base_config()).await;
    let mut client = Client::connect(address).await;
    client.register("alice").await;
    client.send("COMPRESS zlib").await;
    let ack = client.expect("COMPRESS zlib enabled").await;
    assert!(ack.contains("NOTICE alice"), "ack was {ack:?}");
    client.close().await;
}

#[tokio::test]
async fn sasl_plain_authenticates_and_registers() {
    let (server, address) = start(base_config()).await;
    server.set_account_backend(Arc::new(FixedAccounts {
        password: "hunter2".to_owned(),
    }));

    let mut client = Client::connect(address).await;
    client.send("CAP LS 302").await;
    let listing = client.expect("CAP * LS").await;
    assert!(
        listing.contains("sasl=PLAIN"),
        "sasl was not advertised with its mechanisms: {listing:?}"
    );

    client.send("CAP REQ :sasl").await;
    client.expect("CAP * ACK :sasl").await;
    client.send("AUTHENTICATE PLAIN").await;
    client.expect("AUTHENTICATE +").await;
    client
        .send(format!(
            "AUTHENTICATE {}",
            base64_encode(b"\0alice\0hunter2")
        ))
        .await;
    // SASL runs before NICK, so the welcome mask is still `*!*@host` here.
    let logged_in = client.expect(" 900 ").await;
    assert!(
        logged_in.contains(" alice :You are now logged in as alice"),
        "900 was {logged_in:?}"
    );
    client.expect(" 903 ").await;

    client.send("CAP END").await;
    client.send("NICK alice").await;
    client.send("USER alice 0 * :Alice").await;
    client.expect(" 001 ").await;
    client.close().await;
}

#[tokio::test]
async fn sasl_plain_rejects_bad_credentials() {
    let (server, address) = start(base_config()).await;
    server.set_account_backend(Arc::new(FixedAccounts {
        password: "hunter2".to_owned(),
    }));

    let mut client = Client::connect(address).await;
    client.send("AUTHENTICATE PLAIN").await;
    client.expect("AUTHENTICATE +").await;
    client
        .send(format!("AUTHENTICATE {}", base64_encode(b"\0alice\0wrong")))
        .await;
    client.expect(" 904 ").await;

    // An unknown mechanism must list what is available instead of guessing.
    client.send("AUTHENTICATE SCRAM-SHA-256").await;
    let mechanisms = client.expect(" 908 ").await;
    assert!(mechanisms.contains("PLAIN"), "908 was {mechanisms:?}");
    client.close().await;
}

/// Backend with a fixed account table for the channel-access tests.
#[derive(Debug)]
struct TwoAccounts;

impl AccountBackend for TwoAccounts {
    fn name(&self) -> &'static str {
        "test-twice"
    }

    fn mechanisms(&self) -> &'static [&'static str] {
        &["PLAIN"]
    }

    fn verify(&self, credential: &Credential<'_>) -> Option<String> {
        match credential {
            Credential::Plain { account, password } => match (*account, *password) {
                ("alice", "hunter2") | ("bob", "hunter3") => Some((*account).to_owned()),
                _ => None,
            },
            Credential::External { .. } => None,
        }
    }
}

/// Authenticate an already-connected client with SASL `PLAIN`.
async fn authenticate(client: &mut Client, account: &str, password: &str) {
    client.send("AUTHENTICATE PLAIN").await;
    client.expect("AUTHENTICATE +").await;
    let payload = base64_encode(format!("\0{account}\0{password}").as_bytes());
    client.send(format!("AUTHENTICATE {payload}")).await;
    client.expect(" 903 ").await;
}

async fn register_with_sasl(client: &mut Client, nick: &str, password: &str) {
    authenticate(client, nick, password).await;
    client.register(nick).await;
}

#[tokio::test]
async fn account_only_channels_reject_unauthenticated_clients() {
    let (server, address) = start(base_config()).await;
    server.set_account_backend(Arc::new(TwoAccounts));

    let mut alice = Client::connect(address).await;
    register_with_sasl(&mut alice, "alice", "hunter2").await;
    alice.send("JOIN #secure").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #secure -n").await;
    alice.expect("MODE #secure -n").await;
    alice.send("MODE #secure +R").await;
    alice.expect("MODE #secure +R").await;

    let mut bob = Client::connect(address).await;
    bob.register("bob").await;
    bob.send("JOIN #secure").await;
    let refused = bob.expect(" 477 ").await;
    assert!(
        refused.contains("+R"),
        "join refusal did not mention +R: {refused:?}"
    );

    // Authenticating after registration satisfies the mode as well.
    authenticate(&mut bob, "bob", "hunter3").await;
    bob.send("JOIN #secure").await;
    bob.expect("JOIN #secure").await;

    // Speaking is account-only too, and `-n` lets outsiders reach the check.
    let mut carol = Client::connect(address).await;
    carol.register("carol").await;
    carol.send("PRIVMSG #secure :hello").await;
    let denied = carol.expect(" 404 ").await;
    assert!(
        denied.contains("+R"),
        "message refusal did not mention +R: {denied:?}"
    );
}

#[tokio::test]
async fn account_ban_exceptions_allow_matching_accounts() {
    let (server, address) = start(base_config()).await;
    server.set_account_backend(Arc::new(TwoAccounts));

    let mut alice = Client::connect(address).await;
    register_with_sasl(&mut alice, "alice", "hunter2").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #room +b $a:bob").await;
    alice.expect("MODE #room +b $a:bob").await;

    let mut bob = Client::connect(address).await;
    register_with_sasl(&mut bob, "bob", "hunter3").await;
    bob.send("JOIN #room").await;
    let banned = bob.expect(" 474 ").await;
    assert!(banned.contains("+b"), "ban refusal was {banned:?}");

    alice.send("MODE #room +e $a:bob").await;
    alice.expect("MODE #room +e $a:bob").await;
    alice.send("MODE #room +e").await;
    let listing = alice.expect(" 348 ").await;
    assert!(listing.contains("$a:bob"), "exception list was {listing:?}");
    alice.expect(" 349 ").await;

    bob.send("JOIN #room").await;
    bob.expect("JOIN #room").await;
}

#[tokio::test]
async fn account_tag_reaches_only_capable_recipients() {
    let (server, address) = start(base_config()).await;
    server.set_account_backend(Arc::new(TwoAccounts));

    let mut alice = Client::connect(address).await;
    register_with_sasl(&mut alice, "alice", "hunter2").await;

    let mut bob = Client::connect(address).await;
    bob.send("CAP LS 302").await;
    let listing = bob.expect("CAP * LS").await;
    assert!(
        listing.contains("account-tag"),
        "account-tag was not advertised: {listing:?}"
    );
    bob.send("CAP REQ :account-tag").await;
    bob.expect("CAP * ACK :account-tag").await;
    bob.send("CAP END").await;
    bob.register("bob").await;

    let mut carol = Client::connect(address).await;
    carol.register("carol").await;

    alice.send("PRIVMSG bob :tagged hello").await;
    let tagged = bob.expect("PRIVMSG bob :tagged hello").await;
    assert!(
        tagged.starts_with("@account=alice "),
        "tagged delivery was {tagged:?}"
    );

    // A client that did not ask for the capability must not see the tag.
    alice.send("PRIVMSG carol :plain hello").await;
    let plain = carol.expect("PRIVMSG carol :plain hello").await;
    assert!(!plain.contains("account="), "untagged was {plain:?}");

    // The same holds for channel traffic.
    alice.send("JOIN #tagged").await;
    alice.expect(" 366 ").await;
    bob.send("JOIN #tagged").await;
    bob.expect(" 366 ").await;
    alice.send("PRIVMSG #tagged :hello room").await;
    let channel = bob.expect("PRIVMSG #tagged :hello room").await;
    assert!(
        channel.starts_with("@account=alice "),
        "channel delivery was {channel:?}"
    );

    // An unauthenticated sender has no account to advertise.
    bob.send("PRIVMSG carol :from bob").await;
    let from_bob = carol.expect("PRIVMSG carol :from bob").await;
    assert!(!from_bob.contains("account="), "got {from_bob:?}");
}

#[tokio::test]
async fn sasl_logout_clears_the_account() {
    let (server, address) = start(base_config()).await;
    server.set_account_backend(Arc::new(TwoAccounts));

    let mut alice = Client::connect(address).await;
    register_with_sasl(&mut alice, "alice", "hunter2").await;
    alice.send("JOIN #secure").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #secure +R").await;
    alice.expect("MODE #secure +R").await;

    let mut watcher = Client::connect(address).await;
    watcher.register("watcher").await;
    assert!(
        watcher.whois_account("alice").await.is_some(),
        "the account should be visible before logging out"
    );

    alice.send("LOGOUT").await;
    let line = alice.expect(" 901 ").await;
    assert!(line.contains("logged out"), "901 was {line:?}");
    assert!(
        watcher.whois_account("alice").await.is_none(),
        "the account must be gone after LOGOUT"
    );

    // Membership survives, but speaking in an account-only channel does not.
    alice.send("PRIVMSG #secure :still here?").await;
    let denied = alice.expect(" 404 ").await;
    assert!(denied.contains("+R"), "404 was {denied:?}");

    // Logging in again restores the account, so the state is not one-way.
    authenticate(&mut alice, "alice", "hunter2").await;
    assert!(watcher.whois_account("alice").await.is_some());
    alice.send("PRIVMSG #secure :back again").await;
    alice.send("WHOIS alice").await;
    alice.expect(" 318 ").await;
}

#[tokio::test]
async fn client_tags_reach_only_capable_recipients() {
    let (_server, address) = start(base_config()).await;

    let mut alice = Client::connect(address).await;
    alice.send("CAP LS 302").await;
    let listing = alice.expect("CAP * LS").await;
    assert!(
        listing.contains("message-tags"),
        "message-tags was not advertised: {listing:?}"
    );
    alice.send("CAP REQ :message-tags").await;
    alice.expect("CAP * ACK :message-tags").await;
    alice.send("CAP END").await;
    alice.register("alice").await;

    let mut bob = Client::connect(address).await;
    bob.send("CAP REQ :message-tags").await;
    bob.expect("CAP * ACK :message-tags").await;
    bob.send("CAP END").await;
    bob.register("bob").await;

    let mut carol = Client::connect(address).await;
    carol.register("carol").await;

    alice.send("@+example=hello PRIVMSG bob :tagged").await;
    let tagged = bob.expect("PRIVMSG bob tagged").await;
    assert!(
        tagged.starts_with("@+example=hello "),
        "tagged delivery was {tagged:?}"
    );

    // A client that did not negotiate the capability must not see the tag.
    alice.send("@+example=hello PRIVMSG carol :plain").await;
    let plain = carol.expect("PRIVMSG carol plain").await;
    assert!(!plain.contains("+example"), "untagged was {plain:?}");

    // A client cannot forge a server tag such as `time`.
    alice
        .send("@time=1999-01-01T00:00:00Z PRIVMSG bob :forged")
        .await;
    let forged = bob.expect("PRIVMSG bob forged").await;
    assert!(!forged.contains("1999"), "forged tag leaked: {forged:?}");

    // Channel traffic follows the same rule.
    alice.send("JOIN #tags").await;
    alice.expect(" 366 ").await;
    bob.send("JOIN #tags").await;
    bob.expect(" 366 ").await;
    alice.send("@+example=room PRIVMSG #tags :hi").await;
    let channel = bob.expect("PRIVMSG #tags hi").await;
    assert!(
        channel.starts_with("@+example=room "),
        "channel delivery was {channel:?}"
    );
}

#[tokio::test]
async fn account_tag_marks_join_part_and_quit() {
    let (server, address) = start(base_config()).await;
    server.set_account_backend(Arc::new(TwoAccounts));

    let mut alice = Client::connect(address).await;
    register_with_sasl(&mut alice, "alice", "hunter2").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;

    let mut bob = Client::connect(address).await;
    bob.send("CAP REQ :account-tag").await;
    bob.expect("CAP * ACK :account-tag").await;
    bob.send("CAP END").await;
    bob.register("bob").await;
    bob.send("JOIN #room").await;
    bob.expect(" 366 ").await;

    alice.send("PART #room :bye").await;
    let part = bob.expect("PART #room").await;
    assert!(
        part.starts_with("@account=alice "),
        "part was tagged {part:?}"
    );

    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;
    let join = bob.expect("JOIN #room").await;
    assert!(
        join.starts_with("@account=alice "),
        "join was tagged {join:?}"
    );

    alice.send("QUIT :gone").await;
    let quit = bob.expect("QUIT").await;
    assert!(
        quit.starts_with("@account=alice "),
        "quit was tagged {quit:?}"
    );
}

#[tokio::test]
async fn labeled_response_round_trips_the_label() {
    let (_server, address) = start(base_config()).await;
    let mut alice = Client::connect(address).await;
    alice.send("CAP LS 302").await;
    let listing = alice.expect("CAP * LS").await;
    assert!(
        listing.contains("labeled-response"),
        "listing was {listing:?}"
    );
    alice.send("CAP REQ :labeled-response").await;
    alice.expect("CAP * ACK :labeled-response").await;
    alice.send("CAP END").await;
    alice.register("alice").await;

    // Numerics and the command's own echo carry the label.
    alice.send("@label=join-1 JOIN #room").await;
    let join = alice.expect("JOIN #room").await;
    assert!(join.starts_with("@label=join-1 "), "join was {join:?}");
    let end = alice.expect(" 366 ").await;
    assert!(end.starts_with("@label=join-1 "), "names end was {end:?}");

    // A command that produced no reply of its own is acknowledged instead.
    alice.send("@label=silent-1 PONG :token").await;
    let ack = alice.expect(" ACK").await;
    assert!(ack.starts_with("@label=silent-1 "), "ack was {ack:?}");
}

#[tokio::test]
async fn labeled_response_is_opt_in_and_stays_with_the_issuer() {
    let (_server, address) = start(base_config()).await;

    let mut alice = Client::connect(address).await;
    alice.register("alice").await;

    let mut bob = Client::connect(address).await;
    bob.send("CAP REQ :labeled-response").await;
    bob.expect("CAP * ACK :labeled-response").await;
    bob.send("CAP END").await;
    bob.register("bob").await;
    bob.send("JOIN #room").await;
    bob.expect(" 366 ").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;

    // A client that did not negotiate the capability has its label ignored.
    alice.send("@label=ignored WHOIS bob").await;
    let whois = alice.expect(" 311 ").await;
    assert!(!whois.starts_with('@'), "whois was {whois:?}");

    // Once negotiated, the label marks the issuer's own replies.
    alice.send("CAP REQ :labeled-response").await;
    alice.expect(" ACK :labeled-response").await;
    alice.send("@label=msg-1 PRIVMSG #room :hello").await;
    let ack = alice.expect(" ACK").await;
    assert!(ack.starts_with("@label=msg-1 "), "ack was {ack:?}");

    // It never rides along on another client's copy of the message, even when
    // that client also negotiated the capability.
    let delivered = bob.expect("PRIVMSG #room hello").await;
    assert!(!delivered.contains("label="), "delivered was {delivered:?}");
}

#[tokio::test]
async fn invitation_warnings_and_expiry_are_delivered() {
    let mut config = base_config();
    config.server.invite_expiry_secs = 4;
    config.server.invite_warning_secs = 3;
    let (server, address) = start(config).await;

    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #room +i").await;
    alice.expect("MODE #room +i").await;

    let mut bob = Client::connect(address).await;
    bob.register("bob").await;
    alice.send("INVITE bob #room").await;
    alice.expect(" 341 ").await;
    bob.expect("INVITE bob").await;

    // Once inside the warning window both parties hear about it.
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    assert_eq!(server.sweep_invites(), 2, "both parties get a warning");
    let warning = bob.expect("expires in").await;
    assert!(warning.contains("#room"), "warning was {warning:?}");
    let inviter = alice.expect("expires in").await;
    assert!(inviter.contains("bob"), "inviter notice was {inviter:?}");

    // The warning is delivered once, not on every sweep.
    assert_eq!(server.sweep_invites(), 0, "the warning must not repeat");

    // Once it lapses both parties are told and the grant is gone.
    tokio::time::sleep(std::time::Duration::from_millis(3_200)).await;
    assert_eq!(
        server.sweep_invites(),
        2,
        "both parties get an expiry notice"
    );
    let expired = bob.expect("has expired").await;
    assert!(expired.contains("#room"), "expiry notice was {expired:?}");
    let inviter_expired = alice.expect("has expired").await;
    assert!(
        inviter_expired.contains("bob"),
        "inviter notice was {inviter_expired:?}"
    );
    assert!(
        server
            .find_channel("#room")
            .expect("channel")
            .read()
            .invites
            .is_empty(),
        "the lapsed grant must be removed"
    );

    bob.send("JOIN #room").await;
    bob.expect(" 473 ").await;
}

#[tokio::test]
async fn invitations_expire_after_the_configured_lifetime() {
    let mut config = base_config();
    config.server.invite_expiry_secs = 1;
    let (_server, address) = start(config).await;

    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #room +i").await;
    alice.expect("MODE #room +i").await;

    let mut bob = Client::connect(address).await;
    bob.register("bob").await;
    alice.send("INVITE bob #room").await;
    alice.expect(" 341 ").await;
    bob.expect("INVITE bob").await;

    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    bob.send("JOIN #room").await;
    let refused = bob.expect(" 473 ").await;
    assert!(refused.contains("#room"), "refusal was {refused:?}");
}

#[tokio::test]
async fn quitting_withdraws_outstanding_invitations() {
    let (server, address) = start(base_config()).await;

    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #room +i").await;
    alice.expect("MODE #room +i").await;

    let mut bob = Client::connect(address).await;
    bob.register("bob").await;
    alice.send("INVITE bob #room").await;
    alice.expect(" 341 ").await;
    bob.expect("INVITE bob").await;

    bob.send("QUIT :bye").await;
    for _ in 0..250 {
        let cleared = server
            .find_channel("#room")
            .is_some_and(|channel| channel.read().invites.is_empty());
        if cleared {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the invitation survived the invitee's quit");
}

#[tokio::test]
async fn allowlisted_vendor_tags_are_relayed() {
    let mut config = base_config();
    config.server.client_tag_allowlist = vec!["example.com/foo".to_owned()];
    let (_server, address) = start(config).await;

    let mut alice = Client::connect(address).await;
    alice.register("alice").await;

    let mut bob = Client::connect(address).await;
    bob.send("CAP REQ :message-tags").await;
    bob.expect("CAP * ACK :message-tags").await;
    bob.send("CAP END").await;
    bob.register("bob").await;

    // The configured vendor tag and a plain `+` tag both reach the recipient.
    alice
        .send("@example.com/foo=bar;+example=one PRIVMSG bob :hello")
        .await;
    let delivered = bob.expect("PRIVMSG bob hello").await;
    assert!(
        delivered.contains("example.com/foo=bar"),
        "delivered was {delivered:?}"
    );
    assert!(
        delivered.contains("+example=one"),
        "delivered was {delivered:?}"
    );

    // An unlisted vendor tag is dropped and never reaches the recipient.
    alice
        .send("@example.com/other=no PRIVMSG bob :second")
        .await;
    let plain = bob.expect("PRIVMSG bob second").await;
    assert!(
        !plain.contains("example.com/other"),
        "delivered was {plain:?}"
    );
}

#[tokio::test]
async fn account_tag_marks_nick_changes() {
    let (server, address) = start(base_config()).await;
    server.set_account_backend(Arc::new(TwoAccounts));

    let mut alice = Client::connect(address).await;
    register_with_sasl(&mut alice, "alice", "hunter2").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;

    let mut bob = Client::connect(address).await;
    bob.send("CAP REQ :account-tag").await;
    bob.expect("CAP * ACK :account-tag").await;
    bob.send("CAP END").await;
    bob.register("bob").await;
    bob.send("JOIN #room").await;
    bob.expect(" 366 ").await;

    let mut carol = Client::connect(address).await;
    carol.register("carol").await;
    carol.send("JOIN #room").await;
    carol.expect(" 366 ").await;

    alice.send("NICK alice2").await;
    let tagged = bob.expect("NICK alice2").await;
    assert!(
        tagged.starts_with("@account=alice "),
        "nick was tagged {tagged:?}"
    );

    // A client that did not negotiate the capability must not see it.
    let plain = carol.expect("NICK alice2").await;
    assert!(!plain.starts_with('@'), "nick was {plain:?}");

    // The actor is a recipient of its own change, so its echo follows the same
    // rule once it asks for the capability.
    alice.send("CAP REQ :account-tag").await;
    alice.expect(" ACK :account-tag").await;
    alice.send("NICK alice3").await;
    let own = alice.expect("NICK alice3").await;
    assert!(
        own.starts_with("@account=alice "),
        "own nick echo was {own:?}"
    );
}

#[tokio::test]
async fn server_link_handshake_succeeds_with_shared_password() {
    std::env::set_var("RS_IRCD_TEST_LINK_PASSWORD", "link-secret");
    let mut config = base_config();
    config.server.link_password_env = Some("RS_IRCD_TEST_LINK_PASSWORD".to_owned());
    config.server.peers = vec!["peer.test".to_owned()];
    config.listen[0].server_link = true;
    let (server, address) = start(config).await;

    let mut link = Client::connect(address).await;
    link.send("PASS link-secret").await;
    link.send("SERVER peer.test 1 0PF :peer server").await;
    let reply = link.expect(" SERVER ").await;
    assert!(reply.contains("irc.test"), "reply was {reply:?}");
    assert_eq!(server.link_count(), 1);

    // A wrong password must be rejected instead of silently accepted.
    let mut denied = Client::connect(address).await;
    denied.send("PASS wrong").await;
    let error = denied.expect("ERROR").await;
    assert!(error.contains("Invalid link password"), "got {error:?}");
    link.close().await;
}
