//! Client-protocol commands added after the IRCv3 pass: `SILENCE`, `KNOCK`,
//! `WHOX` and `WEBIRC`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ircd::config::{Config, ListenSection, WebircSection};
use ircd::net;
use ircd::server::Server;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

const GATEWAY_SECRET_ENV: &str = "RS_IRCD_TEST_WEBIRC_SECRET";

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
        self.expect(" 376 ").await;
    }

    async fn drain(&mut self, window: Duration) -> Vec<String> {
        let mut lines = std::mem::take(&mut self.seen);
        let deadline = tokio::time::Instant::now() + window;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return lines;
            }
            let mut line = String::new();
            match tokio::time::timeout(remaining, self.reader.read_line(&mut line)).await {
                Ok(Ok(0)) | Err(_) => return lines,
                Ok(Ok(_)) => lines.push(line.trim_end_matches(['\r', '\n']).to_owned()),
                Ok(Err(_)) => return lines,
            }
        }
    }
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

fn config() -> Config {
    let mut config = Config::default();
    config.server.name = "irc.test".to_owned();
    config.server.network = "TestNet".to_owned();
    config.listen.push(ListenSection {
        addresses: vec!["127.0.0.1".parse().expect("ipv4")],
        port: 0,
        tls: false,
        server_link: false,
    });
    config
}

#[tokio::test]
async fn silence_drops_direct_messages_from_matching_masks() {
    let (_server, address) = start(config()).await;
    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    let mut bob = Client::connect(address).await;
    bob.register("bob").await;

    bob.send("SILENCE +alice!*@*").await;
    bob.expect(" 271 ").await;
    bob.expect(" 272 ").await;

    alice.send("PRIVMSG bob :you should not see this").await;
    let lines = bob.drain(Duration::from_millis(300)).await;
    assert!(
        !lines.iter().any(|line| line.contains("should not see")),
        "silenced message was delivered: {lines:?}"
    );

    // Another sender still gets through.
    let mut carol = Client::connect(address).await;
    carol.register("carol").await;
    carol.send("PRIVMSG bob :from carol").await;
    bob.expect("from carol").await;

    bob.send("SILENCE -alice!*@*").await;
    bob.expect(" 272 ").await;
    alice.send("PRIVMSG bob :welcome back").await;
    bob.expect("welcome back").await;

    // The list is empty again, so only the terminator is sent.
    bob.send("SILENCE").await;
    bob.expect(" 272 ").await;
}

#[tokio::test]
async fn knock_reaches_operators_only_on_invite_only_channels() {
    let (_server, address) = start(config()).await;
    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    let mut bob = Client::connect(address).await;
    bob.register("bob").await;

    alice.send("JOIN #vault").await;
    alice.expect("JOIN #vault").await;
    alice.send("MODE #vault +i").await;
    alice.expect("MODE #vault +i").await;

    bob.send("KNOCK #vault :let me in").await;
    bob.expect(" 710 ").await;
    let knock = alice.expect("KNOCK #vault").await;
    assert!(knock.starts_with(":bob!"), "knock was {knock:?}");
    assert!(knock.contains("let me in"));

    // Knocking on a channel that is not invite-only is refused.
    alice.send("MODE #vault -i").await;
    alice.expect("MODE #vault -i").await;
    bob.send("KNOCK #vault").await;
    bob.expect(" 480 ").await;
}

#[tokio::test]
async fn whox_returns_only_the_requested_fields() {
    let (_server, address) = start(config()).await;
    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect("JOIN #room").await;
    alice.expect(" 366 ").await;

    alice.send("WHO #room %cuhnfa,42").await;
    let reply = alice.expect(" 354 ").await;
    assert!(reply.contains("#room"), "got {reply:?}");
    assert!(reply.contains("alice"), "got {reply:?}");
    assert!(reply.contains(" 0 "), "account 0 missing: {reply:?}");
    assert!(reply.ends_with(" 42"), "token missing: {reply:?}");
    alice.expect(" 315 ").await;

    // A plain WHO still answers with the classic numeric.
    alice.send("WHO #room").await;
    alice.expect(" 352 ").await;
}

#[tokio::test]
async fn webirc_is_only_accepted_from_a_trusted_gateway() {
    std::env::set_var(GATEWAY_SECRET_ENV, "gateway-secret");
    let mut config = config();
    config.webirc.push(WebircSection {
        host: "127.0.0.1".to_owned(),
        password_env: GATEWAY_SECRET_ENV.to_owned(),
    });
    let (_server, address) = start(config).await;

    let mut good = Client::connect(address).await;
    good.send("WEBIRC gateway-secret irc.gateway client.example 203.0.113.9")
        .await;
    good.register("good").await;
    good.send("WHOIS good").await;
    let whois = good.expect(" 311 ").await;
    assert!(
        whois.contains("client.example"),
        "spoofed host missing: {whois:?}"
    );

    let mut bad = Client::connect(address).await;
    bad.send("WEBIRC wrong-secret irc.gateway client.example 203.0.113.9")
        .await;
    bad.expect(" 464 ").await;
}

#[tokio::test]
async fn webirc_is_refused_after_registration() {
    std::env::set_var(GATEWAY_SECRET_ENV, "gateway-secret");
    let mut config = config();
    config.webirc.push(WebircSection {
        host: "127.0.0.1".to_owned(),
        password_env: GATEWAY_SECRET_ENV.to_owned(),
    });
    let (_server, address) = start(config).await;

    let mut client = Client::connect(address).await;
    client.register("alice").await;
    client
        .send("WEBIRC gateway-secret irc.gateway client.example 203.0.113.9")
        .await;
    client.expect(" 462 ").await;
}
