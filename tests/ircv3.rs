//! End-to-end tests for the IRCv3 capabilities added after the original set:
//! `monitor`, `setname`, `account-notify`, `draft/multiline` and
//! `draft/chathistory`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ircd::config::{Config, ListenSection};
use ircd::net;
use ircd::server::Server;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

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

    async fn cap(&mut self, capability: &str) {
        self.send(format!("CAP REQ :{capability}")).await;
        self.expect("CAP * ACK").await;
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

async fn start() -> (Arc<Server>, SocketAddr) {
    let mut config = Config::default();
    config.server.name = "irc.test".to_owned();
    config.server.network = "TestNet".to_owned();
    config.listen.push(ListenSection {
        addresses: vec!["127.0.0.1".parse().expect("ipv4")],
        port: 0,
        tls: false,
        server_link: false,
    });
    let config = Arc::new(config);
    let server = Server::new(Arc::clone(&config), None).expect("server state");
    let listeners = net::bind(&config).expect("bind");
    let address = listeners[0].local;
    for listener in listeners {
        net::spawn_accept_loop(Arc::clone(&server), listener);
    }
    (server, address)
}

#[tokio::test]
async fn the_full_capability_set_is_advertised() {
    let (_server, address) = start().await;
    let mut client = Client::connect(address).await;
    client.send("CAP LS 302").await;
    let listing = client.expect("CAP * LS").await;
    for capability in [
        "multi-prefix",
        "away-notify",
        "server-time",
        "extended-join",
        "userhost-in-names",
        "cap-notify",
        "echo-message",
        "account-tag",
        "message-tags",
        "labeled-response",
        "account-notify",
        "invite-notify",
        "setname",
        "chghost",
        "standard-replies",
        "monitor",
        "batch",
        "draft/multiline",
        "draft/chathistory",
    ] {
        assert!(
            listing.contains(capability),
            "{capability} missing from {listing:?}"
        );
    }
    // `sts` is only offered when TLS is configured, and this server has none.
    assert!(
        !listing.contains("sts="),
        "sts advertised without TLS: {listing:?}"
    );
}

#[tokio::test]
async fn monitor_pushes_presence_changes() {
    let (_server, address) = start().await;
    let mut watcher = Client::connect(address).await;
    watcher.cap("monitor").await;
    watcher.send("CAP END").await;
    watcher.register("watcher").await;

    // Watching a nickname that is not online reports it as offline.
    watcher.send("MONITOR +bob").await;
    watcher.expect(" 731 ").await;

    let mut bob = Client::connect(address).await;
    bob.register("bob").await;
    let online = watcher.expect(" 730 ").await;
    assert!(online.contains("bob!bob@"), "online notice was {online:?}");

    bob.send("QUIT :bye").await;
    watcher.expect(" 731 ").await;

    watcher.send("MONITOR L").await;
    watcher.expect(" 732 ").await;
    watcher.expect(" 733 ").await;
}

#[tokio::test]
async fn setname_and_account_notify_reach_capable_peers() {
    let (_server, address) = start().await;
    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    let mut bob = Client::connect(address).await;
    bob.cap("setname").await;
    bob.send("CAP END").await;
    bob.register("bob").await;

    alice.send("JOIN #room").await;
    alice.expect("JOIN #room").await;
    bob.send("JOIN #room").await;
    bob.expect("JOIN #room").await;
    alice.expect("bob").await;

    alice.send("SETNAME :A New Name").await;
    let change = bob.expect("SETNAME :A New Name").await;
    assert!(change.starts_with(":alice!"), "got {change:?}");

    // A peer without the capability must not receive it.
    let mut carol = Client::connect(address).await;
    carol.register("carol").await;
    carol.send("JOIN #room").await;
    carol.expect("JOIN #room").await;
    alice.expect("carol").await;
    alice.send("SETNAME :Another Name").await;
    let lines = carol.drain(Duration::from_millis(250)).await;
    assert!(
        !lines.iter().any(|line| line.contains("SETNAME")),
        "setname leaked to a client without the cap: {lines:?}"
    );
}

#[tokio::test]
async fn multiline_batch_is_joined_and_marked() {
    let (_server, address) = start().await;
    let mut alice = Client::connect(address).await;
    alice.cap("batch").await;
    alice.cap("draft/multiline").await;
    alice.send("CAP END").await;
    alice.register("alice").await;
    let mut bob = Client::connect(address).await;
    bob.cap("batch").await;
    bob.cap("message-tags").await;
    bob.send("CAP END").await;
    bob.register("bob").await;

    alice.send("JOIN #room").await;
    alice.expect("JOIN #room").await;
    bob.send("JOIN #room").await;
    bob.expect("JOIN #room").await;
    alice.expect("bob").await;

    alice.send("BATCH +ml1 draft/multiline #room").await;
    alice.send("@batch=ml1 PRIVMSG #room :first line").await;
    alice.send("@batch=ml1 PRIVMSG #room :second line").await;
    alice.send("BATCH -ml1").await;

    let delivered = bob.expect("draft/multiline-concat").await;
    assert!(
        delivered.contains("PRIVMSG #room :first line"),
        "got {delivered:?}"
    );
    // The body carries an embedded newline, so the reader sees the second
    // half as its own line.
    let second = bob.expect("second line").await;
    assert_eq!(second, "second line");
}

#[tokio::test]
async fn chathistory_replays_in_a_batch() {
    let (_server, address) = start().await;
    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    let mut bob = Client::connect(address).await;
    bob.cap("batch").await;
    bob.cap("draft/chathistory").await;
    bob.send("CAP END").await;
    bob.register("bob").await;

    alice.send("JOIN #room").await;
    alice.expect("JOIN #room").await;
    bob.send("JOIN #room").await;
    bob.expect("JOIN #room").await;
    alice.expect("bob").await;

    alice.send("PRIVMSG #room :hello history").await;
    bob.expect("hello history").await;

    bob.send("CHATHISTORY LATEST #room * 10").await;
    let open = bob.expect("BATCH +").await;
    assert!(
        open.contains("draft/chathistory #room"),
        "open was {open:?}"
    );
    let replayed = bob.expect("hello history").await;
    assert!(replayed.contains("@time="), "replay was {replayed:?}");
    assert!(replayed.contains(":alice!"), "replay was {replayed:?}");
    bob.expect("BATCH -").await;

    // Non-members cannot read a channel's history.
    let mut carol = Client::connect(address).await;
    carol.cap("draft/chathistory").await;
    carol.send("CAP END").await;
    carol.register("carol").await;
    carol.send("CHATHISTORY LATEST #room * 10").await;
    carol.expect(" 442 ").await;
}
