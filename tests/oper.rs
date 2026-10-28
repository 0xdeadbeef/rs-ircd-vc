//! Operator tooling over the wire: privileges, snomasks, `GLOBOPS`, `SAMODE`,
//! channel override and server bans.
//!
//! Each test starts its own server on an ephemeral loopback port, so the cases
//! are independent and run in parallel. The operator password hash is the
//! SHA-256 of `oper-secret`, which is fixed here rather than computed because
//! `sha2` is a dependency of the library, not of the test crate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ircd::config::{Config, ListenSection, OperFlag, OperSection};
use ircd::net;
use ircd::server::Server;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

const OPER_HASH_ENV: &str = "RS_IRCD_TEST_OPER_HASH";
const OPER_PASSWORD: &str = "oper-secret";
const OPER_HASH: &str = "af87d7714ce6b7b9f5b4e1c271b417a9c2f3d34f790a440dfaba4a52f2a10e66";

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
    }

    async fn oper(&mut self, name: &str) {
        self.send(format!("OPER {name} {OPER_PASSWORD}")).await;
        self.expect(" 381 ").await;
    }

    /// Everything readable within `window`, for "nothing was delivered" cases.
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
    std::env::set_var(OPER_HASH_ENV, OPER_HASH);
    let mut config = Config::default();
    config.server.name = "irc.test".to_owned();
    config.server.network = "TestNet".to_owned();
    config.listen.push(ListenSection {
        addresses: vec!["127.0.0.1".parse().expect("ipv4")],
        port: 0,
        tls: false,
        server_link: false,
    });
    config.opers.push(OperSection {
        name: "admin".to_owned(),
        password_hash_env: Some(OPER_HASH_ENV.to_owned()),
        host: None,
        flags: vec![
            OperFlag::Kill,
            OperFlag::Rehash,
            OperFlag::Global,
            OperFlag::Admin,
            OperFlag::Ban,
        ],
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
async fn snomask_subscription_filters_server_notices() {
    let (_server, address) = start().await;
    let mut admin = Client::connect(address).await;
    admin.register("admin").await;
    admin.oper("admin").await;
    let mut watcher = Client::connect(address).await;
    watcher.register("watcher").await;
    watcher.oper("admin").await;

    // Clearing `+s` must stop the notices even though the session still holds
    // the subscription bits.
    watcher.send("MODE watcher -s").await;
    watcher.expect("MODE watcher -s").await;
    let _ = watcher.drain(Duration::from_millis(150)).await;

    admin.send("KLINE silent 1h :quiet").await;
    admin.expect("K-Line on silent is now active").await;
    let lines = watcher.drain(Duration::from_millis(300)).await;
    assert!(
        !lines.iter().any(|line| line.contains("Notice -- K-Line")),
        "an operator without +s received a notice: {lines:?}"
    );

    watcher.send("SNOMASK +b").await;
    watcher.expect("Snomask is now +b").await;
    admin.send("KLINE loud 1h :loud").await;
    watcher.expect("Notice -- K-Line loud").await;

    // `MODE +s` alone restores the previously subscribed set.
    watcher.send("MODE watcher +s").await;
    watcher.expect("MODE watcher +s").await;
    admin.send("KLINE louder 1h :louder").await;
    watcher.expect("Notice -- K-Line louder").await;
}

#[tokio::test]
async fn globops_reaches_every_operator() {
    let (_server, address) = start().await;
    let mut admin = Client::connect(address).await;
    admin.register("admin").await;
    admin.oper("admin").await;
    let mut peer = Client::connect(address).await;
    peer.register("peer").await;
    peer.oper("admin").await;

    admin.send("GLOBOPS :maintenance in five minutes").await;
    let delivered = peer.expect("GLOBOPS :maintenance in five minutes").await;
    assert!(delivered.starts_with(":admin!"), "got {delivered:?}");
    admin.expect("GLOBOPS :maintenance in five minutes").await;
}

#[tokio::test]
async fn samode_forces_a_mode_change_from_outside_the_channel() {
    let (_server, address) = start().await;
    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    let mut bob = Client::connect(address).await;
    bob.register("bob").await;
    let mut admin = Client::connect(address).await;
    admin.register("admin").await;
    admin.oper("admin").await;

    alice.send("JOIN #room").await;
    alice.expect("JOIN #room").await;
    bob.send("JOIN #room").await;
    bob.expect("JOIN #room").await;
    alice.expect("bob").await;

    // The operator is not a member and holds no channel status.
    admin.send("SAMODE #room +m").await;
    let change = bob.expect("MODE #room +m").await;
    assert!(change.contains("MODE #room +m"), "got {change:?}");

    bob.send("PRIVMSG #room :now moderated").await;
    bob.expect(" 404 ").await;
}

#[tokio::test]
async fn admin_override_joins_a_keyed_channel_and_tells_the_operators() {
    let (_server, address) = start().await;
    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    let mut admin = Client::connect(address).await;
    admin.register("admin").await;
    admin.oper("admin").await;

    alice.send("JOIN #vault").await;
    alice.expect("JOIN #vault").await;
    alice.send("MODE #vault +k sekrit").await;
    alice.expect("MODE #vault +k sekrit").await;

    admin.send("JOIN #vault").await;
    admin.expect("JOIN #vault").await;
    let notice = alice.expect("overrode").await;
    assert!(notice.contains("+k"), "notice was {notice:?}");
}

#[tokio::test]
async fn gline_blocks_registration_until_it_is_lifted() {
    let (_server, address) = start().await;
    let mut admin = Client::connect(address).await;
    admin.register("admin").await;
    admin.oper("admin").await;

    admin.send("GLINE blocked* 1h :spam").await;
    admin.expect("G-Line on blocked* is now active").await;

    let mut banned = Client::connect(address).await;
    banned.send("NICK blocked1").await;
    banned.send("USER blocked1 0 * :blocked").await;
    banned.expect(" 465 ").await;

    admin.send("UNBAN G blocked*").await;
    admin.expect("G-Line blocked* removed").await;

    let mut allowed = Client::connect(address).await;
    allowed.register("blocked2").await;
}

#[tokio::test]
async fn shun_silences_speech_but_keeps_the_connection() {
    let (_server, address) = start().await;
    let mut admin = Client::connect(address).await;
    admin.register("admin").await;
    admin.oper("admin").await;
    let mut alice = Client::connect(address).await;
    alice.register("alice").await;
    let mut bob = Client::connect(address).await;
    bob.register("bob").await;

    admin.send("SHUN alice 1h :spam").await;
    admin.expect("Shun on alice is now active").await;

    alice.send("JOIN #room").await;
    alice.expect("JOIN #room").await;
    bob.send("JOIN #room").await;
    bob.expect("JOIN #room").await;
    alice.expect("bob").await;

    alice.send("PRIVMSG #room :should not arrive").await;
    let lines = bob.drain(Duration::from_millis(300)).await;
    assert!(
        !lines.iter().any(|line| line.contains("should not arrive")),
        "a shunned client's message was delivered: {lines:?}"
    );

    // The connection is still usable: state changes are not speech.
    alice.send("TOPIC #room :still here").await;
    bob.expect("TOPIC #room :still here").await;
}

#[tokio::test]
async fn privileges_are_enforced_per_command() {
    std::env::set_var(OPER_HASH_ENV, OPER_HASH);
    let mut config = Config::default();
    config.server.name = "irc.test".to_owned();
    config.listen.push(ListenSection {
        addresses: vec!["127.0.0.1".parse().expect("ipv4")],
        port: 0,
        tls: false,
        server_link: false,
    });
    config.opers.push(OperSection {
        name: "helper".to_owned(),
        password_hash_env: Some(OPER_HASH_ENV.to_owned()),
        host: None,
        flags: vec![OperFlag::Kill],
    });
    let config = Arc::new(config);
    let server = Server::new(Arc::clone(&config), None).expect("server state");
    let listeners = net::bind(&config).expect("bind");
    let address = listeners[0].local;
    for listener in listeners {
        net::spawn_accept_loop(Arc::clone(&server), listener);
    }

    let mut helper = Client::connect(address).await;
    helper.register("helper").await;
    helper.oper("helper").await;
    helper.send("REHASH").await;
    helper.expect(" 481 ").await;
    helper.send("GLINE someone 1h :no").await;
    helper.expect(" 481 ").await;
}
