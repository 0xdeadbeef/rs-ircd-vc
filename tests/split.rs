//! Split-brain tests: two copies of a channel diverge, then a netburst heals
//! them.
//!
//! One side is always the real daemon. The other is a scripted peer, so a
//! divergence can be stated exactly instead of being produced by a race. The
//! healing rule under test is the channel `TS`: the older copy owns the modes,
//! topic and lists, while membership is merged either way.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ircd::config::{Config, ListenSection};
use ircd::net;
use ircd::server::Server;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

const LINK_PASSWORD: &str = "split-secret";
const LINK_PASSWORD_ENV: &str = "RS_IRCD_TEST_SPLIT_PASSWORD";

struct Harness {
    server: Arc<Server>,
    client_addr: SocketAddr,
    link_addr: SocketAddr,
}

async fn start() -> Harness {
    std::env::set_var(LINK_PASSWORD_ENV, LINK_PASSWORD);
    let mut config = Config::default();
    config.server.name = "irc.test".to_owned();
    config.server.sid = "0RS".to_owned();
    config.server.link_password_env = Some(LINK_PASSWORD_ENV.to_owned());
    config.listen.push(ListenSection {
        addresses: vec!["127.0.0.1".parse().expect("ipv4")],
        port: 0,
        tls: false,
        server_link: false,
    });
    config.listen.push(ListenSection {
        addresses: vec!["127.0.0.1".parse().expect("ipv4")],
        port: 0,
        tls: false,
        server_link: true,
    });

    let config = Arc::new(config);
    let server = Server::new(Arc::clone(&config), None).expect("server state");
    let listeners = net::bind(&config).expect("bind");
    let mut client_addr = None;
    let mut link_addr = None;
    for listener in listeners {
        if listener.section.server_link {
            link_addr = Some(listener.local);
        } else {
            client_addr = Some(listener.local);
        }
        net::spawn_accept_loop(Arc::clone(&server), listener);
    }
    Harness {
        server,
        client_addr: client_addr.expect("client listener"),
        link_addr: link_addr.expect("link listener"),
    }
}

struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    seen: Vec<String>,
}

impl Client {
    async fn connect(address: SocketAddr) -> Self {
        let stream = TcpStream::connect(address).await.expect("connect");
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

    /// Collect whatever arrives within `window`; used to prove that nothing was
    /// delivered.
    async fn collect(&mut self, window: Duration) -> Vec<String> {
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

struct Peer {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Peer {
    async fn connect(address: SocketAddr, name: &str, sid: &str) -> Self {
        let stream = TcpStream::connect(address).await.expect("connect link");
        let (read, write) = stream.into_split();
        let mut peer = Self {
            reader: BufReader::new(read),
            writer: write,
        };
        peer.send(format!("PASS {LINK_PASSWORD}")).await;
        peer.send(format!("SERVER {name} 1 {sid} :{name}")).await;
        peer.expect(" SERVER ").await;
        peer
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
                    .unwrap_or_else(|_| panic!("peer timed out waiting for {needle:?}"))
                    .expect("read");
            assert_ne!(read, 0, "link closed waiting for {needle:?}");
            let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
            if trimmed.contains(needle) {
                return trimmed;
            }
        }
        panic!("peer never saw {needle:?}");
    }

    /// Collect lines for `window`; used to assert that nothing was sent.
    async fn collect(&mut self, window: Duration) -> Vec<String> {
        let deadline = tokio::time::Instant::now() + window;
        let mut lines = Vec::new();
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

    async fn disconnect(self) {
        let mut writer = self.writer;
        let _ = writer.shutdown().await;
    }
}

/// Introduce `server` behind the peer and one user who lives on it.
async fn introduce_remote(
    peer: &mut Peer,
    origin: &str,
    server: &str,
    sid: &str,
    nick: &str,
    ts: u64,
) {
    peer.send(format!(":{origin} SERVER {server} 1 {sid} :{server}"))
        .await;
    peer.send(format!(
        ":{nick}!user@remote NICK {nick} 1 {ts} user remote {server} +i :Remote {nick}"
    ))
    .await;
}

async fn wait_for(server: &Arc<Server>, what: &str, predicate: impl Fn(&Server) -> bool) {
    for _ in 0..250 {
        if predicate(server) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

fn created(server: &Arc<Server>, name: &str) -> u64 {
    server
        .find_channel(name)
        .expect("channel exists")
        .read()
        .created
}

#[tokio::test]
async fn older_remote_copy_owns_the_arguments_and_topic() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;
    let local = created(&harness.server, "#room");

    alice.send("TOPIC #room :local topic").await;
    alice.expect("TOPIC #room :local topic").await;
    alice.send("MODE #room +R").await;
    alice.expect("MODE #room +R").await;
    alice.send("MODE #room +k localkey").await;
    alice.expect("MODE #room +k localkey").await;
    alice.send("MODE #room +l 5").await;
    alice.expect("MODE #room +l 5").await;
    alice.send("MODE #room +b $a:troll").await;
    alice.expect("MODE #room +b").await;

    let mut peer = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    // Drain our own burst so later expectations see only new lines.
    peer.expect("EOB").await;
    introduce_remote(
        &mut peer,
        "alpha.test",
        "delta.test",
        "0DD",
        "dave",
        local - 10,
    )
    .await;

    let older = local - 500;
    peer.send(format!("SJOIN #room {older} +mntkl pkey 9 :@dave"))
        .await;
    peer.send(":alpha.test TOPIC #room :remote topic").await;
    peer.send(":alpha.test MODE #room +b *!*@bad.example").await;
    peer.send(":alpha.test EOB").await;

    wait_for(&harness.server, "older copy applied", |server| {
        server.find_channel("#room").is_some_and(|channel| {
            let guard = channel.read();
            guard.created == older
                && guard.topic.as_deref() == Some("remote topic")
                && guard.bans.len() == 2
        })
    })
    .await;

    {
        let channel = harness.server.find_channel("#room").expect("channel");
        let guard = channel.read();
        assert_eq!(guard.created, older, "the older copy owns the channel");
        assert!(guard.moderated && guard.no_external && guard.topic_lock);
        assert!(
            guard.account_only,
            "+R set during the split must survive the merge"
        );
        assert_eq!(guard.key.as_deref(), Some("pkey"), "the older copy owns +k");
        assert_eq!(guard.limit, Some(9), "the older copy owns +l");
        let masks: Vec<&str> = guard.bans.iter().map(|entry| entry.mask.as_str()).collect();
        assert_eq!(
            masks,
            ["$a:troll", "*!*@bad.example"],
            "bans from both sides must survive"
        );
        assert!(guard.exceptions.is_empty());
    }

    // Local members are not removed by a losing copy, and the winner's member
    // is added.
    alice.send("NAMES #room").await;
    let names = alice.expect(" 353 ").await;
    assert!(names.contains("alice"), "names were {names:?}");
    assert!(names.contains("dave"), "names were {names:?}");

    // Local members are told that the channel state moved under them.
    alice.send("TOPIC #room").await;
    let topic = alice.expect(" 332 ").await;
    assert!(topic.contains("remote topic"), "topic was {topic:?}");
    alice.send("MODE #room").await;
    let modes = alice.expect(" 324 ").await;
    assert!(modes.contains("pkey"), "modes were {modes:?}");
}

#[tokio::test]
async fn newer_local_copy_merges_modes_but_keeps_its_topic() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #keep").await;
    alice.expect(" 366 ").await;
    let local = created(&harness.server, "#keep");

    alice.send("TOPIC #keep :local topic").await;
    alice.expect("TOPIC #keep :local topic").await;
    alice.send("MODE #keep +R").await;
    alice.expect("MODE #keep +R").await;
    alice.send("MODE #keep +b $a:troll").await;
    alice.expect("MODE #keep +b").await;

    let mut peer = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    peer.expect("EOB").await;
    introduce_remote(
        &mut peer,
        "alpha.test",
        "delta.test",
        "0DD",
        "bob",
        local - 10,
    )
    .await;

    peer.send(format!("SJOIN #keep {} +m :bob", local + 100))
        .await;
    peer.send(":alpha.test TOPIC #keep :stale topic").await;
    peer.send(":alpha.test MODE #keep +b *!*@stale.example")
        .await;
    peer.send(":alpha.test EOB").await;

    wait_for(&harness.server, "members and lists merged", |server| {
        server.find_channel("#keep").is_some_and(|channel| {
            let guard = channel.read();
            guard.len() == 2 && guard.bans.len() == 2
        })
    })
    .await;

    let channel = harness.server.find_channel("#keep").expect("channel");
    let guard = channel.read();
    assert_eq!(guard.created, local, "the newer local copy keeps ownership");
    assert!(guard.moderated, "+m from the newer copy must still merge");
    assert!(guard.account_only, "+R must survive");
    assert_eq!(guard.topic.as_deref(), Some("local topic"));
    let masks: Vec<&str> = guard.bans.iter().map(|entry| entry.mask.as_str()).collect();
    assert_eq!(masks, ["$a:troll", "*!*@stale.example"]);
}

#[tokio::test]
async fn equal_timestamp_merges_modes_and_members() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #same").await;
    alice.expect(" 366 ").await;
    let local = created(&harness.server, "#same");
    alice.send("TOPIC #same :keeping").await;
    alice.expect("TOPIC #same keeping").await;
    alice.send("MODE #same +R").await;
    alice.expect("MODE #same +R").await;

    let mut peer = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    peer.expect("EOB").await;
    introduce_remote(
        &mut peer,
        "alpha.test",
        "delta.test",
        "0DD",
        "carol",
        local - 10,
    )
    .await;

    peer.send(format!("SJOIN #same {local} +m :carol")).await;
    peer.send(":alpha.test TOPIC #same :stale").await;
    peer.send(":alpha.test MODE #same +b *!*@stale.example")
        .await;
    peer.send(":alpha.test EOB").await;

    wait_for(&harness.server, "modes and members merged", |server| {
        server.find_channel("#same").is_some_and(|channel| {
            let guard = channel.read();
            guard.len() == 2 && guard.bans.len() == 1
        })
    })
    .await;

    {
        let channel = harness.server.find_channel("#same").expect("channel");
        let guard = channel.read();
        assert_eq!(guard.created, local);
        assert!(guard.moderated, "an equal-TS burst still merges modes");
        assert!(guard.account_only);
        assert_eq!(guard.topic.as_deref(), Some("keeping"));
        assert_eq!(guard.bans[0].mask, "*!*@stale.example");
    }

    // The topic is not merged, so the stale one must not be announced.
    let late = alice.collect(Duration::from_millis(200)).await;
    assert!(
        !late
            .iter()
            .any(|line| line.contains("TOPIC") && line.contains("stale")),
        "the stale topic leaked to members: {late:?}"
    );
}

#[tokio::test]
async fn reconnect_burst_describes_the_surviving_state() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;
    let local = created(&harness.server, "#room");
    alice.send("MODE #room +R").await;
    alice.expect("MODE #room +R").await;
    alice.send("TOPIC #room :before split").await;
    alice.expect("TOPIC #room :before split").await;

    let mut peer = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    peer.expect("EOB").await;
    introduce_remote(
        &mut peer,
        "alpha.test",
        "delta.test",
        "0DD",
        "dave",
        local - 10,
    )
    .await;
    peer.send(format!("SJOIN #room {} +nt :@dave", local - 1000))
        .await;
    peer.send(":alpha.test TOPIC #room :remote topic").await;
    peer.send(":alpha.test EOB").await;
    wait_for(&harness.server, "remote copy installed", |server| {
        server
            .find_channel("#room")
            .is_some_and(|channel| channel.read().created == local - 1000)
    })
    .await;

    // The split: the link drops and its users disappear.
    peer.disconnect().await;
    wait_for(&harness.server, "route pruned", |server| {
        server.route("delta.test").is_none()
    })
    .await;

    // Both sides change while apart. `+R` was set before the split and the
    // peer's older burst used to clear it; the merge keeps it.
    alice.send("MODE #room +m").await;
    alice.expect("MODE #room +m").await;
    alice.send("MODE #room +b $a:troll").await;
    alice.expect("MODE #room +b").await;
    alice.send("TOPIC #room :during split").await;
    alice.expect("TOPIC #room :during split").await;

    // The reconnecting peer is told exactly what survived, not the old state.
    let mut peer = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    let sjoin = peer.expect("SJOIN #room").await;
    assert!(sjoin.contains('m'), "burst modes were {sjoin:?}");
    assert!(sjoin.contains("R"), "burst modes were {sjoin:?}");
    let topic = peer.expect("TOPIC #room").await;
    assert!(topic.contains("during split"), "burst topic was {topic:?}");
    let ban = peer.expect("MODE #room +b").await;
    assert!(ban.contains("$a:troll"), "burst ban was {ban:?}");
    peer.expect("EOB").await;

    // The peer's older copy still wins, so the healing is deterministic.
    introduce_remote(
        &mut peer,
        "alpha.test",
        "delta.test",
        "0DD",
        "dave",
        local - 10,
    )
    .await;
    let older = local - 1500;
    peer.send(format!("SJOIN #room {older} +i :@dave")).await;
    peer.send(":alpha.test TOPIC #room :peer topic").await;
    peer.send(":alpha.test MODE #room +b *!*@split.example")
        .await;
    peer.send(":alpha.test EOB").await;

    wait_for(&harness.server, "older copy applied", |server| {
        server.find_channel("#room").is_some_and(|channel| {
            let guard = channel.read();
            guard.created == older
                && guard.topic.as_deref() == Some("peer topic")
                && guard.bans.len() == 2
        })
    })
    .await;

    let channel = harness.server.find_channel("#room").expect("channel");
    let guard = channel.read();
    assert!(guard.invite_only);
    assert!(guard.moderated, "+m set during the split must survive");
    assert!(guard.account_only, "+R set during the split must survive");
    let masks: Vec<&str> = guard.bans.iter().map(|entry| entry.mask.as_str()).collect();
    assert_eq!(
        masks,
        ["$a:troll", "*!*@split.example"],
        "bans from both sides must survive"
    );
}

#[tokio::test]
async fn reconnect_burst_replays_outstanding_invites() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #room +i").await;
    alice.expect("MODE #room +i").await;

    let mut bob = Client::connect(harness.client_addr).await;
    bob.register("bob").await;
    alice.send("INVITE bob #room").await;
    alice.expect(" 341 ").await;
    bob.expect(" INVITE bob").await;

    let peer = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    peer.disconnect().await;
    wait_for(&harness.server, "route pruned", |server| {
        server.route("alpha.test").is_none()
    })
    .await;

    // The invitation outlives the split, so the reconnecting peer learns it
    // instead of refusing bob when he joins through that side.
    let mut peer = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    peer.expect("SJOIN #room").await;
    let invite = peer.expect("INVITE bob #room").await;
    assert!(
        invite.starts_with(":irc.test INVITE bob #room"),
        "replayed invite was {invite:?}"
    );
    peer.expect("EOB").await;
}

#[tokio::test]
async fn burst_invite_lets_a_remote_user_pass_invite_only() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;
    let local = created(&harness.server, "#room");
    alice.send("MODE #room +i").await;
    alice.expect("MODE #room +i").await;

    let peer = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    peer.disconnect().await;
    wait_for(&harness.server, "route pruned", |server| {
        server.route("alpha.test").is_none()
    })
    .await;

    let mut peer = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    peer.expect("EOB").await;

    // `+i` is still in force, so an uninvited remote user is refused.
    introduce_remote(
        &mut peer,
        "alpha.test",
        "delta.test",
        "0DD",
        "dave",
        local - 10,
    )
    .await;
    peer.send(":dave!user@remote JOIN #room").await;
    peer.expect("KICK #room dave").await;

    // The same join succeeds once the burst has replayed the invitation.
    peer.send(":carol!user@remote NICK carol 1 0DD user remote delta.test +i :Carol")
        .await;
    peer.send(":alpha.test INVITE carol #room").await;
    peer.send(":alpha.test EOB").await;
    peer.send(":carol!user@remote JOIN #room").await;

    wait_for(&harness.server, "invited user joined", |server| {
        server
            .find_channel("#room")
            .is_some_and(|channel| channel.read().len() == 2)
    })
    .await;
    let late = peer.collect(Duration::from_millis(200)).await;
    assert!(
        !late
            .iter()
            .any(|line| line.contains("KICK") && line.contains("carol")),
        "the invited user was refused: {late:?}"
    );
}
