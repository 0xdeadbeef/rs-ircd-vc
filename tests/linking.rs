//! Multi-hop link tests: routing, propagation, collisions and partitions.
//!
//! Each test starts one real server with a client listener and a link
//! listener. Remote servers are scripted peers on the link socket, which lets
//! the tests send exact link-protocol lines and observe what the server
//! forwards to each peer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ircd::config::{Config, ListenSection};
use ircd::net;
use ircd::server::Server;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

const LINK_PASSWORD: &str = "link-secret";
const LINK_PASSWORD_ENV: &str = "RS_IRCD_TEST_LINK_PROTOCOL_PASSWORD";

/// A running server plus the two ports the tests talk to.
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

/// A local IRC client.
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
}

/// A scripted peer server on the link listener.
struct Peer {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    seen: Vec<String>,
    name: String,
}

impl Peer {
    async fn connect(address: SocketAddr, name: &str, sid: &str) -> Self {
        let stream = TcpStream::connect(address).await.expect("connect link");
        let (read, write) = stream.into_split();
        let mut peer = Self {
            reader: BufReader::new(read),
            writer: write,
            seen: Vec::new(),
            name: name.to_owned(),
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
                    .unwrap_or_else(|_| {
                        panic!(
                            "{} timed out waiting for {needle:?}; saw {:?}",
                            self.name, self.seen
                        )
                    })
                    .expect("read");
            assert_ne!(read, 0, "link closed waiting for {needle:?}");
            let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
            if trimmed.contains(needle) {
                return trimmed;
            }
            self.seen.push(trimmed);
        }
        panic!("{} never saw {needle:?}; saw {:?}", self.name, self.seen);
    }

    /// Collect lines for `window`, then return everything seen so far. Used to
    /// assert that nothing was delivered to a peer that is not on the route.
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

    async fn disconnect(self) {
        let mut writer = self.writer;
        let _ = writer.shutdown().await;
    }
}

/// Introduce a server behind `peer` and one user who lives on it.
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

#[tokio::test]
async fn remote_join_part_and_quit_carry_the_account_tag() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.send("CAP REQ :account-tag").await;
    alice.expect("CAP * ACK :account-tag").await;
    alice.send("CAP END").await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;

    let mut peer = Peer::connect(harness.link_addr, "peer.test", "0PR").await;
    introduce_remote(
        &mut peer,
        "peer.test",
        "remote.test",
        "0RM",
        "bob",
        1_700_000_000,
    )
    .await;
    peer.send(":bob!user@remote ACCOUNT bob").await;

    peer.send(":bob!user@remote JOIN #room").await;
    let join = alice.expect("JOIN #room").await;
    assert!(join.starts_with("@account=bob "), "join was {join:?}");

    peer.send(":bob!user@remote PART #room :later").await;
    let part = alice.expect("PART #room").await;
    assert!(part.starts_with("@account=bob "), "part was {part:?}");

    peer.send(":bob!user@remote JOIN #room").await;
    alice.expect("JOIN #room").await;
    peer.send(":bob!user@remote QUIT :gone").await;
    let quit = alice.expect("QUIT").await;
    assert!(quit.starts_with("@account=bob "), "quit was {quit:?}");
}

#[tokio::test]
async fn remote_nick_change_carries_the_account_tag() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.send("CAP REQ :account-tag").await;
    alice.expect("CAP * ACK :account-tag").await;
    alice.send("CAP END").await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;

    let mut peer = Peer::connect(harness.link_addr, "peer.test", "0PR").await;
    introduce_remote(
        &mut peer,
        "peer.test",
        "remote.test",
        "0RM",
        "bob",
        1_700_000_000,
    )
    .await;
    peer.send(":bob!user@remote ACCOUNT bob").await;
    peer.send(":bob!user@remote JOIN #room").await;
    alice.expect("JOIN #room").await;

    // The short form of a rename must keep the account the link introduced.
    peer.send(":bob!user@remote NICK bobby").await;
    let nick = alice.expect("NICK bobby").await;
    assert!(nick.starts_with("@account=bob "), "nick was {nick:?}");
}

#[tokio::test]
async fn client_tags_cross_the_link_only_for_capable_clients() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.send("CAP REQ :message-tags").await;
    alice.expect("CAP * ACK :message-tags").await;
    alice.send("CAP END").await;
    alice.register("alice").await;

    let mut carol = Client::connect(harness.client_addr).await;
    carol.register("carol").await;

    let mut peer = Peer::connect(harness.link_addr, "peer.test", "0PR").await;
    introduce_remote(
        &mut peer,
        "peer.test",
        "remote.test",
        "0RM",
        "bob",
        1_700_000_000,
    )
    .await;

    peer.send("@+x=1 :bob!user@remote PRIVMSG alice :relayed")
        .await;
    let tagged = alice.expect("PRIVMSG alice relayed").await;
    assert!(tagged.starts_with("@+x=1 "), "got {tagged:?}");

    // The same message reaches a client without the capability untagged.
    peer.send("@+x=1 :bob!user@remote PRIVMSG carol :relayed")
        .await;
    let plain = carol.expect("PRIVMSG carol relayed").await;
    assert!(!plain.contains("+x=1"), "got {plain:?}");
}

#[tokio::test]
async fn remote_joins_are_refused_by_an_account_only_channel() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #secure").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #secure +R").await;
    alice.expect("MODE #secure +R").await;

    let mut peer = Peer::connect(harness.link_addr, "peer.test", "0PR").await;
    introduce_remote(
        &mut peer,
        "peer.test",
        "remote.test",
        "0RM",
        "bob",
        1_700_000_000,
    )
    .await;

    // The peer has already accepted this join, so the refusal has to travel
    // back as a KICK instead of being dropped.
    peer.send(":bob!user@remote JOIN #secure").await;
    let kick = peer.expect("KICK #secure bob").await;
    assert!(kick.contains("+R"), "kick reason was {kick:?}");

    alice.send("NAMES #secure").await;
    let names = alice.expect(" 353 ").await;
    assert!(
        !names.contains("bob"),
        "a refused user must not be a member: {names:?}"
    );

    // The same join is accepted once the account arrives, and is not kicked.
    peer.send(":bob!user@remote ACCOUNT bob").await;
    peer.send(":bob!user@remote JOIN #secure").await;
    let join = alice.expect("JOIN #secure").await;
    assert!(join.contains("bob"), "join was {join:?}");
    let after = peer.collect(Duration::from_millis(200)).await;
    assert!(
        !after.iter().any(|line| line.contains("KICK")),
        "an accepted join must not be kicked; saw {after:?}"
    );
}

#[tokio::test]
async fn remote_joins_are_refused_by_an_account_ban() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #banned").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #banned +b $a:bob").await;
    alice.expect("MODE #banned +b").await;

    let mut peer = Peer::connect(harness.link_addr, "peer.test", "0PR").await;
    introduce_remote(
        &mut peer,
        "peer.test",
        "remote.test",
        "0RM",
        "bob",
        1_700_000_001,
    )
    .await;
    // The account is what makes the ban match, and it arrives over the link.
    peer.send(":bob!user@remote ACCOUNT bob").await;
    peer.send(":bob!user@remote JOIN #banned").await;
    let kick = peer.expect("KICK #banned bob").await;
    assert!(kick.contains("+b"), "kick reason was {kick:?}");

    // A different account is not covered by the entry, so it joins normally.
    peer.send(
        ":carol!user@remote NICK carol 1 1700000002 user remote remote.test +i :Remote carol",
    )
    .await;
    peer.send(":carol!user@remote ACCOUNT carol").await;
    peer.send(":carol!user@remote JOIN #banned").await;
    let join = alice.expect("JOIN #banned").await;
    assert!(join.contains("carol"), "join was {join:?}");
    let after = peer.collect(Duration::from_millis(200)).await;
    assert!(
        !after.iter().any(|line| line.contains("KICK")),
        "an unmatched account must not be kicked; saw {after:?}"
    );
}

#[tokio::test]
async fn keyed_join_is_enforced_two_hops_from_the_home_server() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #secret").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #secret +k sekrit").await;
    alice.expect("MODE #secret +k sekrit").await;

    // carol lives on delta.test, which reaches us through alpha.test, so a join
    // her home server announces has already crossed one hop.
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    alpha.expect("EOB").await;
    introduce_remote(
        &mut alpha,
        "alpha.test",
        "delta.test",
        "0DD",
        "carol",
        1_700_000_000,
    )
    .await;
    wait_for(&harness.server, |server| {
        server.find_nick("carol").is_some()
    })
    .await;

    let mut beta = Peer::connect(harness.link_addr, "beta.test", "0BB").await;
    beta.expect("EOB").await;

    // The home server never learned the key, so its join carries none. Two hops
    // later the key is still enforced, and the refusal travels back.
    alpha.send(":carol!user@remote JOIN #secret").await;
    let kick = alpha.expect("KICK #secret carol").await;
    assert!(kick.contains("+k"), "kick reason was {kick:?}");

    let carol = harness.server.find_nick("carol").expect("remote user");
    assert!(
        !harness
            .server
            .find_channel("#secret")
            .expect("channel")
            .read()
            .contains(carol.id),
        "a join without the key must be refused two hops out"
    );
    assert!(
        carol.session(|session| session.channels.is_empty()),
        "the refused user must not be recorded in the channel"
    );

    // A refused join is not forwarded to the third server either.
    let leaked = beta.collect(Duration::from_millis(150)).await;
    assert!(
        !leaked.iter().any(|line| line.contains(" JOIN #secret")),
        "a refused join was forwarded: {leaked:?}"
    );

    // With the key, the join is accepted and the key travels onward so the next
    // hop can apply the same check, while members never see it.
    alpha.send(":carol!user@remote JOIN #secret sekrit").await;
    let forwarded = beta.expect(" JOIN #secret sekrit").await;
    assert!(
        forwarded.contains("sekrit"),
        "the key must reach the next hop: {forwarded:?}"
    );
    let seen = alice.expect("JOIN #secret").await;
    assert!(
        !seen.contains("sekrit"),
        "the key leaked to members: {seen:?}"
    );
    wait_for(&harness.server, |server| {
        server
            .find_channel("#secret")
            .expect("channel")
            .read()
            .contains(carol.id)
    })
    .await;
}

#[tokio::test]
async fn remote_joins_honour_key_limit_and_invite() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;

    alice.send("JOIN #keyed").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #keyed +k s3cret").await;
    alice.expect("MODE #keyed +k s3cret").await;

    alice.send("JOIN #full").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #full +l 1").await;
    alice.expect("MODE #full +l 1").await;

    alice.send("JOIN #secret").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #secret +i").await;
    alice.expect("MODE #secret +i").await;

    let mut peer = Peer::connect(harness.link_addr, "peer.test", "0PR").await;
    introduce_remote(
        &mut peer,
        "peer.test",
        "remote.test",
        "0RM",
        "bob",
        1_700_000_000,
    )
    .await;

    peer.send(":bob!user@remote JOIN #keyed").await;
    let kick = peer.expect("KICK #keyed bob").await;
    assert!(kick.contains("+k"), "kick reason was {kick:?}");

    // The same join with the key succeeds, and no KICK follows.
    peer.send(":bob!user@remote JOIN #keyed s3cret").await;
    let join = alice.expect("JOIN #keyed").await;
    assert!(join.contains("bob"), "join was {join:?}");
    let after = peer.collect(Duration::from_millis(200)).await;
    assert!(
        !after.iter().any(|line| line.contains("KICK")),
        "the right key must not be refused; saw {after:?}"
    );

    peer.send(":bob!user@remote JOIN #full").await;
    let full = peer.expect("KICK #full bob").await;
    assert!(full.contains("+l"), "kick reason was {full:?}");

    peer.send(":bob!user@remote JOIN #secret").await;
    let secret = peer.expect("KICK #secret bob").await;
    assert!(secret.contains("+i"), "kick reason was {secret:?}");

    // An invitation travels the link, so the second attempt is accepted.
    alice.send("INVITE bob #secret").await;
    alice.expect(" 341 ").await;
    peer.send(":bob!user@remote JOIN #secret").await;
    let join = alice.expect("JOIN #secret").await;
    assert!(join.contains("bob"), "join was {join:?}");
}

#[tokio::test]
async fn introductions_are_forwarded_with_growing_hop_counts() {
    let harness = start().await;
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    let mut beta = Peer::connect(harness.link_addr, "beta.test", "0BB").await;

    assert_eq!(
        harness.server.route("alpha.test").map(|route| route.hops),
        Some(1)
    );

    let ts = 1_700_000_000;
    introduce_remote(&mut alpha, "alpha.test", "delta.test", "0DD", "dave", ts).await;

    // The second hop must carry the incremented count.
    let learned = beta.expect("SERVER delta.test").await;
    assert!(
        learned.contains(" SERVER delta.test 2 0DD delta.test"),
        "forwarded introduction was {learned:?}"
    );
    assert_eq!(
        harness.server.route("delta.test").map(|route| route.hops),
        Some(2)
    );

    let forwarded_user = beta.expect("NICK dave").await;
    assert!(
        forwarded_user.contains(" NICK dave 2 1700000000 user remote delta.test +i :Remote dave"),
        "forwarded user was {forwarded_user:?}"
    );

    // The remote user is visible to local clients.
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("WHOIS dave").await;
    let whois = alice.expect(" 311 ").await;
    assert!(whois.contains("dave user remote"), "whois was {whois:?}");
}

#[tokio::test]
async fn private_messages_follow_the_route() {
    let harness = start().await;
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    let mut beta = Peer::connect(harness.link_addr, "beta.test", "0BB").await;
    introduce_remote(
        &mut alpha,
        "alpha.test",
        "delta.test",
        "0DD",
        "dave",
        1_700_000_000,
    )
    .await;
    beta.expect("NICK dave").await;

    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("PRIVMSG dave :hello far away").await;

    let delivered = alpha.expect("PRIVMSG dave").await;
    assert!(
        delivered.contains("hello far away"),
        "delivered was {delivered:?}"
    );

    // beta is not on the route to delta.test, so it must see nothing.
    let unsolicited = beta.collect(Duration::from_millis(300)).await;
    assert!(
        !unsolicited.iter().any(|line| line.contains("PRIVMSG")),
        "message was flooded to a server off the route: {unsolicited:?}"
    );
}

#[tokio::test]
async fn channel_messages_cross_the_link() {
    let harness = start().await;
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    introduce_remote(
        &mut alpha,
        "alpha.test",
        "delta.test",
        "0DD",
        "dave",
        1_700_000_000,
    )
    .await;
    alpha.send(":dave!user@remote JOIN #room").await;

    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect("JOIN #room").await;

    alice.send("PRIVMSG #room :hello channel").await;
    let delivered = alpha.expect("PRIVMSG #room").await;
    assert!(
        delivered.contains("hello channel"),
        "channel message did not cross the link: {delivered:?}"
    );
}

#[tokio::test]
async fn link_loss_prunes_the_subtree() {
    let harness = start().await;
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    let mut beta = Peer::connect(harness.link_addr, "beta.test", "0BB").await;
    introduce_remote(
        &mut alpha,
        "alpha.test",
        "delta.test",
        "0DD",
        "dave",
        1_700_000_000,
    )
    .await;
    beta.expect("NICK dave").await;

    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect("JOIN #room").await;
    alpha.send(":dave!user@remote JOIN #room").await;
    alice.expect("dave").await;

    alpha.disconnect().await;

    let quit = alice.expect("QUIT").await;
    assert!(quit.starts_with(":dave!"), "quit was {quit:?}");
    assert!(harness.server.route("delta.test").is_none());
    assert!(harness.server.route("alpha.test").is_none());
    assert!(harness.server.find_nick("dave").is_none());

    let squit = beta.expect("SQUIT delta.test").await;
    assert!(squit.contains("SQUIT delta.test"), "squit was {squit:?}");
}

#[tokio::test]
async fn squit_removes_a_server_and_its_users() {
    let harness = start().await;
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    let mut beta = Peer::connect(harness.link_addr, "beta.test", "0BB").await;
    introduce_remote(
        &mut alpha,
        "alpha.test",
        "delta.test",
        "0DD",
        "dave",
        1_700_000_000,
    )
    .await;
    beta.expect("NICK dave").await;

    alpha.send("SQUIT delta.test :test split").await;

    let forwarded = beta.expect("SQUIT delta.test").await;
    assert!(forwarded.contains("test split"), "squit was {forwarded:?}");
    assert!(harness.server.route("delta.test").is_none());
    assert!(harness.server.find_nick("dave").is_none());
    // The server that carried delta.test is still linked.
    assert!(harness.server.route("alpha.test").is_some());
}

#[tokio::test]
async fn older_timestamp_wins_a_nick_collision() {
    let harness = start().await;
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;

    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    let local_ts = harness
        .server
        .find_nick("alice")
        .expect("local alice")
        .session(|session| session.ts);

    alpha
        .send(format!(
            ":alice!remote@remote NICK alice 1 {} remote remote alpha.test +i :Remote Alice",
            local_ts - 60
        ))
        .await;

    // The local client is disconnected by the collision.
    alice.expect("ERROR").await;
    let kill = alpha.expect("KILL alice").await;
    assert!(kill.contains("Nick collision"), "kill was {kill:?}");

    let winner = harness.server.find_nick("alice").expect("alice remains");
    assert!(!winner.is_local(), "the remote user must win");
    assert_eq!(winner.remote_server.as_deref(), Some("alpha.test"));
    assert_eq!(winner.session(|session| session.ts), local_ts - 60);
}

#[tokio::test]
async fn newer_timestamp_loses_a_nick_collision() {
    let harness = start().await;
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;

    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    let local_ts = harness
        .server
        .find_nick("alice")
        .expect("local alice")
        .session(|session| session.ts);

    alpha
        .send(format!(
            ":alice!remote@remote NICK alice 1 {} remote remote alpha.test +i :Remote Alice",
            local_ts + 60
        ))
        .await;

    let kill = alpha.expect("KILL alice").await;
    assert!(kill.contains("Nick collision"), "kill was {kill:?}");
    let survivor = harness.server.find_nick("alice").expect("alice remains");
    assert!(survivor.is_local(), "the local user must keep the nickname");

    // The client was never disconnected.
    alice.send("PING :alive").await;
    alice.expect("PONG").await;
}

#[tokio::test]
async fn equal_timestamps_break_on_server_name() {
    let harness = start().await;
    let mut later = Peer::connect(harness.link_addr, "zzz.test", "0ZZ").await;
    let mut earlier = Peer::connect(harness.link_addr, "aaa.test", "0AA").await;

    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    let local_ts = harness
        .server
        .find_nick("alice")
        .expect("local alice")
        .session(|session| session.ts);

    // irc.test sorts before zzz.test, so the local user wins the tie.
    later
        .send(format!(
            ":alice!remote@remote NICK alice 1 {local_ts} remote remote zzz.test +i :Remote Alice"
        ))
        .await;
    later.expect("KILL alice").await;
    assert!(harness.server.find_nick("alice").expect("alice").is_local());

    // aaa.test sorts before irc.test, so now the remote user wins the tie.
    earlier
        .send(format!(
            ":alice!remote@remote NICK alice 1 {local_ts} remote remote aaa.test +i :Remote Alice"
        ))
        .await;
    alice.expect("ERROR").await;
    let winner = harness.server.find_nick("alice").expect("alice");
    assert_eq!(winner.remote_server.as_deref(), Some("aaa.test"));
}

/// Poll server state until `predicate` holds; bursts are applied asynchronously.
async fn wait_for(server: &Arc<Server>, predicate: impl Fn(&Server) -> bool) {
    for _ in 0..200 {
        if predicate(server) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition was never met");
}

#[tokio::test]
async fn netburst_sends_local_state() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;
    alice.send("TOPIC #room :welcome").await;
    alice.expect("TOPIC #room").await;
    alice.send("MODE #room +R").await;
    alice.expect("MODE #room +R").await;
    alice.send("MODE #room +b *!*@bad.example").await;
    alice.expect("MODE #room +b").await;

    let mut peer = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    let user = peer.expect("NICK alice").await;
    assert!(user.contains(" alice 1 "), "burst user was {user:?}");
    let sjoin = peer.expect("SJOIN #room").await;
    assert!(sjoin.contains("@alice"), "sjoin was {sjoin:?}");
    assert!(sjoin.contains("+ntR"), "sjoin modes were {sjoin:?}");
    peer.expect("TOPIC #room").await;
    let ban = peer.expect("MODE #room +b").await;
    assert!(ban.contains("*!*@bad.example"), "ban was {ban:?}");
    peer.expect("EOB").await;
}

#[tokio::test]
async fn netburst_applies_remote_channel_state() {
    let harness = start().await;
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    let ts = 1_700_000_000u64;
    alpha
        .send(":alpha.test SERVER delta.test 1 0DD :delta.test")
        .await;
    alpha
        .send(format!(
            ":dave!user@remote NICK dave 1 {ts} user remote delta.test + :Dave"
        ))
        .await;
    alpha.send(format!("SJOIN #room {ts} +mnt :@dave")).await;
    alpha.send(":alpha.test TOPIC #room :welcome").await;
    alpha.send(":alpha.test MODE #room +b $a:troll").await;
    alpha.send(":alpha.test EOB").await;

    wait_for(&harness.server, |server| {
        server.find_channel("#room").is_some_and(|channel| {
            let guard = channel.read();
            !guard.bans.is_empty() && guard.topic.is_some()
        })
    })
    .await;

    {
        let channel = harness.server.find_channel("#room").expect("channel");
        let guard = channel.read();
        assert_eq!(guard.members.len(), 1);
        assert!(guard.moderated && guard.no_external);
        assert_eq!(guard.topic.as_deref(), Some("welcome"));
        assert!(guard.bans.iter().any(|ban| ban.mask == "$a:troll"));
        assert_eq!(guard.created, ts);
        let dave = harness.server.find_nick("dave").expect("remote user");
        assert!(guard.is_op(dave.id), "burst member lost operator status");
    }

    // A local user sees the bursted topic and membership. The server sends the
    // topic numerics before the member list.
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    let topic = alice.expect(" 332 ").await;
    assert!(topic.contains("welcome"), "topic was {topic:?}");
    let names = alice.expect(" 353 ").await;
    assert!(names.contains("@dave"), "names was {names:?}");
}

#[tokio::test]
async fn netburst_merges_modes_per_mode() {
    let harness = start().await;
    let mut alice = Client::connect(harness.client_addr).await;
    alice.register("alice").await;
    alice.send("JOIN #room").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #room +m").await;
    alice.expect("MODE #room +m").await;
    let local_ts = harness
        .server
        .find_channel("#room")
        .expect("channel")
        .read()
        .created;

    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    alpha
        .send(":alpha.test SERVER delta.test 1 0DD :delta.test")
        .await;
    alpha
        .send(format!(
            ":dave!user@remote NICK dave 1 {} user remote delta.test +i :Dave",
            local_ts + 1
        ))
        .await;

    // An older channel contributes its own modes but cannot clear +m.
    alpha
        .send(format!("SJOIN #room {} +i :@dave", local_ts - 100))
        .await;
    wait_for(&harness.server, |server| {
        server
            .find_channel("#room")
            .is_some_and(|channel| channel.read().invite_only)
    })
    .await;
    {
        let channel = harness.server.find_channel("#room").expect("channel");
        let guard = channel.read();
        assert!(guard.invite_only, "the older copy contributes +i");
        assert!(guard.moderated, "+m must survive the merge");
        assert_eq!(guard.created, local_ts - 100);
    }

    // A newer channel merges its modes too; only arguments follow the TS.
    alpha
        .send(format!("SJOIN #room {} +s :dave", local_ts + 100))
        .await;
    wait_for(&harness.server, |server| {
        server
            .find_channel("#room")
            .is_some_and(|channel| channel.read().secret)
    })
    .await;
    {
        let channel = harness.server.find_channel("#room").expect("channel");
        let guard = channel.read();
        assert!(guard.invite_only, "+i must survive a newer burst");
        assert!(guard.secret, "the newer copy contributes +s");
        assert!(guard.moderated, "+m must survive a newer burst");
        assert_eq!(guard.created, local_ts - 100, "the older TS still wins");
    }
}

#[tokio::test]
async fn netburst_sjoin_is_forwarded_to_other_links() {
    let harness = start().await;
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    let mut beta = Peer::connect(harness.link_addr, "beta.test", "0BB").await;
    alpha
        .send(":alpha.test SERVER delta.test 1 0DD :delta.test")
        .await;
    alpha
        .send(":dave!user@remote NICK dave 1 1700000000 user remote delta.test +i :Dave")
        .await;
    alpha.send("SJOIN #room 1700000000 +nt :@dave").await;

    let forwarded = beta.expect("SJOIN #room").await;
    assert!(
        forwarded.contains("@dave"),
        "forwarded burst was {forwarded:?}"
    );
}

#[tokio::test]
async fn reconnect_burst_restores_lost_state() {
    let harness = start().await;
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    alpha
        .send(":alpha.test SERVER delta.test 1 0DD :delta.test")
        .await;
    alpha
        .send(":dave!user@remote NICK dave 1 1700000000 user remote delta.test +i :Dave")
        .await;
    wait_for(&harness.server, |server| server.find_nick("dave").is_some()).await;

    alpha.disconnect().await;
    wait_for(&harness.server, |server| server.find_nick("dave").is_none()).await;

    // Reconnecting after the split replays the state instead of leaving the
    // user unknown until something changes.
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    alpha
        .send(":alpha.test SERVER delta.test 1 0DD :delta.test")
        .await;
    alpha
        .send(":dave!user@remote NICK dave 1 1700000000 user remote delta.test +i :Dave")
        .await;
    wait_for(&harness.server, |server| server.find_nick("dave").is_some()).await;
    assert!(harness.server.route("delta.test").is_some());
}

#[tokio::test]
async fn duplicate_server_links_are_rejected() {
    let harness = start().await;
    let mut alpha = Peer::connect(harness.link_addr, "alpha.test", "0AA").await;
    // Keep the peer alive so the link is not dropped before the second dial.
    alpha.send("PING :keep").await;
    alpha.expect("PONG").await;

    let mut duplicate = Peer::begin(harness.link_addr, "alpha.test", "0A2").await;
    duplicate.send(format!("PASS {LINK_PASSWORD}")).await;
    duplicate.send("SERVER alpha.test 1 0A2 :second path").await;
    let error = duplicate.expect("ERROR").await;
    assert!(
        error.contains("already connected"),
        "second link was not refused: {error:?}"
    );
    assert_eq!(harness.server.links.len(), 1);
}

impl Peer {
    /// Connect and send nothing, so a test can drive the handshake itself.
    async fn begin(address: SocketAddr, name: &str, _sid: &str) -> Self {
        let stream = TcpStream::connect(address).await.expect("connect link");
        let (read, write) = stream.into_split();
        Self {
            reader: BufReader::new(read),
            writer: write,
            seen: Vec::new(),
            name: name.to_owned(),
        }
    }
}
