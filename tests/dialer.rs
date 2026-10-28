//! Outbound link tests: two real daemons, one dialling the other.
//!
//! Nothing here is scripted. The dialling server resolves, connects, sends its
//! own `PASS`/`SERVER`, and the accepting server runs its normal link path, so
//! these tests cover the path an operator actually uses.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use ircd::auth::{AccountBackend, Credential};
use ircd::config::{Config, LinkSection, ListenSection};
use ircd::net;
use ircd::server::Server;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

const PASSWORD: &str = "dial-secret";
const PASSWORD_ENV: &str = "RS_IRCD_TEST_DIAL_PASSWORD";

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

    async fn next_line(&mut self) -> String {
        let mut line = String::new();
        let read = tokio::time::timeout(Duration::from_secs(3), self.reader.read_line(&mut line))
            .await
            .unwrap_or_else(|_| panic!("timed out reading a line; saw {:?}", self.seen))
            .expect("read");
        assert_ne!(read, 0, "connection closed; saw {:?}", self.seen);
        line.trim_end_matches(['\r', '\n']).to_owned()
    }

    async fn expect(&mut self, needle: &str) -> String {
        for _ in 0..100 {
            let trimmed = self.next_line().await;
            if trimmed.contains(needle) {
                return trimmed;
            }
            self.seen.push(trimmed);
        }
        panic!("never saw {needle:?}; saw {:?}", self.seen);
    }

    /// Authenticate with SASL `PLAIN`, before or after registration.
    async fn authenticate(&mut self, account: &str, password: &str) {
        self.send("AUTHENTICATE PLAIN").await;
        self.expect("AUTHENTICATE +").await;
        let payload =
            base64::engine::general_purpose::STANDARD.encode(format!("\0{account}\0{password}"));
        self.send(format!("AUTHENTICATE {payload}")).await;
        self.expect(" 903 ").await;
    }

    /// Ask `WHOIS` and return the `330` account line, when the server sends one.
    async fn whois_account(&mut self, nick: &str) -> Option<String> {
        self.send(format!("WHOIS {nick}")).await;
        let mut account = None;
        for _ in 0..60 {
            let line = self.next_line().await;
            if line.contains(" 318 ") {
                return account;
            }
            if line.contains(" 330 ") {
                account = Some(line);
            } else {
                self.seen.push(line);
            }
        }
        panic!("WHOIS {nick} never finished; saw {:?}", self.seen);
    }

    async fn register(&mut self, nick: &str) {
        self.send(format!("NICK {nick}")).await;
        self.send(format!("USER {nick} 0 * :{nick} real")).await;
        self.expect(" 001 ").await;
    }

    async fn close(mut self) {
        let _ = self.writer.shutdown().await;
    }
}

fn base(name: &str, sid: &str) -> Config {
    let mut config = Config::default();
    config.server.name = name.to_owned();
    config.server.sid = sid.to_owned();
    config.server.network = "DialNet".to_owned();
    config.server.description = format!("{name} test server");
    config.server.link_password_env = Some(PASSWORD_ENV.to_owned());
    config.listen.push(ListenSection {
        addresses: vec!["127.0.0.1".parse().expect("ipv4")],
        port: 0,
        tls: false,
        server_link: false,
    });
    config
}

fn link_listener() -> ListenSection {
    ListenSection {
        addresses: vec!["127.0.0.1".parse().expect("ipv4")],
        port: 0,
        tls: false,
        server_link: true,
    }
}

async fn start(config: Config) -> (Arc<Server>, Vec<SocketAddr>) {
    let config = Arc::new(config);
    let server = Server::new(Arc::clone(&config), None).expect("server state");
    let listeners = net::bind(&config).expect("bind");
    let addresses = listeners.iter().map(|listener| listener.local).collect();
    for listener in listeners {
        net::spawn_accept_loop(Arc::clone(&server), listener);
    }
    (server, addresses)
}

/// Poll until `predicate` holds; the dialler works in real time.
async fn wait_until(server: &Arc<Server>, what: &str, predicate: impl Fn(&Server) -> bool) {
    for _ in 0..250 {
        if predicate(server) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Like [`wait_until`], but with a horizon long enough for a dialler retry.
async fn wait_long(server: &Arc<Server>, what: &str, predicate: impl Fn(&Server) -> bool) {
    for _ in 0..400 {
        if predicate(server) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

fn channel_created(server: &Server, name: &str) -> u64 {
    server
        .find_channel(name)
        .expect("channel exists")
        .read()
        .created
}

fn channel_members(server: &Server, name: &str) -> usize {
    server
        .find_channel(name)
        .map_or(0, |channel| channel.read().members.len())
}

fn channel_bans(server: &Server, name: &str) -> usize {
    server
        .find_channel(name)
        .map_or(0, |channel| channel.read().bans.len())
}

fn link_to(name: &str, port: u16) -> LinkSection {
    LinkSection {
        name: name.to_owned(),
        address: "127.0.0.1".to_owned(),
        port,
        retry_initial_secs: 1,
        retry_max_secs: 2,
        ..LinkSection::default()
    }
}

/// Start a dialling server pointed at `port` and return it with its client port.
async fn start_dialler(name: &str, sid: &str, port: u16) -> (Arc<Server>, SocketAddr) {
    let mut config = base(name, sid);
    config.links.push(link_to("beta.test", port));
    let (server, addresses) = start(config).await;
    net::dialer::spawn_all(Arc::clone(&server));
    (server, addresses[0])
}

#[tokio::test]
async fn dialer_connects_and_carries_traffic() {
    std::env::set_var(PASSWORD_ENV, PASSWORD);
    let mut beta = base("beta.test", "0BB");
    beta.listen.push(link_listener());
    let (beta_server, beta_addresses) = start(beta).await;
    assert_eq!(beta_addresses.len(), 2, "client and link listener");

    let (alpha_server, alpha_address) =
        start_dialler("alpha.test", "0AA", beta_addresses[1].port()).await;

    wait_until(&alpha_server, "route to beta", |server| {
        server.route("beta.test").is_some()
    })
    .await;
    wait_until(&beta_server, "route to alpha", |server| {
        server.route("alpha.test").is_some()
    })
    .await;

    let mut alice = Client::connect(alpha_address).await;
    alice.register("alice").await;
    let mut bob = Client::connect(beta_addresses[0]).await;
    bob.register("bob").await;
    wait_until(&alpha_server, "bob introduced", |server| {
        server.find_nick("bob").is_some()
    })
    .await;

    alice.send("PRIVMSG bob :hello over the dialled link").await;
    bob.expect("hello over the dialled link").await;
    alice.close().await;
    bob.close().await;
}

#[tokio::test]
async fn dialer_verifies_a_tls_link_against_the_configured_authority() {
    std::env::set_var(PASSWORD_ENV, PASSWORD);
    let directory = tempfile::tempdir().expect("temp dir");
    let certified =
        rcgen::generate_simple_self_signed(vec!["beta.test".to_owned()]).expect("certificate");
    let certificate_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&certificate_path, certified.cert.pem()).expect("write cert");
    std::fs::write(&key_path, certified.key_pair.serialize_pem()).expect("write key");

    let mut beta = base("beta.test", "0BB");
    beta.tls.cert_path = Some(certificate_path.to_string_lossy().into_owned());
    beta.tls.key_path = Some(key_path.to_string_lossy().into_owned());
    let mut listener = link_listener();
    listener.tls = true;
    beta.listen.push(listener);
    let (beta_server, beta_addresses) = start(beta).await;

    let mut alpha = base("alpha.test", "0AA");
    let mut link = link_to("beta.test", beta_addresses[1].port());
    link.tls = true;
    link.tls_ca_path = Some(certificate_path.to_string_lossy().into_owned());
    alpha.links.push(link);
    let (alpha_server, _) = start(alpha).await;
    net::dialer::spawn_all(Arc::clone(&alpha_server));

    wait_until(&alpha_server, "TLS route to beta", |server| {
        server.route("beta.test").is_some()
    })
    .await;
    wait_until(&beta_server, "TLS route to alpha", |server| {
        server.route("alpha.test").is_some()
    })
    .await;

    // A link is only useful if it carries the protocol, not just a handshake.
    let mut alice = Client::connect(beta_addresses[0]).await;
    alice.register("alice").await;
    alice.send("LINKS").await;
    let listing = alice.expect(" 364 ").await;
    assert!(
        listing.contains("beta.test"),
        "links listing was {listing:?}"
    );
    alice.close().await;
}

#[tokio::test]
async fn dialer_reconnects_after_a_drop_and_replays_state() {
    std::env::set_var(PASSWORD_ENV, PASSWORD);
    let mut beta = base("beta.test", "0BB");
    beta.listen.push(link_listener());
    let (beta_server, beta_addresses) = start(beta).await;

    let (alpha_server, alpha_address) =
        start_dialler("alpha.test", "0AA", beta_addresses[1].port()).await;
    wait_until(&alpha_server, "initial route", |server| {
        server.route("beta.test").is_some()
    })
    .await;
    wait_until(&beta_server, "initial route", |server| {
        server.route("alpha.test").is_some()
    })
    .await;

    let mut bob = Client::connect(beta_addresses[0]).await;
    bob.register("bob").await;
    wait_until(&alpha_server, "bob introduced", |server| {
        server.find_nick("bob").is_some()
    })
    .await;
    // One user on each side, so the test can prove both bursts are sent.
    let mut alice = Client::connect(alpha_address).await;
    alice.register("alice").await;
    wait_until(&beta_server, "alice introduced", |server| {
        server.find_nick("alice").is_some()
    })
    .await;

    // Drop the link from the accepting side, the way a network failure would.
    let link = beta_server
        .links
        .iter()
        .map(|entry| *entry.key())
        .next()
        .expect("one link");
    let handle = beta_server.find_client(link).expect("link handle");
    beta_server.disconnect(&handle, "test drop");

    wait_until(&alpha_server, "pruned route", |server| {
        server.route("beta.test").is_none()
    })
    .await;
    wait_until(&beta_server, "pruned route", |server| {
        server.route("alpha.test").is_none()
    })
    .await;
    wait_until(&alpha_server, "bob pruned", |server| {
        server.find_nick("bob").is_none()
    })
    .await;
    wait_until(&beta_server, "alice pruned", |server| {
        server.find_nick("alice").is_none()
    })
    .await;

    // The dialler reconnects on its own and each side bursts its own users, so
    // both halves of the network come back without a live event to trigger it.
    wait_until(&alpha_server, "restored route", |server| {
        server.route("beta.test").is_some()
    })
    .await;
    wait_until(&beta_server, "restored route", |server| {
        server.route("alpha.test").is_some()
    })
    .await;
    wait_until(&alpha_server, "bob restored", |server| {
        server.find_nick("bob").is_some()
    })
    .await;
    wait_until(&beta_server, "alice restored", |server| {
        server.find_nick("alice").is_some()
    })
    .await;
    alice.close().await;
    bob.close().await;
}

#[tokio::test]
async fn dialer_heals_diverged_channels_after_a_reconnect() {
    std::env::set_var(PASSWORD_ENV, PASSWORD);
    let mut beta = base("beta.test", "0BB");
    beta.listen.push(link_listener());
    let (beta_server, beta_addresses) = start(beta).await;

    // A slow retry leaves time to build a genuine divergence before the
    // dialler reconnects on its own.
    let mut alpha = base("alpha.test", "0AA");
    let mut link = link_to("beta.test", beta_addresses[1].port());
    link.retry_initial_secs = 4;
    link.retry_max_secs = 4;
    alpha.links.push(link);
    let (alpha_server, alpha_addresses) = start(alpha).await;
    net::dialer::spawn_all(Arc::clone(&alpha_server));
    let alpha_address = alpha_addresses[0];

    wait_until(&alpha_server, "initial route", |server| {
        server.route("beta.test").is_some()
    })
    .await;
    wait_until(&beta_server, "initial route", |server| {
        server.route("alpha.test").is_some()
    })
    .await;

    let mut alice = Client::connect(alpha_address).await;
    alice.register("alice").await;
    let mut bob = Client::connect(beta_addresses[0]).await;
    bob.register("bob").await;
    wait_until(&alpha_server, "bob introduced", |server| {
        server.find_nick("bob").is_some()
    })
    .await;
    wait_until(&beta_server, "alice introduced", |server| {
        server.find_nick("alice").is_some()
    })
    .await;

    let link = beta_server
        .links
        .iter()
        .map(|entry| *entry.key())
        .next()
        .expect("one link");
    let handle = beta_server.find_client(link).expect("link handle");
    beta_server.disconnect(&handle, "test split");
    wait_until(&alpha_server, "pruned route", |server| {
        server.route("beta.test").is_none()
    })
    .await;
    wait_until(&beta_server, "pruned route", |server| {
        server.route("alpha.test").is_none()
    })
    .await;

    // Each side builds its own copy of the same channel, a second apart so the
    // two timestamps cannot tie.
    alice.send("JOIN #split").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #split +m").await;
    alice.expect("MODE #split +m").await;
    alice.send("TOPIC #split :alpha topic").await;
    alice.expect("TOPIC #split").await;
    alice.send("MODE #split +b $a:troll").await;
    alice.expect("MODE #split +b").await;

    tokio::time::sleep(Duration::from_millis(1_100)).await;

    bob.send("JOIN #split").await;
    bob.expect(" 366 ").await;
    bob.send("MODE #split +i").await;
    bob.expect("MODE #split +i").await;
    bob.send("MODE #split +k betakey").await;
    bob.expect("MODE #split +k betakey").await;
    bob.send("TOPIC #split :beta topic").await;
    bob.expect("TOPIC #split").await;
    bob.send("MODE #split +b *!*@beta.example").await;
    bob.expect("MODE #split +b").await;

    let alpha_ts = channel_created(&alpha_server, "#split");
    let beta_ts = channel_created(&beta_server, "#split");
    assert!(
        alpha_ts < beta_ts,
        "the two copies must have distinct timestamps: {alpha_ts} vs {beta_ts}"
    );

    // The dialler redials by itself; both bursts then merge the two copies.
    wait_long(&alpha_server, "restored route", |server| {
        server.route("beta.test").is_some()
    })
    .await;
    wait_long(&beta_server, "restored route", |server| {
        server.route("alpha.test").is_some()
    })
    .await;
    for (server, label) in [(&alpha_server, "alpha"), (&beta_server, "beta")] {
        wait_long(server, "merged members", |server| {
            channel_members(server, "#split") == 2
        })
        .await;
        wait_long(server, "merged bans", |server| {
            channel_bans(server, "#split") == 2
        })
        .await;
        let channel = server.find_channel("#split").expect("channel");
        let guard = channel.read();
        assert_eq!(
            guard.created, alpha_ts,
            "{label} must adopt the older timestamp"
        );
        assert_eq!(
            guard.topic.as_deref(),
            Some("alpha topic"),
            "{label} must keep the older topic"
        );
        assert!(guard.moderated, "{label} lost +m from the older copy");
        assert!(guard.invite_only, "{label} lost +i from the newer copy");
        assert_eq!(
            guard.key.as_deref(),
            Some("betakey"),
            "{label} lost the merged +k"
        );
        let mut masks: Vec<&str> = guard.bans.iter().map(|entry| entry.mask.as_str()).collect();
        masks.sort_unstable();
        assert_eq!(
            masks,
            ["$a:troll", "*!*@beta.example"],
            "{label} did not merge both ban lists"
        );
    }

    alice.close().await;
    bob.close().await;
}

#[tokio::test]
async fn chain_heals_across_a_forwarding_hop() {
    std::env::set_var(PASSWORD_ENV, PASSWORD);
    let mut beta = base("beta.test", "0BB");
    beta.listen.push(link_listener());
    let (beta_server, beta_addresses) = start(beta).await;

    // gamma dials beta first, so beta already holds gamma's state when alpha
    // arrives and the line is alpha - beta - gamma with beta in the middle.
    let mut gamma = base("gamma.test", "0GG");
    gamma
        .links
        .push(link_to("beta.test", beta_addresses[1].port()));
    let (gamma_server, gamma_addresses) = start(gamma).await;
    net::dialer::spawn_all(Arc::clone(&gamma_server));

    // A slow retry on this edge leaves time to build divergence after the
    // split; the beta - gamma edge stays up throughout.
    let mut alpha = base("alpha.test", "0AA");
    let mut link = link_to("beta.test", beta_addresses[1].port());
    link.retry_initial_secs = 4;
    link.retry_max_secs = 4;
    alpha.links.push(link);
    let (alpha_server, alpha_addresses) = start(alpha).await;
    net::dialer::spawn_all(Arc::clone(&alpha_server));

    wait_long(&alpha_server, "route to gamma through beta", |server| {
        server.route("gamma.test").is_some()
    })
    .await;
    wait_long(&gamma_server, "route to alpha through beta", |server| {
        server.route("alpha.test").is_some()
    })
    .await;

    let mut alice = Client::connect(alpha_addresses[0]).await;
    alice.register("alice").await;
    let mut carol = Client::connect(gamma_addresses[0]).await;
    carol.register("carol").await;
    wait_long(&gamma_server, "alice forwarded two hops", |server| {
        server.find_nick("alice").is_some()
    })
    .await;
    wait_long(&alpha_server, "carol forwarded two hops", |server| {
        server.find_nick("carol").is_some()
    })
    .await;

    // Cut the edge on the far side from gamma, so healing has to cross beta.
    let alpha_link = beta_server
        .links
        .iter()
        .find(|entry| entry.value().eq_ignore_ascii_case("alpha.test"))
        .map(|entry| *entry.key())
        .expect("link to alpha");
    let handle = beta_server.find_client(alpha_link).expect("link handle");
    beta_server.disconnect(&handle, "test split");

    wait_long(&alpha_server, "route to beta pruned", |server| {
        server.route("beta.test").is_none()
    })
    .await;
    wait_long(
        &gamma_server,
        "route to alpha pruned by the squit",
        |server| server.route("alpha.test").is_none(),
    )
    .await;
    wait_long(&gamma_server, "alice pruned", |server| {
        server.find_nick("alice").is_none()
    })
    .await;

    // Each side of the split builds state the other side cannot see.
    alice.send("JOIN #split-alpha").await;
    alice.expect(" 366 ").await;
    alice.send("MODE #split-alpha +m").await;
    alice.expect("MODE #split-alpha +m").await;
    alice.send("TOPIC #split-alpha :alpha only").await;
    alice.expect("TOPIC #split-alpha").await;

    carol.send("JOIN #split-gamma").await;
    carol.expect(" 366 ").await;
    carol.send("MODE #split-gamma +i").await;
    carol.expect("MODE #split-gamma +i").await;
    carol.send("TOPIC #split-gamma :gamma only").await;
    carol.expect("TOPIC #split-gamma").await;

    assert!(alpha_server.find_channel("#split-gamma").is_none());
    assert!(gamma_server.find_channel("#split-alpha").is_none());

    // The dialler restores the edge and the bursts travel through beta, so
    // gamma ends up with a channel two hops away and alpha with the mirror.
    wait_long(&alpha_server, "restored route to gamma", |server| {
        server.route("gamma.test").is_some()
    })
    .await;
    wait_long(&gamma_server, "restored route to alpha", |server| {
        server.route("alpha.test").is_some()
    })
    .await;
    wait_long(&gamma_server, "forwarded channel", |server| {
        server.find_channel("#split-alpha").is_some()
    })
    .await;
    wait_long(&alpha_server, "mirror channel", |server| {
        server.find_channel("#split-gamma").is_some()
    })
    .await;

    for (server, label) in [
        (&alpha_server, "alpha"),
        (&beta_server, "beta"),
        (&gamma_server, "gamma"),
    ] {
        let alice = server
            .find_nick("alice")
            .unwrap_or_else(|| panic!("{label} does not know alice"))
            .id;
        let carol = server
            .find_nick("carol")
            .unwrap_or_else(|| panic!("{label} does not know carol"))
            .id;
        {
            let channel = server.find_channel("#split-alpha").expect("#split-alpha");
            let guard = channel.read();
            assert!(guard.moderated, "{label} lost +m across the hop");
            assert_eq!(
                guard.topic.as_deref(),
                Some("alpha only"),
                "{label} lost the topic on #split-alpha"
            );
            assert!(guard.contains(alice), "{label} lost alice");
        }
        {
            let channel = server.find_channel("#split-gamma").expect("#split-gamma");
            let guard = channel.read();
            assert!(guard.invite_only, "{label} lost +i across the hop");
            assert_eq!(
                guard.topic.as_deref(),
                Some("gamma only"),
                "{label} lost the topic on #split-gamma"
            );
            assert!(guard.contains(carol), "{label} lost carol");
        }
    }

    alice.close().await;
    carol.close().await;
}

/// Account backend standing in for an external directory service.
#[derive(Debug)]
struct FixedAccounts {
    account: &'static str,
    password: &'static str,
}

impl AccountBackend for FixedAccounts {
    fn name(&self) -> &'static str {
        "dialer-test"
    }

    fn mechanisms(&self) -> &'static [&'static str] {
        &["PLAIN"]
    }

    fn verify(&self, credential: &Credential<'_>) -> Option<String> {
        match credential {
            Credential::Plain { account, password }
                if *account == self.account && *password == self.password =>
            {
                Some((*account).to_owned())
            }
            Credential::Plain { .. } | Credential::External { .. } => None,
        }
    }
}

async fn linked_pair(
    accounts: Option<Arc<dyn AccountBackend>>,
) -> (Arc<Server>, Vec<SocketAddr>, Arc<Server>, SocketAddr) {
    std::env::set_var(PASSWORD_ENV, PASSWORD);
    let mut beta = base("beta.test", "0BB");
    beta.listen.push(link_listener());
    let (beta_server, beta_addresses) = start(beta).await;
    if let Some(accounts) = accounts {
        beta_server.set_account_backend(accounts);
    }
    let (alpha_server, alpha_address) =
        start_dialler("alpha.test", "0AA", beta_addresses[1].port()).await;
    wait_until(&alpha_server, "route to beta", |server| {
        server.route("beta.test").is_some()
    })
    .await;
    wait_until(&beta_server, "route to alpha", |server| {
        server.route("alpha.test").is_some()
    })
    .await;
    (alpha_server, beta_addresses, beta_server, alpha_address)
}

fn shadow_account(server: &Server, nick: &str) -> Option<String> {
    server
        .find_nick(nick)
        .and_then(|user| user.session(|session| session.account.clone()))
}

#[tokio::test]
async fn account_login_after_registration_propagates_over_the_link() {
    let (alpha_server, beta_addresses, _beta_server, alpha_address) =
        linked_pair(Some(Arc::new(FixedAccounts {
            account: "bob",
            password: "hunter2",
        })))
        .await;

    let mut bob = Client::connect(beta_addresses[0]).await;
    bob.register("bob").await;
    wait_until(&alpha_server, "bob introduced", |server| {
        server.find_nick("bob").is_some()
    })
    .await;

    let mut watcher = Client::connect(alpha_address).await;
    watcher.register("watcher").await;
    assert!(
        watcher.whois_account("bob").await.is_none(),
        "an unauthenticated user must not report an account"
    );

    // Logging in after registration has to reach the other server too.
    bob.authenticate("bob", "hunter2").await;
    wait_until(&alpha_server, "account propagated", |server| {
        shadow_account(server, "bob").is_some()
    })
    .await;
    let line = watcher
        .whois_account("bob")
        .await
        .expect("account line missing after login");
    assert!(line.contains("is logged in as"), "330 was {line:?}");
    bob.close().await;
    watcher.close().await;
}

#[tokio::test]
async fn account_survives_a_link_drop_and_the_netburst() {
    let (alpha_server, beta_addresses, beta_server, alpha_address) =
        linked_pair(Some(Arc::new(FixedAccounts {
            account: "alice",
            password: "hunter2",
        })))
        .await;

    let mut alice = Client::connect(beta_addresses[0]).await;
    alice.authenticate("alice", "hunter2").await;
    alice.register("alice").await;
    wait_until(
        &alpha_server,
        "alice introduced with her account",
        |server| shadow_account(server, "alice").is_some(),
    )
    .await;

    let mut watcher = Client::connect(alpha_address).await;
    watcher.register("watcher").await;
    assert!(watcher.whois_account("alice").await.is_some());

    // The burst is the only thing that can restore the account after a split.
    let link = beta_server
        .links
        .iter()
        .map(|entry| *entry.key())
        .next()
        .expect("one link");
    let handle = beta_server.find_client(link).expect("link handle");
    beta_server.disconnect(&handle, "test drop");
    wait_until(&alpha_server, "alice pruned", |server| {
        server.find_nick("alice").is_none()
    })
    .await;
    wait_until(&alpha_server, "alice restored", |server| {
        shadow_account(server, "alice").is_some()
    })
    .await;

    let line = watcher
        .whois_account("alice")
        .await
        .expect("account line missing after the burst");
    assert!(line.contains("is logged in as"), "330 was {line:?}");
    alice.close().await;
    watcher.close().await;
}

#[tokio::test]
async fn sasl_logout_relays_the_cleared_account() {
    let (alpha_server, beta_addresses, _beta_server, alpha_address) =
        linked_pair(Some(Arc::new(FixedAccounts {
            account: "alice",
            password: "hunter2",
        })))
        .await;

    let mut alice = Client::connect(beta_addresses[0]).await;
    alice.register("alice").await;
    alice.authenticate("alice", "hunter2").await;
    wait_until(&alpha_server, "account propagated", |server| {
        shadow_account(server, "alice").is_some()
    })
    .await;

    let mut watcher = Client::connect(alpha_address).await;
    watcher.register("watcher").await;
    assert!(watcher.whois_account("alice").await.is_some());

    alice.send("LOGOUT").await;
    let line = alice.expect(" 901 ").await;
    assert!(line.contains("logged out"), "901 was {line:?}");

    // The `ACCOUNT *` relay is the only thing that can clear the shadow.
    wait_until(&alpha_server, "account cleared", |server| {
        shadow_account(server, "alice").is_none()
    })
    .await;
    assert!(
        watcher.whois_account("alice").await.is_none(),
        "the remote account must be gone after LOGOUT"
    );
    alice.close().await;
    watcher.close().await;
}
