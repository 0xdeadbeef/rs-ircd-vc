//! End-to-end coverage for compiled guard rules.
//!
//! Rule semantics are unit-tested in `ircd::script::rules`; this proves the
//! wiring: a rule loaded from `[scripting] rules` runs inside the real command
//! path and its notice reaches the client.

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

    async fn close(mut self) {
        let _ = self.writer.shutdown().await;
    }
}

const RULES: &str = r#"
[[rule]]
name = "no-badword"
hook = "command"
command = "PRIVMSG"
text = "*badword*"
action = "deny"
notice = "That word is not welcome here"

[[rule]]
name = "advertise"
hook = "command"
command = "PRIVMSG"
text = "*please-login*"
action = "notice"
notice = "This network prefers account-based access"
"#;

#[tokio::test]
async fn rules_run_inside_the_command_path() {
    let directory = tempfile::tempdir().expect("temp dir");
    let rules = directory.path().join("rules.toml");
    std::fs::write(&rules, RULES).expect("write rules");

    let mut config = Config::default();
    config.server.name = "irc.test".to_owned();
    config.server.network = "TestNet".to_owned();
    config.server.description = "test server".to_owned();
    config.scripting.enabled = true;
    config.scripting.rules = vec![rules.to_string_lossy().into_owned()];
    config.listen.push(ListenSection {
        addresses: vec!["127.0.0.1".parse().expect("ipv4")],
        port: 0,
        tls: false,
        server_link: false,
    });

    let config = Arc::new(config);
    let server = Server::new(Arc::clone(&config), None).expect("server state");
    assert!(server.scripts_enabled(), "rules must switch scripting on");
    let listeners = net::bind(&config).expect("bind");
    let address = listeners[0].local;
    for listener in listeners {
        net::spawn_accept_loop(Arc::clone(&server), listener);
    }

    let mut alice = Client::connect(address).await;
    alice.register("alice").await;

    // A matching deny replaces command handling entirely: the notice arrives
    // and there is no `403` for the nonexistent channel.
    alice.send("PRIVMSG #nowhere :this contains badword").await;
    let notice = alice.expect("NOTICE").await;
    assert!(
        notice.contains("That word is not welcome here"),
        "unexpected notice: {notice}"
    );

    // A non-matching message reaches the command handler as usual.
    alice.send("PRIVMSG #nowhere :hello").await;
    alice.expect(" 403 ").await;

    // `notice` rules let the command run and add the advisory.
    alice.send("PRIVMSG #nowhere :please-login").await;
    let advisory = alice.expect("NOTICE").await;
    assert!(
        advisory.contains("prefers account-based access"),
        "unexpected notice: {advisory}"
    );
    alice.expect(" 403 ").await;

    alice.close().await;
}
