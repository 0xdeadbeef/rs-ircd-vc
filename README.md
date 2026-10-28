# rs-ircd

An IRC daemon written in Rust. It implements the RFC 1459 client protocol and
the RFC 2810-2813 architecture, with TLS, optional connection compression, a
Rhai scripting layer and structured logging.

![status](https://img.shields.io/badge/tests-113%20passing-brightgreen)

## What it does

* **Protocol**: RFC 1459/2812 client commands, RFC 2811 channel modes, and
  RFC 2813 peer links with multi-hop routing and timestamp collision
  resolution. IRCv3 `CAP` with ten capabilities including `sasl`,
  `account-tag` and `message-tags`.
* **Accounts**: IRCv3 SASL `PLAIN` and `EXTERNAL` over a pluggable account
  backend, with optional mandatory authentication.
* **Transport**: any number of IPv4 and IPv6 listeners from one configuration;
  `0.0.0.0` binds all IPv4 and `[::]` all IPv6 (with `IPV6_V6ONLY` set so both
  can share a port). TLS 1.2/1.3 with PEM certificates, plaintext or
  passphrase-encrypted PKCS#8 keys.
* **Compression**: `COMPRESS zlib` negotiation with an explicit length-prefixed
  frame format, configurable level, and a decompression-bomb ceiling.
* **Operations**: daemonisation on Unix, console/file/syslog logging (Windows
  Event Log on Windows), runtime-reloadable log filter, PID file, bounded
  queues, ping timeouts, graceful shutdown, `SIGHUP` rehash.
* **Extensibility**: compiled guard rules plus Rhai hooks (`on_command`, `on_connect`, `on_join`) and
  script-defined commands, with instruction and memory limits.
* **Diagnostics**: an operator-only `BENCH` command that measures the parse,
  casemap and serialisation hot paths on a live server.

## Build and run

```bash
cargo build --release
./target/release/rs-ircd init            # writes ircd.toml
./target/release/rs-ircd --check         # validate the configuration
./target/release/rs-ircd                 # run in the foreground
```

Daemonise by setting `daemon.enabled = true`; a `pid_file` is written after the
double fork. Configuration comes from `ircd.toml` (see `ircd.toml.example`); the
path is `--config`.

## Secrets

No password is stored in the configuration file. Each password is an
environment-variable name, loaded from the environment or a `.env` file
(`.env.example` documents the variables):

```bash
# Operator hash: printed to stdout, never passed as an argument.
printf '%s' 'my-oper-password' | ./target/release/rs-ircd hash
export IRCD_OPER_ADMIN_HASH=...
export IRCD_LINK_PASSWORD=...
```

`ircd.toml` must therefore define `password_hash_env` for every operator,
`password_env` for the optional client password and `link_password_env` for
server links. Without a link password, links are refused rather than accepted
insecurely.

## TLS

```toml
[tls]
cert_path = "cert.pem"
key_path = "key.pem"
min_version = "1.2"
```

A development certificate:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=irc.example.org"
```

Encrypted PKCS#8 keys are supported through `key_password_env`. Pointing
`[[listen]] tls = true` at port 6697 follows RFC 7194's convention.

Note: RFC 7184 is an OLSRv2 MIB and unrelated to IRC; RFC 7194 is the IRC TLS
port convention referenced here.

## Compression

```toml
[compression]
enabled = true
level = 6
max_decompressed = 1048576
```

The client sends `COMPRESS zlib`; the server acknowledges, then frames are
`uncompressed length (u32 LE) | compressed length (u32 LE) | zlib stream`.
Every frame is a complete zlib stream, so a reader validates sizes from the
header before allocating. See `docs/COMPRESSION.md` for the algorithm
comparison that chose zlib over zstd, brotli and LZ4.

## SASL

```toml
[sasl]
enabled = true
require = false          # true: no 001 until AUTHENTICATE succeeds

[[accounts]]
name = "alice"
password_hash_env = "IRCD_ACCOUNT_ALICE_HASH"

[[accounts]]
name = "bob"
# SHA-256 of the DER certificate: openssl x509 -in client.pem -outform der | sha256sum
cert_fingerprint = "..."
```

`PLAIN` verifies against a SHA-256 password hash held in an environment
variable; `EXTERNAL` verifies the TLS client certificate by fingerprint, which
is why a certificate authority is not needed. `EXTERNAL` is only advertised on
servers with `tls.request_client_certs = true`, and each mechanism is only
advertised when an account can actually use it, so clients never see a login
prompt the server cannot satisfy.

Accounts are read through the `ircd::auth::AccountBackend` trait. The built-in
`ConfigAccounts` reads the configuration; embeddings can install another source
with `Server::set_account_backend`, and every mechanism, capability listing and
registration gate follows that backend.

An account also controls channel access. `MODE #chan +R` restricts joining and
speaking to authenticated users, and a ban entry written as `$a:<name>` matches
the account instead of `nick!user@host`, so it survives nick and host changes.
`+e` exceptions are matched the same way, which makes `MODE #chan +e $a:trusted`
an escape hatch from a wide mask ban. The account travels with the user over
server links and netbursts, and joins arriving over a link are re-checked, so
both restrictions apply to remote users too, alongside `+i`, `+k` and `+l`,
whose join credentials travel with the relayed join: a refused join is returned
to the user's home server as a `KICK`. `LOGOUT` clears the account (`901`) and sends
`ACCOUNT *` to every link, so the restriction applies on every server at once.

## Scripting

```toml
[scripting]
enabled = true
scripts = ["scripts/policy.rhai"]
```

```rhai
fn on_command(ctx) {
    if ctx.command == "PRIVMSG" && ctx.text.contains_text("spam") {
        return #{ allow: false, notice: "Not here." };
    }
}
```

See `docs/SCRIPTING.md` for the event list, return contract and shared state.

## Architecture

```
src/
  main.rs        CLI, config load, daemonise, runtime
  auth.rs        account backends for SASL
  config.rs      TOML schema, defaults, validation
  logging.rs     console / rolling file / syslog (or Event Log)
  daemon.rs      fork/setsid, PID file
  net/           listeners, TLS, compression, per-connection driver
  protocol/      parser, serialiser, numerics
  server/        shared state, dispatch, channels, RFC 2813 links
  commands/      registration, channel, messaging, admin handlers
  hooks.rs       Rhai engine
  script/        Rules framework and compiled guards
```

State lives in concurrent maps (`DashMap`, `parking_lot::RwLock`). A message
never needs a global write lock: fan-out resolves recipients and serialises at
most twice (plain and `server-time`-tagged), then clones a `Bytes` handle per
recipient. Handlers are function pointers returning boxed futures, so the
command table is a single static map.

## Testing and benchmarks

```bash
cargo test                      # 107 unit + 22 socket + 21 link + 8 dialer + 6 split + 2 TLS + 1 scripting
cargo bench --bench protocol    # parse / serialise / casemap / masks
cargo bench --bench compression # zlib vs zstd vs brotli vs LZ4
```

Benchmarks run single-threaded on purpose. Results are recorded in
`docs/BENCHMARKS.md` and `docs/COMPRESSION.md`.

## Audit reports

Speed and security reports are generated from the source tree, not written by
hand:

```bash
cargo run --release --bin audit -- report      # writes reports/
cargo run --release --bin audit -- markers     # list every MARK annotation
cargo run --release --bin audit -- speed       # measurement table
cargo run --release --bin audit -- security    # checks plus parser soak
```

Code carries `// MARK: category: severity: ID: text` annotations on the paths
worth reviewing, and the generator collects them into a register with source
links alongside measured numbers: hot-path timings, a seeded soak of the
parser, boundary checks on the length and tag ceilings, and wildcard cost
scaling. `report` exits non-zero on a malformed or duplicate marker or a failed
check, so it works as a gate. See `docs/AUDIT.md` for the grammar and what each
report covers.

## Limitations

Documented in `docs/COMPLIANCE.md`: links are multi-hop on a spanning tree with
timestamp collision resolution, a netburst on every (re)connection and outbound
dialling that reconnects with backoff, but the topology must be a tree (no
redundant links or split-mode healing). IRCv3 support covers eleven
capabilities (no batches, history or `monitor`), and SASL
supports `PLAIN` and `EXTERNAL` only. `docs/FEATURES.md` compares this feature
set with InspIRCd, UnrealIRCd, Solanum, Ergo and ngIRCd, including which gaps
actually matter.

## License

CC0 1.0 Universal, matching the repository's existing LICENSE.
