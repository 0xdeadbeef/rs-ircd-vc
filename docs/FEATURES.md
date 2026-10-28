# Feature comparison

Compared with five established daemons. "Listed" means the vendor documents the
feature; it does not mean every build enables it. Sources are linked at the end.

## Matrix

| Feature | rs-ircd (this) | InspIRCd 4 | UnrealIRCd 6 | Solanum | Ergo | ngIRCd |
|---|---|---|---|---|---|---|
| Language | Rust | C++ | C | C | Go | C |
| RFC 1459/2810-2813 client protocol | Yes | Yes | Yes | Yes | Partial (IRCv3-first) | Yes (IRC+ extension) |
| Server linking | RFC 2813-shaped, multi-hop tree | Own spanning tree | Own protocol | TS6 | None | RFC 2813 + IRC+ |
| TS/TS6 collision resolution | Yes (TS, name tiebreak) | Own scheme | Own scheme | TS6 | n/a | RFC 2813 |
| TLS for clients | Yes | Yes (modules) | Yes | Yes | Yes | Yes |
| TLS for server links | Yes (TLS listener) | Yes | Yes | Yes | n/a | Yes |
| Link client certificates | No | Yes | Yes | Yes | n/a | Yes |
| Connection compression | zlib, per frame | Not documented | Not verified | ZIP/ziplinks | n/a | zlib for links |
| SASL | PLAIN, EXTERNAL, pluggable backend | Yes (via services) | Yes (via services) | Yes | Yes | Not documented |
| IRCv3 CAP 302 | Yes | Yes | Yes | Yes | Yes | Yes |
| `message-tags` | `server-time` only | Yes | Yes | Yes | Yes | No |
| `server-time` | Yes | Yes | Yes | Yes | Yes | No |
| `batch` | No | Yes | Yes | Yes | Yes | No |
| `chathistory` | No | No (join history module) | Yes | No | Yes | No |
| `labeled-response` | No | Yes | Yes | Yes | Yes | No |
| `account-tag` | Yes | Yes | Yes | Yes | Yes | No |
| `monitor` | No | Yes | Yes | Yes | Yes | No |
| `extended-join` | Yes | Yes | Yes | Yes | Yes | No |
| `multi-prefix` | Yes | Yes (4.10+) | Yes | Yes | Draft | Yes |
| `userhost-in-names` | Yes | Yes | Yes | Yes | Yes | Yes |
| `echo-message` | Yes | Yes | Yes | Yes | Yes | No |
| `away-notify` | Yes | Yes | Yes | Yes | Yes | No |
| Scripting language | Rhai (embedded) | C++ modules | C modules | C modules | None | None |
| Runtime log level change | Yes | Rehash | Rehash | Rehash | Rehash | Rehash |
| Windows support | Code paths present, unverified | Yes | Yes | No | Yes | Cygwin/WSL only |
| Built-in micro-benchmarks | Yes (`BENCH`) | No | No | No | No | No |
| Configuration format | TOML | Tag-based | Block-based | `ircd.conf` | YAML | Section-based |
| IPv4 + IPv6 multi-bind | Yes | Yes | Yes | Yes | Yes | Yes |

## Where this server is behind

* **Services integration.** SASL is implemented (`PLAIN` and `EXTERNAL` against
  a pluggable account backend), so clients can log in without a bouncer or an
  external services package. What is still missing is the rest of a services
  suite: NickServ/ChanServ-style pseudoclients. Account-based channel access
  (`+R`, `$a:` bans) exists, accounts travel with users over links and
  `account-tag` attaches them to messages. Ergo integrates those;
  InspIRCd, UnrealIRCd and Solanum defer them to an external services daemon.
  Cloaking and host hiding are also absent.
* **History.** `chathistory`/`batch` require a message store and per-client
  replay. Ergo and UnrealIRCd have it; Solanum and InspIRCd do not (InspIRCd
  offers join-time history instead). Without it, bouncerless clients cannot
  catch up.
* **Linking.** Multi-hop routing, TS collision resolution, a full netburst on
  every (re)connection and outbound dialling with exponential backoff are
  implemented, so a dropped link comes back without operator action. What TS6
  still adds is redundant-link handling with split-mode healing and UID/SID
  addressing: here the topology must be a tree.
* **Module ecosystem.** Dynamic C++/C modules expose far more surface area than
  the Rhai hooks. The hook layer is safer and sandboxed, but it cannot replace a
  packet-filtering module or a services pseudoclient.
* **Cloaking/host hiding.** Not implemented; `host` is the resolved address.

## Where this server is ahead or equal

* **Memory safety without FFI.** No `unsafe` in the daemon outside the Unix and
  Windows platform shims; no C modules to audit.
* **Bounded queues by construction.** Every connection has a bounded outbound
  channel; a stalled reader is disconnected rather than growing the heap. This
  is a common outage mode in C daemons.
* **Compression framing that resists bombs.** Length-prefixed, self-contained
  frames with a hard ceiling; the reader never inflates before checking sizes.
* **Benchmarks in the binary.** `BENCH` measures the live hot paths
  (`parse`, `fold`, `serialise`) so an operator can confirm a regression on the
  actual deployment, not just in CI.
* **Crash-free configuration reloads.** `REHASH` parses and validates the new
  file and compiles new scripts before swapping; a bad file leaves the old
  configuration running.

## Would the missing features perform better?

Honest answer: the performance-relevant ones would not, and the functional ones
are not about performance.

* **Redundant links and netburst** would improve *correctness* under partition,
  not throughput; route-directed delivery is already cheaper per message than
  flooding every link.
* **SASL** adds a round trip per login; that costs nothing per message. The
  built-in `ConfigAccounts` backend is a hash comparison, so login cost is one
  SHA-256 and a constant-time compare, not a database round trip.
* **History** adds per-message storage and lookup, which is the dominant cost in
  Ergo-style deployments.
* **C modules** can beat Rhai for hot filters because they run native code. The
  Rhai opcode budget (100k instructions per call) is a deliberate trade: a
  scripted `on_command` hook costs tens of microseconds, which is acceptable at
  IRC message rates but poor for per-packet work.

## Sources

* InspIRCd modules and spanning tree: <https://docs.inspircd.org/4/modules/>,
  <https://docs.inspircd.org/server/>
* UnrealIRCd message tags, SASL, channel history, server protocol:
  <https://www.unrealircd.org/docs/Message_tags>,
  <https://www.unrealircd.org/docs/SASL>,
  <https://www.unrealircd.org/docs/Channel_history>,
  <https://www.unrealircd.org/docs/Server_protocol>
* Solanum TS6 and ziplinks: <https://github.com/solanum-ircd/solanum/blob/main/doc/technical/ts6.md>,
  <https://github.com/solanum-ircd/solanum/blob/main/doc/technical/capab.txt>
* Ergo manual (no server linking, CHATHISTORY):
  <https://github.com/ergochat/ergo/blob/master/docs/MANUAL.md>
* ngIRCd protocol, capabilities and zlib build option:
  <https://github.com/ngircd/ngircd/blob/master/doc/Protocol.txt>,
  <https://github.com/ngircd/ngircd/blob/master/doc/Capabilities.txt>,
  <https://github.com/ngircd/ngircd/blob/master/INSTALL.md>
* IRCv3 server support table: <https://ircv3.net/software/servers.html>
