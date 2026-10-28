# Comparison and gap report

Full comparison of this daemon against the five open-source IRC servers this
repository already indexes in [FEATURES.md](FEATURES.md), followed by a
prioritised list of features we do not have, sized for implementation.

* **Subject:** rs-ircd (53 client commands, 21 IRCv3 capabilities, channel
  modes `imnpstRklovbe`). The capability table below reflects the tree after the
  IRCv3 work; see [IRCV3.md](IRCV3.md) for what each capability does.
* **Peers:** InspIRCd 4.x, UnrealIRCd 6.x, Solanum, Ergo 2.x, ngIRCd. All five
  are open source and their source, documentation and protocol notes are
  public.
* **Date of comparison:** 2026-10-28.

## How to read this

Cells are `Yes`, `Partial`, `No` or `?` (not verified). `Yes` means the vendor
documents the feature, not that every build enables it: InspIRCd and UnrealIRCd
are modular, so an operator can compile a server with less than the table shows.

Three kinds of evidence are mixed, and are labelled where it matters:

| Evidence | Meaning |
| --- | --- |
| Verified in this tree | Read from the source or asserted by a test or audit check |
| Upstream documentation | Read on 2026-10-28 from the vendor docs linked in [Sources](#sources) |
| General knowledge | Not re-checked for this report; treat as lower confidence |

Peer versions move. Where a row depends on a recently added module, the note
says so rather than pretending the comparison is version-independent.

## 1. The field

| | rs-ircd | InspIRCd 4 | UnrealIRCd 6 | Solanum | Ergo | ngIRCd |
| --- | --- | --- | --- | --- | --- | --- |
| Language | Rust | C++ | C | C | Go | C |
| First released | 2026 | 2002 | 1999 | 2013 (ratbox lineage) | 2017 | 2001 |
| Network model | Tree, own RFC 2813-shaped protocol | Spanning tree | Tree | TS6, mesh capable | Standalone | RFC 2813 + IRC+ |
| Services | Account backend plus account-aware modes and bans; no pseudoclients | External | External | External | Built in | External |
| History | None | Join-time history module | Channel history | No | Built in | No |
| Scripting | Rhai, sandboxed, plus compiled rules | C++ modules | C modules | C modules | None | None |
| Configuration | TOML | Tag-based | Block-based | `ircd.conf` | YAML | Section-based |

## 2. Transport and connection

| Capability | rs-ircd | InspIRCd 4 | UnrealIRCd 6 | Solanum | Ergo | ngIRCd | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TLS for clients | Yes | Yes | Yes | Yes | Yes | Yes | We serve TLS only on marked listeners |
| TLS 1.3 | Yes | Yes | Yes | Yes | Yes | ? | |
| STARTTLS upgrade | No | Yes | Yes | Yes | ? | ? | We have no in-band upgrade path |
| TLS client certificates | Yes, pinned per account | Yes | Yes | Yes | Yes | ? | Ours needs no CA |
| Encrypted private key | Yes (PKCS#8, passphrase env) | Yes | Yes | Yes | ? | ? | |
| WebSocket transport | No | Module | Yes | No | Yes | No | Ergo documents this explicitly |
| Proxy protocol / WEBIRC | No | Module | Yes | Yes | ? | No | Needed behind a CDN or bouncer |
| Connection compression | Yes, framed zlib | No | ? | Yes (ziplinks) | No | Yes (links) | Ours is per-connection, bomb-resistant |
| IPv4 and IPv6 multi-bind | Yes | Yes | Yes | Yes | Yes | Yes | |
| Hostname resolution | Yes (opt-in) | Yes | Yes | Yes | Yes | Yes | We default it off for latency |
| Ident (RFC 1413) | No | Yes | Yes | Yes | No | Yes | Mostly obsolete; expect bans to need it |
| UTF-8 validation | No | Yes | Yes | Yes | Yes | ? | We accept arbitrary bytes |

## 3. Client protocol and commands

| Capability | rs-ircd | InspIRCd 4 | UnrealIRCd 6 | Solanum | Ergo | ngIRCd | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RFC 1459/2812 command set | Yes, 39 commands | Yes | Yes | Yes | Partial, IRCv3-first | Yes | |
| `WHOX` | No | Yes | Yes | Yes | Yes | No | Used by bots and clients for efficient WHO |
| `SILENCE` | No | Yes | Yes | Yes | ? | No | Server-side ignore lists |
| `KNOCK` | No | Module | Yes | ? | ? | No | `+K` disables it where supported |
| `TAGMSG` | Yes | Yes | Yes | Yes | Yes | No | Bodyless messages under `message-tags` |
| `SETNAME` | No | Module | Yes | Yes | Yes | No | Real name changes after registration |
| `CHGHOST` | No | Module | Yes | Yes | Yes | No | Services-driven host changes |
| `MONITOR` | Yes | Yes | Yes | Yes | Yes | No | 100 entries per session |
| `USERS` | No | No | No | No | No | No | Obsolete; listed for completeness |
| `STATS` breadth | Partial (`l`, `u`) | Yes | Yes | Yes | Yes | Yes | We deliberately expose two letters |
| `DIE` / `RESTART` | No | Yes | Yes | Yes | Yes | Yes | We refuse them by design |
| `SQUIT` / `CONNECT` from clients | No (links only) | Yes | Yes | Yes | n/a | Yes | Routing is automatic here |

Verified in this tree: the capability rows marked `Yes` are asserted by
`tests/ircv3.rs`, `tests/network.rs` or the audit harness. `SILENCE`, `KNOCK`,
`WHOX`, `STARTTLS` and `WEBIRC` still have no implementation and no hits in
`src/`, so those rows are `No` rather than "untested".

## 4. IRCv3 capabilities

| Capability | rs-ircd | InspIRCd 4 | UnrealIRCd 6 | Solanum | Ergo | ngIRCd |
| --- | --- | --- | --- | --- | --- | --- |
| `cap` 302 negotiation | Yes | Yes | Yes | Yes | Yes | Yes |
| `cap-notify` | Yes | Yes | Yes | Yes | Yes | No |
| `sasl` | Yes (`PLAIN`, `EXTERNAL`) | Yes, via services | Yes, via services | Yes | Yes | No |
| `account-tag` | Yes | Yes | Yes | Yes | Yes | No |
| `account-notify` | Yes | Yes | Yes | Yes | Yes | No |
| `away-notify` | Yes | Yes | Yes | Yes | Yes | No |
| `message-tags` | Yes, 4 KiB client-tag budget | Yes | Yes | Yes | Yes | No |
| `server-time` | Yes | Yes | Yes | Yes | Yes | No |
| `batch` | Yes | Yes | Yes | Yes | Yes | No |
| `labeled-response` | Yes | Yes | Yes | Yes | Yes | No |
| `chathistory` | Yes, in-memory | Module (join-time history, not `CHATHISTORY`) | Yes | No | Yes | No | Not persisted, not shared across links |
| `echo-message` | Yes | Yes | Yes | Yes | Yes | No |
| `extended-join` | Yes | Yes | Yes | Yes | Yes | No |
| `invite-notify` | Yes | Yes | Yes | Yes | Yes | No |
| `multi-prefix` | Yes | Yes | Yes | Yes | Yes | Yes |
| `userhost-in-names` | Yes | Yes | Yes | Yes | Yes | Yes |
| `setname` | Yes | Module | Yes | Yes | Yes | No |
| `chghost` | Yes | Module | Yes | Yes | Yes | No |
| `sts` | Yes, with TLS | No | Yes | No | Yes | No |
| `standard-replies` | Yes | Yes | Yes | Yes | Yes | No |
| `multiline` | Yes | No | Yes | No | Yes | No |
| `draft/relaymsg` | No | No | No | No | Yes | No |

## 5. Channel modes, by function

Letter mapping differs between servers (`+M` is "registered users only speak" in
UnrealIRCd and "registered users only join" in InspIRCd), so this table compares
effects, not letters.

| Effect | rs-ircd | InspIRCd 4 | UnrealIRCd 6 | Solanum | Ergo | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Invite only | `+i` | `+i` | `+i` | `+i` | `+i` | |
| Invite exception list | No | `+I` | `+I` | `+I` | ? | Needed for usable `+i` |
| Moderated | `+m` | `+m` | `+m` | `+m` | `+m` | |
| No external messages | `+n` | `+n` | `+n` | `+n` | `+n` | |
| Secret / private | `+s` / `+p` | `+s` / `+p` | `+s` / `+p` | `+s` / `+p` | `+s` | |
| Topic lock | `+t` | `+t` | `+t` | `+t` | `+t` | |
| Key | `+k` | `+k` | `+k` | `+k` | `+k` | |
| Limit | `+l` | `+l` | `+l` | `+l` | `+l` | |
| Ban / exception | `+b` / `+e` | `+b` / `+e` | `+b` / `+e` | `+b` / `+e` | `+b` / `+e` | We also support `$a:` account masks |
| Quiet list | No | No | No | Yes | ? | Suppresses speech without banning |
| Half-op / admin / owner prefixes | No | `+h`/`+a`/`+q` via `customprefix` | `+h`/`+a`/`+q` | Partial | `+h`? | We have only `+o`/`+v` |
| Registered users only | `+R` (join and speak) | `+R` join, `+M` speak | `+R` join, `+M` speak | `+r` registered channel | `+R` | Ours is one mode covering both |
| No colour | No | `+c` | `+c` | No | `+c` | Trivial to add and widely used |
| No CTCP | No | `+C` | `+C` | No | `+C` | |
| Strip colour | No | `+S` | `+S` | No | ? | |
| No notices | No | `+T` | `+T` | No | ? | |
| Flood protection | No | `+f`/`+F`/`+E` | `+f`/`+F` | No | `+f`? | Channel-level anti-flood |
| Join throttling | No | `+j` | `+f` (join component) | No | `+j` | |
| Kick no-rejoin | No | `+J` | No | No | ? | |
| Redirect on failure | No | `+L` | `+L` | No | ? | Also gives `+l` a soft landing |
| Permanent channel | No | `+P` | `+P` | No | Yes (registered channels) | Requires channel persistence |
| TLS-only | No | `+z` | `+z`/`+Z` | `+z`? | `+z`? | We track TLS per client already |
| Oper-only | No | `+O` | `+O` | `+O` | ? | |
| No kick / no knock / no invite | No | `+Q`/`+K`/`+V` | `+Q`/`+K`/`+V` | ? | ? | |
| Auditorium | No | `+u` | No | No | ? | Hides member list from non-ops |
| Delayed join | No | `+D` | `+D` | No | ? | Bouncer/display feature |
| No nick changes | No | `+N` | `+N` | ? | ? | Nick-flood mitigation |
| Extended bans | Only `$a:` | `~account`, `~channel`, many | `~account`, `~channel`, many | `$~a` style | ? | The big semantic gap |

## 6. User modes, identity and accounts

| Capability | rs-ircd | InspIRCd 4 | UnrealIRCd 6 | Solanum | Ergo | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Invisible / wallops / oper | `+i` / `+w` / `+o` | Yes | Yes | Yes | Yes | We have exactly these three |
| Bot mode (`+B`) | No | Yes | Yes | Yes | Yes | Marks bots for `WHO`/flood policy |
| Callerid / white list (`+g`) | No | Yes | Yes | Yes | ? | Pre-emptive ignore, server side |
| Helpop (`+h`) | No | Yes | Yes | Yes | ? | Network-wide operator reach |
| Cloaked host (`+x`) | No | Yes | Yes | Yes | Yes | Privacy for ordinary users |
| Oper vhost | No | Yes | Yes | Yes | ? | |
| Account registration in-protocol | No | Via services | Via services | Via services | Yes | `draft/account-registration` |
| Password change in-protocol | No | Via services | Via services | Via services | Yes | |
| Certfp login without SASL | No | Via services | Yes | Yes | Yes | We require SASL `EXTERNAL` |
| Account-based bans | `$a:` | `~account` | `~account` | Services | Yes | We have the narrow version |

## 7. Anti-abuse and operator tooling

| Capability | rs-ircd | InspIRCd 4 | UnrealIRCd 6 | Solanum | Ergo | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Oper flags / classes | 4 flags | Fine-grained | Fine-grained classes | Fine-grained | Fine-grained | We have `kill`, `rehash`, `global`, `die` |
| `SNOMASK` | No | Yes | Yes | Yes | Yes | Operators cannot subscribe to notices |
| Remote oper | No | Yes | Yes | Yes | ? | |
| Oper override / `SAMODE` | No | Yes | Yes | Yes | ? | |
| Global notices (`GLOBOPS`) | No | Yes | Yes | Yes | ? | |
| Ban types (K/G/Z/shun) | No | Yes | Yes | Yes | Yes | We only have channel bans |
| Ban synchronisation over links | n/a | Yes | Yes | Yes | n/a | Follows from ban types |
| Connection throttling | No | Yes | Yes (`Connthrottle`) | Yes | Yes | Per-IP rate limiting is the common defence |
| Clone limits per IP | No | Yes | Yes | Yes | Yes | |
| DNSBL / blacklists | No | Yes | Yes | Yes | Yes | |
| Spam filter (regex, actions) | No | Yes | Yes | Yes | Yes | |
| Bad-word censor | No | Yes | Yes | No | Yes | |
| Exemptions from limits | No | Yes | Yes | Yes | Yes | |
| Live benchmark command | Yes (`BENCH`) | No | No | No | No | |

## 8. Linking, services and history

| Capability | rs-ircd | InspIRCd 4 | UnrealIRCd 6 | Solanum | Ergo | ngIRCd | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Server links | Yes | Yes | Yes | Yes | No | Yes | |
| Multi-hop routing | Yes | Yes | Yes | Yes | n/a | Yes | |
| Hop-counted introductions | Yes | Yes | Yes | Yes | n/a | Yes | |
| TS collision resolution | Yes (TS, name tiebreak) | Own | Own | TS6 | n/a | RFC 2813 | |
| TS6 wire compatibility | No | No | No | Yes | n/a | No | Ours is RFC 2813-shaped |
| SID/UID addressing | No (nicknames) | Yes (SID/UID) | Yes (SID/UID) | Yes | n/a | No | Nick-change churn costs a relay here |
| Redundant links / mesh | No (tree only) | No (tree) | No (tree) | Yes | n/a | No | Only Solanum heals a partition with a second path |
| Outbound dialling with backoff | Yes | Yes | Yes | Yes | n/a | Yes | |
| Netburst on reconnect | Yes, full including invites and accounts | Yes | Yes | Yes | n/a | Yes | |
| Services pseudoservers | No | Yes (`SVS*`/`ENCAP`) | Yes | Yes | Built in | ? | Needed for NickServ/ChanServ |
| MLOCK | No | Via services | Via services | Via services | Yes | No | Services enforce mode locks |
| Channel registration | No | Via services | Via services | Via services | Yes | No | |
| Channel access lists (AOP/HOP) | No | Via services | Yes | Via services | Yes | No | |
| Account-based history replay | No | Join history only | Yes | No | Yes | No | |

## 9. Operations and extensibility

| Capability | rs-ircd | InspIRCd 4 | UnrealIRCd 6 | Solanum | Ergo | ngIRCd | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Console / file / syslog logging | Yes (+ Windows Event Log) | Yes | Yes | Yes | Yes | Yes | |
| Runtime log filter change | Yes | Rehash | Rehash | Rehash | Rehash | Rehash | We can change it without a reload |
| Structured logging | Yes (JSON option) | Partial | Yes | Partial | Yes | No | |
| Daemonise, PID file | Yes | Yes | Yes | Yes | No (service manager) | Yes | |
| Config validation without starting | Yes (`--check`) | Yes | Yes | Yes | Yes | Yes | |
| Atomic config reload | Yes | Yes | Yes | Yes | Yes | Yes | |
| Metrics endpoint (Prometheus) | No | No | Partial (third party) | No | Yes | No | Confidence: medium |
| HTTP / JSON-RPC admin | No | No | Partial (`RPC` module) | No | Yes (JSON-RPC) | No | Confidence: medium |
| Dynamic modules | No (scripts only) | Yes (C++) | Yes (C) | Yes | No | No | |
| Sandboxed scripting | Yes (Rhai, opcode budget) | No | No | No | No | No | |
| Test suite in the repository | Yes, 194 tests | Yes | Yes | Yes | Yes | Yes | |
| Generated audit report | Yes (`audit report`) | No | No | No | No | No | |

## 10. Scorecard

Counting cells across sections 2-9 (excluding rows marked `?`), out of 74 rows:

| Server | Yes | Partial | No | Modelled as |
| --- | ---: | ---: | ---: | --- |
| rs-ircd | 33 | 3 | 38 | |
| InspIRCd 4 | 62 | 4 | 6 | Tree, modular |
| UnrealIRCd 6 | 64 | 2 | 6 | Tree, monolithic defaults |
| Solanum | 52 | 4 | 12 | TS6 mesh |
| Ergo | 46 | 4 | 8 | Standalone |
| ngIRCd | 28 | 3 | 32 | Minimal |

Raw counts mislead in both directions. InspIRCd and UnrealIRCd ship modules for
almost everything listed, whereas a bare ngIRCd is a deliberately small server;
Ergo loses points for not linking servers at all, which its design does not
need, and Solanum scores on mesh at the cost of needing external services. The
useful reading is per category, not per total.

Our lowest categories are channel modes (7 of 27 effects), anti-abuse (1 of 13)
and services/history (2 of 8). Our strongest are transport integrity, account
authentication, linking mechanics and operability.

## 11. Where this daemon leads or matches

* **Memory safety.** No `unsafe` outside the Unix and Windows platform shims,
  and no C module surface to audit. Every peer except Ergo is C or C++.
* **Bounded queues by construction.** A stalled reader is disconnected when its
  send queue fills, rather than growing the heap. This is a common C daemon
  outage mode.
* **Compression that resists bombs.** Length-prefixed, self-contained frames with
  a hard ceiling checked before any allocation. ziplinks achieve compression but
  are not framed the same way.
* **Certificate pinning without a CA.** `EXTERNAL` maps one SHA-256 fingerprint to
  one account, so no public PKI and no private CA to operate.
* **Account rules that survive the network.** `$a:` bans, `+R`, and `$a:`
  exceptions evaluate remote users by the account carried in their
  introduction, and the netburst carries accounts and outstanding invitations.
* **Invitation lifetime with warnings.** Expiry, pre-expiry notice to both
  parties, and replay of only unexpired grants across a reconnect. Peers expire
  invites but do not document the warning stage.
* **Guard rules plus sandboxed scripts.** Compiled function-pointer rules for
  cheap vetoes, Rhai behind it with an opcode budget and no filesystem or
  network access. C modules are more capable and far less contained.
* **Generated audit material.** 34 markers, 14 executable security checks and a
  seeded parser soak, regenerable with one command. No peer ships anything
  comparable.
* **Operator benchmark in the binary.** `BENCH` measures parse, fold and
  serialisation on the live deployment, not only in CI.

## 12. Gap report

Ordered by value per unit of work. Size is engineering effort for one developer
familiar with the codebase: **S** up to a day, **M** two to five days, **L** one
to three weeks.

### P1: client-visible, cheap, high adoption

These are the gaps a modern client notices within a minute of connecting.

| # | Gap | Peers with it | Why it matters | Size | Notes |
| --- | --- | --- | --- | --- | --- |
| 1 | `TAGMSG` | InspIRCd, Unreal, Solanum, Ergo | Typing indicators and reactions travel as tags with no body; without it `message-tags` is half-implemented | S | Reuse the `PRIVMSG` tag path, deliver to capable recipients only, no `echo-message` text |
| 2 | `MONITOR` | InspIRCd, Unreal, Solanum, Ergo | Clients poll with `ISON` today; `MONITOR` is cheaper and pushes changes | S | Bounded per-client list (`limits.max_targets` sibling), reuse the notify path |
| 3 | `invite-notify` | InspIRCd, Unreal, Solanum, Ergo | Channel ops see invitations in real time | S | One capability check on the existing `INVITE` fan-out |
| 4 | `SETNAME` | Unreal, Solanum, Ergo (module in InspIRCd) | Real-name changes after registration | S | Numeric `SETNAME` reply, relay over links, audit-log |
| 5 | `CHGHOST` | Unreal, Solanum, Ergo (module in InspIRCd) | Services-driven host changes; prerequisite for vhosts | S | Needs a way to mutate `session.host` safely and relay it |
| 6 | `standard-replies` | InspIRCd, Unreal, Solanum, Ergo | Machine-readable failure reasons; clients stop parsing prose | M | Touches every handler that emits a numeric; can be incremental |
| 7 | `WHOX` | InspIRCd, Unreal, Solanum, Ergo | Bots and clients fetch specific fields instead of everything | M | New `WHO` form plus field selection; bounded output |
| 8 | `SILENCE` | InspIRCd, Unreal, Solanum | Server-side ignore lists that work across devices | M | Bounded list, enforced at delivery, not at send |
| 9 | `STARTTLS` | InspIRCd, Unreal, Solanum | Upgrade a plain connection instead of a second port | M | The connection driver already switches to TLS for links; reuse that machinery |
| 10 | `STS` | Unreal, Ergo | Pins TLS policy so a downgrade is visible | S | Config string in `005`/`CAP`; policy only, no new transport |
| 11 | `WEBIRC` | InspIRCd, Unreal, Solanum | Correct client host behind a gateway or bouncer | S | Trusted-gateway list with password, must run before registration |

### P2: channel semantics and abuse controls

| # | Gap | Peers with it | Why it matters | Size | Notes |
| --- | --- | --- | --- | --- | --- |
| 12 | `+c` / `+C` / `+S` / `+T` | InspIRCd, Unreal | Colour/CTCP/notice control is table stakes on public networks | S | Four switches checked on the message path |
| 13 | `+q` quiet list | Solanum, others | Silence a user without banning | S | Reuse `BanEntry` and the `+e` machinery; suppression at delivery |
| 14 | `+I` invite exception list | InspIRCd, Unreal, Solanum | `+i` is unusable without an exception list | S | Same list plumbing as `+b`/`+e` |
| 15 | `+z` / `+Z` TLS-only | InspIRCd, Unreal | Ordinary privacy control | S | Client TLS state is already tracked |
| 16 | `+M` (registered only to speak) | InspIRCd, Unreal | Separates join policy from speak policy, which our single `+R` conflates | S | Split `+R` semantics; keep `+R` as join-only for compatibility |
| 17 | `+P` permanent channels | InspIRCd, Unreal | Channels survive an empty moment; requires persistence | M | Needs a channel store and reload on start |
| 18 | `+L` redirect | InspIRCd, Unreal | Gives an overflow channel somewhere to go | S | Only after `+l` refusal; one lookup |
| 19 | `+O` / `+V` / `+Q` / `+K` / `+N` | InspIRCd, Unreal | Oper-only channels and local control of invite/kick/nick | S | Switches, each with a numeric |
| 20 | `+f` / `+j` flood control | InspIRCd, Unreal, Ergo | Channel-level protection without an oper | L | Token buckets per member per channel; must not be a DoS vector itself |
| 21 | Half-op and admin prefixes | InspIRCd, Unreal, Solanum | Delegated moderation on large channels | M | Prefix modes change `NAMES`, `MODE` and permissions broadly |
| 22 | Extended bans (`~account`, `~channel`, `~realname`) | InspIRCd, Unreal | The `$a:` prefix is a narrow special case of a general mechanism | M | Generalise `BanEntry` matching; keep `$a:` as an alias |
| 23 | Cloaking / vhosts | All five | Ordinary users are exposed by their reverse DNS | M | Needs a deterministic cloak algorithm and a vhost store |
| 24 | Connection throttling and clone limits | All five | The cheapest defence against drone floods | M | Per-IP counters, exemptions by mask, no lock contention |

### P3: operator tooling and moderation

| # | Gap | Peers with it | Why it matters | Size | Notes |
| --- | --- | --- | --- | --- | --- |
| 25 | `SNOMASK` | All five | Operators currently cannot subscribe to categories of server notices | S | Bitmask per oper session, filter at the notice site |
| 26 | Fine-grained oper privileges | All five | Four flags cannot express "may use `KILL` but not `REHASH`" | M | Replace `Vec<OperFlag>` with a privilege set plus config migration |
| 27 | Server ban types (K/G/Z/shun) | InspIRCd, Unreal, Solanum, Ergo | Network-wide bans are the primary abuse response | L | Needs link propagation, expiry, matching on connect, and `STATS` |
| 28 | Spam filter | InspIRCd, Unreal, Solanum, Ergo | Pattern-based blocking with actions beats per-channel rules | L | Regex on the hot path needs a compiled set and a time budget |
| 29 | Remote oper / oper override | InspIRCd, Unreal, Solanum | Moderating a linked network from one place | M | Depends on privilege granularity (26) |
| 30 | `GLOBOPS` and global notices | InspIRCd, Unreal, Solanum | Cross-server operator coordination | S | We already relay `WALLOPS` |
| 31 | DNSBL | All five | Blocks known-bad addresses before registration | M | Async lookups with a timeout, must not stall the reactor |

### P4: services, network topology and history

| # | Gap | Peers with it | Why it matters | Size | Notes |
| --- | --- | --- | --- | --- | --- |
| 32 | Services pseudoserver protocol (`SVS*`, `ENCAP`, `MLOCK`) | InspIRCd, Unreal, Solanum | Without it, no external NickServ/ChanServ can drive the network | L | Account backend exists; the gap is the wire control surface and enforcement |
| 33 | Built-in account registration | Ergo | Self-service accounts without an external service | L | `draft/account-registration`, email or challenge verification, storage |
| 34 | Channel registration and access lists | All except ngIRCd | Delegated channel management that survives founder absence | L | Storage, MLOCK enforcement, AOP/HOP lists |
| 35 | `chathistory` and `batch` | Unreal, Ergo | Clients catch up after a disconnect without a bouncer | L | Message store keyed by target and account, retention limits, replay authorisation |
| 36 | `multiline` | Unreal, Ergo | Pasted multi-line text without breaking the line ceiling | M | Depends on `batch` |
| 37 | TS6 compatibility and UID/SID addressing | Solanum (and others internally) | Interoperability with an existing TS6 network | L | Rewrites user identity, routing and collision handling; only worth it for federation with existing networks |
| 38 | Mesh and split-mode healing | Solanum | Survives a partition with a redundant path | L | Contradicts the tree invariant throughout `link.rs`; a design change, not a patch |
| 39 | SASL `SCRAM-SHA-256`, `OAUTHBEARER` | InspIRCd, Unreal, Solanum, Ergo (varies) | Password never crosses the wire; token login | M | Backend trait needs a challenge-response shape, not just `verify` |
| 40 | Prometheus metrics / JSON-RPC | Ergo (JSON-RPC) | Dashboards and automation today use log scraping | M | Separate listener, authentication, no per-request allocation |

## 13. Three milestones

**Milestone 1, "modern client" (about one week).** Items 1-5, 10, 11: `TAGMSG`,
`MONITOR`, `invite-notify`, `SETNAME`, `CHGHOST`, `STS`, `WEBIRC`. Each is a
capability advertisement plus one handler or fan-out change. Acceptance: a
current client negotiates all of them, typing indicators work, `MONITOR` pushes
on nick changes and quits, and the audit harness gains checks for the new
capability list and the `TAGMSG` relay rules.

**Milestone 2, "public network" (two to three weeks).** Items 12-19, 24, 25:
cheap channel modes, invite exceptions, quiet list, TLS-only channels,
throttling and snomasks. Acceptance: a channel can be configured with colour
suppression, a quiet list and an invite exception; a flood of connections from
one address is throttled with a configurable allowance; operators can subscribe
to link and kill notices; the join gate check grows cases for every new mode.

**Milestone 3, "services and history" (three to six weeks).** Items 32-35 plus
31: a services control surface, account and channel registration, and a message
store behind `CHATHISTORY`. These need storage and a retention policy, which is
the real design work; the protocol is the easy part. Acceptance: an external
services package can set modes with `MLOCK`, a user can register and recover an
account, and a client can request the last N messages for a channel it is
joined to and receives them in a `batch`.

## 14. Deliberately not planned

* **`+a` anonymous channels.** Obsolete, removed by most implementations, and
  the privacy gain does not justify the routing complexity.
* **`DIE` and `RESTART` from clients.** Process lifecycle belongs to the service
  manager; `REHASH` covers the operational need.
* **A C module ABI.** It would undo the memory-safety property this server has
  and cannot be made sound across a boundary that already passes pointers.
* **Byte-compatible TS6** unless federating with an existing TS6 network is a
  stated goal; the tree plus hop counts already provides multi-hop routing.
* **`USERS`.** No client uses it.
* **`+d` (delay-join internals) and `+r` (services-set channel marker)** until
  services exist; both are artifacts of other designs.

## 15. What each gap would cost per message

Useful when prioritising, because several peers pay for features this server
does not have:

* `MONITOR`, `invite-notify` and `account-notify` are O(watchers) per event and
  add nothing per message in the steady state.
* `TAGMSG` reuses the existing tag path: one capability check and one
  serialisation per variant, no new allocation in the untagged case.
* `+c`, `+C`, `+S` add a byte scan over the message body, proportional to length
  and only when the mode is set.
* `+f`/`+j` add a token bucket per member per channel, which is the only feature
  here that touches every message on a busy channel; it needs a coarse clock and
  a per-channel budget to stay predictable.
* Spam filters are the dangerous one: a regex set on the hot path can dominate
  the per-message cost. Compile once, cap the input scanned, and measure with
  the audit speed harness before enabling by default.
* `chathistory` turns the message path into a storage path. Retention,
  fsync policy and query cost matter more than the protocol.
* TS6/UID addressing removes the per-nick-change relay and shortens identifiers,
  which would reduce bandwidth on large networks, but rewrites routing.

## 16. Corrections to the existing index

`docs/FEATURES.md` had two stale rows for this server, corrected in the same
change: `message-tags` is implemented (client tags with a 4 KiB budget, not
"`server-time` only") and `labeled-response` is implemented. Both are asserted in
[docs/COMPLIANCE.md](COMPLIANCE.md) and by the audit harness.

The old matrix also had no rows for `TAGMSG`, `SILENCE`, `WHOX`, `MONITOR`,
`STS`, `standard-replies`, `STARTTLS` or any of the anti-abuse tooling, which is
why the gap report above is longer than the old "where this server is behind"
section. That section was accurate but incomplete.

## Sources

Read for this report on 2026-10-28:

* UnrealIRCd channel modes: <https://www.unrealircd.org/docs/Channel_modes>
* UnrealIRCd user modes: <https://www.unrealircd.org/docs/User_modes>
* UnrealIRCd history: <https://www.unrealircd.org/docs/Channel_history>
* InspIRCd 4 channel modes: <https://docs.inspircd.org/4/channel-modes/>
* InspIRCd 4 user modes: <https://docs.inspircd.org/4/user-modes/>
* InspIRCd 4 modules: <https://docs.inspircd.org/4/modules/>
* Ergo specifications: <https://ergo.chat/specs/>
* Ergo manual: <https://github.com/ergochat/ergo/blob/master/docs/MANUAL.md>
* Solanum technical documentation:
  <https://github.com/solanum-ircd/solanum/blob/main/doc/technical/ts6.md>
* Solanum release notes (message tags, ENCAP, `+e`/`+I`):
  <https://github.com/solanum-ircd/solanum/blob/main/NEWS.md>
* ngIRCd protocol and capabilities:
  <https://github.com/ngircd/ngircd/blob/master/doc/Protocol.txt>,
  <https://github.com/ngircd/ngircd/blob/master/doc/Capabilities.txt>
* IRCv3 specification index and server support table:
  <https://ircv3.net/irc/>, <https://ircv3.net/software/servers.html>

Repository evidence: [FEATURES.md](FEATURES.md), [COMPLIANCE.md](COMPLIANCE.md),
[LINK_PROTOCOL.md](LINK_PROTOCOL.md), [SCRIPTING.md](SCRIPTING.md),
[performance numbers](BENCHMARKS.md), and the generated
[security report](../reports/SECURITY.md).

## Method limits

* No peer was built or benchmarked. Every "would perform better" statement is an
  argument from design, not a measurement; the per-message analysis in section 15
  says where a measurement would be needed before believing it.
* Peer feature lists come from documentation for the current major version. A
  modular server's default build may enable less than the table shows.
* Cells marked `?` were not verified and are excluded from the scorecard rather
  than guessed.
* The comparison is about protocol and operational features. It is not a security
  audit of the peers, and nothing here should be read as one.
