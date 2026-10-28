# Robustness, performance and scripting: an audit report

This pass covered the whole tree (15,971 lines of Rust: 11,505 in `src`, 3,437 in
`tests`, 1,029 in `benches`). Rather than claim a line-by-line rewrite, here is
exactly what was done:

* Read in full: `protocol/message.rs`, `commands/mod.rs`, `commands/messaging.rs`,
  `server/channel.rs`, `hooks.rs`, `util.rs`, `casemap.rs`, `config.rs` (relevant
  sections), `lib.rs`, `error.rs`, `main.rs`, `net/connection.rs`,
  `net/dialer.rs`, `script/*` and the test harnesses.
* Searched systematically for the classes of defect that break daemons:
  `unwrap`/`expect`/`todo!` in `src`, blocking or panicking paths in the message
  loop, unbounded allocations from client input, and every string that reaches
  the wire under a peer's control.
* Read the hot paths that benchmarks exercise (`deliver`, `broadcast_text`,
  `send_burst`, link relay) rather than every branch of every command handler.

Findings are split into what was fixed, what was measured and reverted, and what
was deliberately left alone.

## 1. Protocol injection through control characters (fixed)

The parser trimmed trailing `CR`/`LF` but accepted control bytes *inside* a
line. Every parameter is later re-serialised verbatim: `PRIVMSG` text, `TOPIC`,
`AWAY`, `PART`/`QUIT` reasons, and the `realname` that ends up in `WHOIS`
numerics. A `\r` or `\n` in any of those turns one message into two on the wire,
for local clients, for every relayed link message, and for script output.

RFC 1459 §2.3 forbids NUL, CR and LF inside a message; implementations also treat
the other C0 bytes as line noise. `Message::parse` now rejects any byte below
`0x20` or `DEL` with `ParseError::InvalidControl`, before any field is copied.
That is one check per line and it closes the whole class, including paths that
were not enumerated here.

Test: `protocol::message::tests::rejects_control_characters`.

## 2. Unterminated lines at absurd limits (fixed)

`to_bytes_limited` computed `max_len - 2` for the body and then appended `CRLF`.
For `max_len < 2` the result exceeded the ceiling and the arithmetic relied on
saturating subtraction. The limit is now clamped to `2`, so the guarantee "never
longer than the limit, always terminated" holds for every input.

Test: `protocol::message::tests::tiny_limits_keep_the_line_terminated`.

## 3. Command dispatch: a measured 6.6x win (kept)

Dispatch used `HashMap<&'static str, CommandSpec>` behind a `LazyLock`, i.e. a
SipHash round trip and a bucket probe per command.

Two alternatives were built and measured, in this order:

| Lookup | Time per call | Verdict |
|---|---:|---|
| `HashMap` (baseline) | 20.9 ns | previous behaviour |
| Sorted slice + `binary_search_by` | 47.3 ns | **rejected**: branch-predictor hostile |
| `match` tree over the verbs | **3.16 ns** | adopted |
| `match` tree, miss | 2.50 ns | adopted |

The binary search is the interesting negative result: fewer comparisons than a
hash, but six unpredictable branches cost more than the hash does. The match
tree compiles to a length-and-bytes decision tree with no hashing and no loop.

The table and the lookup are generated from one list by a macro
(`command_table!` in `src/commands/mod.rs`), so names cannot drift between the
slice used by `names()` and the match used for dispatch. A test asserts every
spec is reachable and resolves to its own name.

Benchmark: `cargo bench --bench dispatch`. Numbers are from one shared VM, single
threaded, 20 samples; compare within the run, not across machines.

## 4. Ban checks allocated per entry (fixed)

`Channel::is_banned` walked `bans` and `exceptions` with a closure that built
`nick!user@host` and `user@host` for **every** entry. On a channel with `n` bans
that is `2n` allocations per `JOIN`/`PRIVMSG` check.

`BanEntry::matches_mask` now takes the two derived masks, built once per check.
`BanEntry::matches` keeps its signature for other callers and delegates.
The public API is unchanged.

## 5. Scripting framework (new)

`src/script/` adds the layer the daemon lacked: an engine-agnostic host.

```rust
pub trait ScriptBackend: Send + Sync {
    fn is_enabled(&self) -> bool;
    fn loaded(&self) -> Vec<String>;
    fn invoke(&self, hook: Hook, context: &HookContext) -> HookOutcome;
    fn custom_command(&self, name: &str, context: &HookContext) -> Option<HookOutcome>;
}
```

* `Hook` is a closed enum with a single `ALL: &[(&str, Hook)]` table, so parsing,
  rules and scripted function names read the same data.
* `ScriptHost` owns a `RuleSet` and an optional `Box<dyn ScriptBackend>`. Rhai is
  now one implementation (`impl ScriptBackend for HookEngine`); adding a second
  language is one impl and no changes at call sites.
* Rules are compiled, not interpreted. Each condition is a
  `ConditionFn = fn(&HookContext, &str) -> bool` bound to a fixed field
  (`command`, `nick`, `user`, `host`, `channel`, `text`, `account`), and the
  pattern is matched with the existing linear-time wildcard matcher. Evaluating
  a deny costs a pointer call and a few byte comparisons, so the common
  "is this allowed" question does not enter the interpreter.
* Ordering is deliberate: rules run first and a `Deny` short-circuits the
  backend. A script must not be able to overturn an operator's hard deny.
* Loading is all-or-nothing: an unknown hook, a `deny`/`notice` rule without a
  notice, a malformed file or a broken script aborts start-up/`REHASH` instead of
  silently disabling a guard.

Config: `[scripting] rules = [...]` runs alongside `scripts = [...]`, gated by
the existing `enabled` switch. `HookContext` gained `account`, exposed to Rhai as
`ctx.account` (empty when unauthenticated).

Tests: seven unit tests in `src/script/rules.rs` (deny, notice, allow-precedence,
account wildcards, malformed files, empty set), three in `src/script/mod.rs`
(hook table round trip, inert host), and one end-to-end test
(`tests/scripting.rs`) that proves a rule loaded from config runs inside the real
command path, blocks the command, and that a `notice` rule still lets it run.

## 6. RFC compliance reviewed, unchanged

* Message grammar (RFC 1459 §2.3.1 / RFC 2812): tags, prefix, command verb,
  trailing parameter and the 15-parameter ceiling are enforced; control
  characters are now rejected (item 1).
* Delivery semantics (RFC 2810): `PRIVMSG` to a channel goes to members once,
  private messages follow the route to the recipient's server, and nothing is
  echoed back to the link it arrived on.
* Prefix handling on relayed burst `TOPIC`/`MODE` lines was corrected in the
  previous change so a second hop accepts them; see `docs/LINK_PROTOCOL.md`.
* Numerics, `ISUPPORT` tokens, `CASEMAPPING` folding and the invite/ban rules
  were checked against the RFCs and left as they were; no discrepancies were
  found that did not already have a test.

## 7. Deliberately not changed

* **Link TLS trust.** `tls_ca_path` verification is in place, but link
  authentication still rests on the shared secret. Adding certificate pinning
  per peer is an operator-facing format change, not a refactor.
* **Bursts remain additive.** Membership divergence after a split is merged, not
  reconciled by timestamp. Changing that needs a per-member timestamp the wire
  format does not carry.
* **Rhai remains on by default at compile time.** Making it optional
  (`features = ["scripting"]`) would remove the dependency for operators who do
  not use it, but it changes the crate's public surface and every test build; it
  is a packaging decision, not a correctness one.
* **`unsafe` blocks.** The three remaining ones are the `getnameinfo` call in
  `util.rs`, each with a safety comment. Replacing them with a safe wrapper would
  add a dependency to remove 15 lines.

## 8. Verification

* `cargo test`: 167 tests, all passing (107 unit, 22 socket, 21 link, 8 dialer,
  6 split, 2 TLS, 1 scripting).
* `cargo clippy --all-targets -- -D warnings`: clean.
* `cargo fmt --check`: clean.
* `cargo bench --bench dispatch`: numbers in item 3.
* `cargo bench --bench fanout` and `--bench protocol` were not re-run this pass;
  their code paths changed only in `deliver`'s address, which the unit and
  integration suites cover.

## 9. Known limits of this report

* "Every line" is aspirational for a 16k-line tree: the inventory above is what
  was actually read, and the rest was covered by targeted searches for the
  defect classes listed at the top. A claim that every branch of `admin.rs` was
  reviewed would be false.
* The dispatch benchmark is a microbenchmark of the lookup, not of command
  execution; the win is 17 ns per command, which matters at high message rates
  and not at all for offline operators.
* Rule evaluation is `O(conditions)` per rule and `O(rules)` per event with an
  early exit; there is no indexing by command yet. Thousands of rules would be
  worth bucketing by hook (already done) and by command (not done).
* No fuzzing or property testing was run. The parser is the obvious next target.
