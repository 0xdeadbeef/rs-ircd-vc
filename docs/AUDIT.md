# Audit tooling

`cargo run --release --bin audit -- report` regenerates `reports/` from the
source tree: a marker register, measured hot paths and executable security
checks. The point is that a claim in a document has a command behind it, so the
report is regenerated rather than edited.

## Commands

| Command | What it does | Exit status |
| --- | --- | --- |
| `audit markers` | List and validate `MARK:` annotations | 0 |
| `audit markers --check` | Same, but non-zero when a marker is malformed or duplicated | gate |
| `audit speed` | Measure every case and print a table | 0 |
| `audit security` | Run the checks and the parser soak | non-zero on a failed check |
| `audit report` | Write `AUDIT.md`, `SECURITY.md`, `SPEED.md` and `audit.json` | non-zero on a marker problem or failed check |

Global flags: `--root <path>` (defaults to the manifest directory) and `--json`
(machine-readable output instead of a table). Report generation takes
`--iterations`, `--rounds`, `--soak`, `--seed` and `--out`.

Generate reports with `--release`. A debug build measures debug code, and the
report records which profile produced it so a mislabelled run is visible.

## Markers

A marker is a single line comment:

```rust
// MARK: security: critical: SEC-CONTROL-001: rejects C0/DEL before copying any field.
```

The grammar is `// MARK: category: severity: id: text`, with the leading `/`s
allowing `///` and `//!` so a marker can sit on a documented item.

* **category** is one of `security`, `safety`, `speed`, `protocol`, `policy`.
  It decides which report table the marker appears in.
* **severity** is one of `critical`, `high`, `medium`, `low`, `info`, ordered
  most to least urgent in every report.
* **id** is `PREFIX-NNN`: up to eight uppercase alphanumeric characters that
  start with a letter, a hyphen, then exactly three digits. Ids must be unique
  across the tree, because the point of an id is to cite it in a review or a
  commit message without ambiguity.
* **text** is one line and must not be empty. It says what the code does and
  why it matters, not what the next line says.

Prose after the third colon belongs to the text, so a marker can quote a rule
or a rationale. Markers are not parsed as code: one in a string literal or a
Markdown file is ignored because the scanner only reads `//` comments in `.rs`
files under `src`, `tests` and `benches`.

The scanner reports these as problems: an unknown category, an unknown
severity, an id of the wrong shape, a duplicate id, empty text, and a line
containing `MARK:` that does not start with `// MARK: ` (a typo that would
otherwise silently drop the annotation).

## Reports

### `reports/SECURITY.md`

* Headline counts, markers by severity, and the commit the run measured.
* **Executable checks**: one row per assertion with the evidence that
  produced the verdict.
* **Parser soak**: how many generated lines were accepted or rejected, why they
  were rejected, and any invariant violations with the failing input escaped so
  it can be pasted into a test.
* **Injection analysis**: the reasoning behind the control-character guard and
  the invariants the soak re-checks.
* **Wildcard cost** and **credential comparison timing**: the measurements that
  back the corresponding markers.
* **Marker register**: every `security`, `safety` and `policy` annotation with a
  link to its exact source line.
* **Static inventory**: textual counts of `unsafe`, `unwrap`, `expect`,
  `panic!`, `allow` and debug prints per tree.
* **Files without a marker**: modules over 150 lines with no annotation, which
  is where the next review should start.
* **Not covered**: what this harness deliberately does not measure.

### `reports/SPEED.md`

* Environment fingerprint: target, profile, toolchain, CPU count, commit.
* One row per case with median, minimum, maximum, coefficient of variation,
  implied rate and iteration count.
* An interpretation row per case, so the table cannot be read as more than it
  is.
* Marked hot paths with source links.
* Method and limits.

### `reports/audit.json`

Everything above as one JSON document: `environment`, `markers`, `problems`,
`inventory`, `security`, `speed`. Use it for dashboards or for diffing two
revisions.

## Harnesses

### Speed

`src/bin/audit/speed.rs` times one case at a time on one thread:

1. a warm-up pass of an eighth of the iteration count,
2. `rounds` rounds of `iterations` calls each, timed with `Instant`,
3. a checksum folded through `black_box` so the optimiser cannot delete work.

The report shows per-round distribution rather than a single number: a case
whose `cv` exceeds 10% is machine noise, and the summary counts how many rows
that affected. Cases cover parsing (plain, tagged, rejected), serialisation
(untagged, tagged), casemapping, wildcard matching, a 16-entry ban list hit on
the last entry, command dispatch, nickname validation and numeric formatting.

This does not replace `cargo bench`, which uses criterion and reports
confidence intervals. It exists so one command can produce a report with the
environment fingerprinted and a stable machine-readable shape.

### Security

`src/bin/audit/security.rs` asserts, against the real library:

| Check | Assertion |
| --- | --- |
| `C-CTRL` | Every C0 byte and `DEL` is rejected with `InvalidControl` in a trailing parameter, middle parameter, prefix, tag value and tag key |
| `C-LEN` | A line of exactly `max_len` parses, one byte more is `TooLong`, the tag budget is enforced, and `to_bytes_limited` never exceeds its ceiling, including at 0 |
| `C-PARAM` | 15 parameters parse, 16 are `TooManyParams`, the trailing form is preserved |
| `C-TAG` | Server tags (`time`, `account`, `label`) are never relayed, `+` tags are, vendor tags need the allowlist, and a flood is clipped to the budget |
| `C-SOAK` | Generated input never panics, is always decided, and every accepted message survives serialise/re-parse unchanged |
| `C-WILD` | Per-byte wildcard cost stays flat from 1 KiB to 100 KiB of adversarial input |
| `C-LINK-PASS` | A link password is matched exactly: unset and empty configuration refuse every link, and no prefix, suffix or altered byte matches |
| `C-LINK-ADMIT` | The `SERVER` policy refuses a connection without `PASS`, an empty name, an unlisted peer, a self-link, an unconfigured dialled link and a duplicate path, in that order |
| `C-PIN` | A pinned fingerprint authenticates only its account: exact match, case-insensitive, authzid binds the name, no partial match, no fallback for an unknown authzid |
| `C-PIN-CONFIG` | Pinned fingerprints must be 64 hex digits at start-up; short, long, non-hex, duplicate and credential-less accounts are rejected |

The soak generator is a seeded xorshift64 with no dependency, blending valid
message shapes (70%), fragment soup (30%), control bytes, multi-byte UTF-8 and
IRC syntax. A failure prints the seed and the escaped input, so
`audit security --soak 50000 --seed <n>` reproduces it.

## Using this as a gate

```bash
cargo run --release --bin audit -- markers --check
cargo run --release --bin audit -- report
```

Both exit non-zero on a marker problem, and `report` also fails when any
security check fails. Nothing in the tool opens a socket, reads a secret or
starts the daemon, so it runs offline in CI.

## Limits

* The marker register records what was reviewed; its absence is not evidence of
  safety. `reports/SECURITY.md` lists unannotated files explicitly.
* Static counts are substring matches, not an AST, so a construct mentioned in
  a comment is counted.
* Timing on a shared virtual machine is indicative. Treat `cv` above 10% as a
  failed measurement, and never compare two different hosts.
* The soak harness is deterministic and grammar-limited. It exercises the
  paths its generator reaches; a coverage-guided fuzzer is the right next step.
* No dependency advisory check is performed (`cargo audit` covers that).
* The harness covers the link *admission policy* and the certificate pinning
  *decision*, not the TLS handshake, routing convergence or rate limits: those
  need real sockets and live in `tests/tls.rs`, `tests/linking.rs`,
  `tests/split.rs` and `tests/dialer.rs`.
