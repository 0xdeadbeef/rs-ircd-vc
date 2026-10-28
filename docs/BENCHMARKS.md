# Protocol benchmarks

Measured on the development machine (2 vCPU, `x86_64`, stable Rust, no
`target-cpu=native` or other `RUSTFLAGS`), single-threaded, one benchmark group
at a time. Reproduce with:

```bash
cargo bench --bench protocol
cargo bench --bench fanout
```

| Benchmark | Median | Implied rate |
|---|---:|---|
| `message_parse/plain` (`:nick!user@host PRIVMSG #channel :hello...`) | 128.9 ns | ~7.8 M messages/s |
| `message_parse/tagged` (three IRCv3 tags) | 445.8 ns | ~2.2 M messages/s |
| `message_serialise/untagged` | 34.7 ns | ~28.8 M messages/s |
| `message_serialise/tagged` | 87.8 ns | ~11.4 M messages/s |
| `casemapping/ascii` | 48.4 ns | ~20.6 M folds/s |
| `casemapping/rfc1459` | 48.0 ns | ~20.8 M folds/s |
| `casemapping/equality` (no allocation) | 21.4 ns | ~46.7 M comparisons/s |
| `wildcard/hostmask` | 48.1 ns | ~20.8 M matches/s |
| `wildcard/no_match` | 66.2 ns | ~15.1 M matches/s |
| `numeric_format/display` | 34.0 ns | ~29.4 M formats/s |

## Reading the numbers

* **Parsing allocates per present field.** The plain line allocates the prefix,
  the command and two parameters; the tagged line also allocates three tag
  pairs, which is why it costs 3.5x more. At IRC message rates (tens to
  thousands per second per server) this is far from the bottleneck; a
  zero-copy parser would complicate handler lifetimes for no operational gain.
* **Serialisation is allocation-light.** One `Vec` grows to the line length and
  the `server-time` tag adds a second pass, not a second allocation.
* **Casemapping folds byte-wise into a reusable buffer** (`fold_into`), which
  the benchmarks exercise directly. The equality path allocates nothing.
* **Mask matching is linear** in the input with a single backtrack point
  (greedy star), so hostile masks cannot cause exponential blow-up; there is a
  test that runs a 10 KB adversarial input under 100 ms.
* **The `BENCH` operator command** runs the same parse/fold/serialise loops
  against the live server, so a regression on a deployed binary can be measured
  without rebuild tooling. It is gated behind `diagnostics.benchmarks = true`
  and the `rehash` operator flag.

## Fan-out benchmarks

`Server::deliver` builds at most one serialisation per combination of the
`server-time`, `account-tag` and `message-tags` bits (eight slots) and shares
them across the audience, so fan-out is O(recipients) in enqueues but constant
in serialisations. `cargo bench --bench fanout` measures that trade with 64
recipients in every case.

| Benchmark | Median (64 recipients) | Per recipient | Implied rate |
|---|---:|---:|---:|
| `fanout/untagged_homogeneous` (1 serialisation) | 1.260 µs | 19.7 ns | ~50.8 M recipients/s |
| `fanout/tagged_homogeneous` (`@time`, `@account`, 2 client tags, 1 variant) | 2.813 µs | 43.9 ns | ~22.8 M recipients/s |
| `fanout/tagged_mixed_2` (half plain, half fully capable, 2 variants) | 2.750 µs | 43.0 ns | ~23.3 M recipients/s |
| `fanout/tagged_mixed_8` (every capability combination, 8 variants) | 7.458 µs | 116.5 ns | ~8.6 M recipients/s |

### Reading the numbers

* **Tagging costs about 2.2x an untagged fan-out.** The extra is the tagged
  serialisation plus three capability checks per recipient, not the number of
  recipients.
* **The second variant is free.** Splitting the audience in half lands within
  2% of the single-variant case, so a mixed audience is not charged per group.
* **Eight variants cost ~4.6 µs more than one**, about 0.66 µs per additional
  variant, paid once per fan-out rather than once per recipient. The
  per-recipient floor stays near 20 ns (a `Bytes` clone and a queue send),
  which is why the worst case still reaches 8.6 M recipients/s on one core.
* **A per-recipient allocation was removed after the first run.** `deliver`
  used to clone the account `String` for every recipient that negotiated
  `account-tag`; keeping it borrowed cut the tagged homogeneous case from
  3.163 µs to 2.813 µs (−8.1%) and the mixed case from 2.991 µs to 2.750 µs.
  That allocation, not serialisation, dominated the tagged-versus-untagged gap.
* **Extrapolation, not measurement:** serialising per recipient instead of
  caching would add roughly 0.66 µs × 64 ≈ 42 µs to the worst case, an order of
  magnitude above the 7.5 µs measured. That path is not built, so treat the
  figure as an inference from the per-variant delta.

## Method notes

* Criterion runs each group sequentially; benchmarks are never run in parallel.
* These numbers are from a shared cloud VM, so treat absolute values as
  indicative and compare only within a run.
* The compression comparison lives in [COMPRESSION.md](COMPRESSION.md).

## Command dispatch (`benches/dispatch.rs`)

`cargo bench --bench dispatch` measures the per-command lookup alone. The
`hash_map_hit` arm reproduces the previous `HashMap<&str, _>` lookup with the
same key set, so the comparison is like for like.

| Lookup | Time per call |
|---|---:|
| `hash_map_hit` (previous) | 20.9 ns |
| `match_table_hit` (current) | 3.16 ns |
| `match_table_miss` | 2.50 ns |

A sorted slice with `binary_search_by` was also tried and **rejected**: 47.3 ns,
worse than hashing because six unpredictable branches cost more than one hash.
The match tree wins because it hashes nothing and loops not at all; the compiler
turns it into a length-then-bytes decision tree.

Same caveats as above: one shared VM, single threaded, 20 samples, and the
measurement stops at the lookup rather than command execution.
