//! Markdown and environment rendering for the audit reports.
//!
//! Every generated file says how it was produced and what it does not cover.
//! The numbers come from the harnesses in this binary; nothing is transcribed
//! by hand, so a stale figure is a bug in the generator rather than in a
//! reviewer's memory.

use std::fmt::Write as _;

use serde::Serialize;

use crate::inventory::SourceInventory;
use crate::markers::{Marker, Markers};
use crate::security::SecurityReport;
use crate::speed::SpeedReport;

/// Where a report was produced and from which revision.
#[derive(Debug, Clone, Serialize)]
pub struct Environment {
    /// UTC generation time, RFC 3339.
    pub generated: String,
    /// Rust target triple.
    pub target: String,
    /// Operating system.
    pub os: String,
    /// Architecture.
    pub arch: String,
    /// Logical CPUs reported by the platform.
    pub cores: usize,
    /// `debug` or `release`, from the build profile actually used.
    pub profile: &'static str,
    /// `rustc -V`, or `unknown` when the toolchain is not on `PATH`.
    pub rustc: String,
    /// Short commit hash, or `unknown` outside a checkout.
    pub commit: String,
}

/// Fingerprint the machine and the toolchain.
pub fn environment() -> Environment {
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    Environment {
        generated: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_owned()),
        target: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        cores: std::thread::available_parallelism().map_or(1, |count| count.get()),
        profile,
        rustc: command(&["rustc", "-V"]),
        commit: command(&["git", "rev-parse", "--short", "HEAD"]),
    }
}

/// First line of a command's stdout, or `unknown`.
fn command(argv: &[&str]) -> String {
    let (program, arguments) = argv.split_first().expect("argv is never empty");
    std::process::Command::new(program)
        .args(arguments)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned()
        })
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Render `reports/AUDIT.md`.
pub fn index(
    env: &Environment,
    markers: &Markers,
    inventory: &SourceInventory,
    security: &SecurityReport,
    speed: &SpeedReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Audit report\n");
    banner(&mut out, "AUDIT.md");
    let _ = writeln!(
        out,
        "This is the entry point for the generated audit material. Both reports \
         below are produced by the same run, from the same revision, so their \
         figures are consistent with each other.\n"
    );
    let _ = writeln!(out, "| Report | Contents |");
    let _ = writeln!(out, "| --- | --- |");
    let _ = writeln!(
        out,
        "| [SECURITY.md](SECURITY.md) | marker register, executable checks, parser soak, injection analysis |"
    );
    let _ = writeln!(
        out,
        "| [SPEED.md](SPEED.md) | measured hot paths, distributions and interpretation |"
    );
    let _ = writeln!(
        out,
        "| [audit.json](audit.json) | the same data, machine readable |"
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## Headline\n");
    let _ = writeln!(out, "| Measure | Value |");
    let _ = writeln!(out, "| --- | --- |");
    let _ = writeln!(
        out,
        "| Source files scanned | {} |",
        inventory.library.totals.files
    );
    let _ = writeln!(out, "| Source lines | {} |", inventory.library.totals.lines);
    let _ = writeln!(
        out,
        "| Markers | {} valid, {} problems |",
        markers.markers.len(),
        markers.problems.len()
    );
    let _ = writeln!(
        out,
        "| Security checks | {} of {} passing |",
        security.checks.len() - security.failed(),
        security.checks.len()
    );
    let _ = writeln!(
        out,
        "| Soak | {} generated lines, {} invariant failures |",
        security.soak.iterations, security.soak.failure_count
    );
    let _ = writeln!(out, "| Speed cases | {} |", speed.cases.len());
    let _ = writeln!(
        out,
        "| Unsafe blocks in `src` | {} |",
        inventory.library.totals.unsafe_blocks
    );
    let _ = writeln!(out, "| Commit | `{}` |", env.commit);
    let _ = writeln!(out);

    let _ = writeln!(out, "## Marker totals\n");
    let _ = writeln!(out, "| Category | Markers |");
    let _ = writeln!(out, "| --- | ---: |");
    for (category, count) in markers.category_counts() {
        let _ = writeln!(out, "| {category} | {count} |");
    }
    let _ = writeln!(out, "\n| Severity | Markers |");
    let _ = writeln!(out, "| --- | ---: |");
    for (severity, count) in markers.severity_counts() {
        let _ = writeln!(out, "| {severity} | {count} |");
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Environment\n");
    environment_table(&mut out, env);
    let _ = writeln!(out);

    let _ = writeln!(out, "## Regenerating\n");
    let _ = writeln!(out, "```bash");
    let _ = writeln!(out, "cargo run --release --bin audit -- report");
    let _ = writeln!(out, "cargo run --release --bin audit -- markers --check");
    let _ = writeln!(out, "cargo run --release --bin audit -- speed --json");
    let _ = writeln!(
        out,
        "cargo run --release --bin audit -- security --soak 200000"
    );
    let _ = writeln!(out, "```\n");
    let _ = writeln!(
        out,
        "`report` exits non-zero when a marker is malformed or duplicated, or \
         when an executable check fails, so it can be used as a gate.\n"
    );

    let _ = writeln!(out, "## Scope and limits\n");
    let _ = writeln!(
        out,
        "* The marker register records what was reviewed and where; it is not a \
         proof of correctness, and absence of a marker is not absence of risk."
    );
    let _ = writeln!(
        out,
        "* Static counts are textual, not semantic: an `unsafe` mentioned in a \
         comment counts as an `unsafe` block."
    );
    let _ = writeln!(
        out,
        "* Speed numbers come from one shared virtual machine and are only \
         comparable within a single run of this binary."
    );
    let _ = writeln!(
        out,
        "* The security checks cover the parser, the tag relay, wildcard cost and \
         the credential comparison. They do not cover TLS pinning, link \
         authentication, rate limits or filesystem exposure."
    );
    out
}

/// Render `reports/SECURITY.md`.
pub fn security(
    env: &Environment,
    markers: &Markers,
    inventory: &SourceInventory,
    report: &SecurityReport,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Security report\n");
    banner(&mut out, "SECURITY.md");

    let _ = writeln!(out, "## Summary\n");
    let _ = writeln!(out, "| Measure | Value |");
    let _ = writeln!(out, "| --- | --- |");
    let failed = report.checks.iter().filter(|check| !check.passed).count();
    let _ = writeln!(
        out,
        "| Checks | {} total, {} failed |",
        report.checks.len(),
        failed
    );
    let _ = writeln!(
        out,
        "| Soak | {} lines, {} accepted, {} rejected, {} invariant failures |",
        report.soak.iterations,
        report.soak.accepted,
        report.soak.rejected,
        report.soak.failure_count
    );
    let _ = writeln!(
        out,
        "| Markers | {} valid, {} problems |",
        markers.markers.len(),
        markers.problems.len()
    );
    let _ = writeln!(out, "| Commit | `{}` |", env.commit);
    let _ = writeln!(out);

    let _ = writeln!(out, "### Markers by severity\n");
    let _ = writeln!(out, "| Severity | Count |");
    let _ = writeln!(out, "| --- | ---: |");
    for (severity, count) in markers.severity_counts() {
        let _ = writeln!(out, "| {severity} | {count} |");
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Executable checks\n");
    let _ = writeln!(
        out,
        "Each row is asserted by `src/bin/audit/security.rs` against the real \
         library, not against a copy of its logic.\n"
    );
    let _ = writeln!(out, "| Check | ID | Result | Evidence |");
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    for check in &report.checks {
        let _ = writeln!(
            out,
            "| {} | `{}` | {} | {} |",
            cell(&check.name),
            check.id,
            if check.passed { "pass" } else { "FAIL" },
            cell(&check.detail)
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Parser soak\n");
    let _ = writeln!(
        out,
        "The generator in `src/bin/audit/security.rs` builds lines from IRC \
         syntax, control bytes, multi-byte UTF-8 and fragment soup, seeded with \
         `{}` so a failure can be reproduced exactly. Every accepted message is \
         serialised and re-parsed.\n",
        report.soak.seed
    );
    let _ = writeln!(out, "| Property | Result |");
    let _ = writeln!(out, "| --- | --- |");
    let _ = writeln!(out, "| Lines generated | {} |", report.soak.iterations);
    let _ = writeln!(out, "| Accepted | {} |", report.soak.accepted);
    let _ = writeln!(out, "| Rejected | {} |", report.soak.rejected);
    let _ = writeln!(
        out,
        "| Invariants checked | {} |",
        report.soak.invariants_checked
    );
    let _ = writeln!(
        out,
        "| Invariant failures | {} |",
        report.soak.failure_count
    );
    let _ = writeln!(out);

    if !report.soak.histogram.is_empty() {
        let _ = writeln!(out, "### Why input was rejected\n");
        let _ = writeln!(out, "| Reason | Count |");
        let _ = writeln!(out, "| --- | ---: |");
        for (reason, count) in &report.soak.histogram {
            let _ = writeln!(out, "| {reason} | {count} |");
        }
        let _ = writeln!(out);
    }

    if !report.soak.failures.is_empty() {
        let _ = writeln!(out, "### Recorded violations\n");
        for failure in &report.soak.failures {
            let _ = writeln!(out, "* `{failure}`");
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## Injection analysis\n");
    let _ = writeln!(
        out,
        "A single line of input must never become two lines of output. The \
         chain this guards is: client line -> `Message::parse` -> handler \
         parameter -> `Message::write_to` or `to_bytes_limited` -> socket, with \
         the same path taken for relayed link traffic and script output. The \
         guard is the control-character rejection in `Message::parse`, because \
         every later stage copies parameters verbatim.\n"
    );
    let _ = writeln!(
        out,
        "Check `C-CTRL` covers C0 bytes and `DEL` in a trailing parameter, a \
         middle parameter, the prefix and the tag block. Check `C-SOAK` re-checks \
         the property on every accepted generated message: exactly one trailing \
         `CRLF`, no interior control bytes, and a serialised form that re-parses \
         to the same message.\n"
    );

    let _ = writeln!(out, "### Wildcard cost\n");
    let _ = writeln!(
        out,
        "Ban masks and hook conditions use `wildcard_match`. The matcher keeps a \
         single backtrack point (the most recent `*`), so cost is bounded by \
         `len(text) * len(pattern)` with no exponential case. Measured with the \
         adversarial pattern `*a*a*a*a*a*a*a*b`:\n"
    );
    let _ = writeln!(out, "| Input bytes | Per call | Per byte |");
    let _ = writeln!(out, "| ---: | ---: | ---: |");
    for point in &report.scaling {
        let _ = writeln!(
            out,
            "| {} | {} | {:.2} ns |",
            point.bytes,
            duration(point.ns_per_call),
            point.ns_per_byte
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "### Credential comparison timing\n");
    let _ = writeln!(
        out,
        "`constant_time_eq` compares SHA-256 digests through `subtle`, which \
         cannot short-circuit. The 4 KiB comparisons are shown with the naive \
         `str` equality for contrast: its differing rows return early, and both \
         number and position of differences change how much it reads. These are \
         indicative numbers from a shared VM, not a timing-leak proof.\n"
    );
    let _ = writeln!(out, "| Probe | Median |");
    let _ = writeln!(out, "| --- | ---: |");
    for probe in &report.probes {
        let _ = writeln!(out, "| `{}` | {} |", probe.name, duration(probe.median_ns));
    }
    let _ = writeln!(out);

    marker_register(
        &mut out,
        markers,
        &["security", "safety", "policy"],
        "Security and safety markers",
    );

    let _ = writeln!(out, "## Static inventory\n");
    let _ = writeln!(
        out,
        "Textual counts across the trees. `expect` is allowed for invariant \
         violations with a message; `unwrap` is not, and the `src` figure is the \
         one to keep at zero.\n"
    );
    let _ = writeln!(
        out,
        "| Tree | Files | Lines | Code | unsafe | unwrap | expect | panic | allow | debug prints | stubs |"
    );
    let _ = writeln!(
        out,
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
    );
    for tree in inventory.trees() {
        let totals = &tree.totals;
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            tree.name,
            totals.files,
            totals.lines,
            totals.code_lines,
            totals.unsafe_blocks,
            totals.unwraps,
            totals.expects,
            totals.panics,
            totals.allows,
            totals.debug_prints,
            totals.stubs
        );
    }
    let _ = writeln!(out);

    let unannotated = inventory.unannotated(markers.annotated_files().as_slice(), 150);
    if !unannotated.is_empty() {
        let _ = writeln!(out, "## Files without a marker\n");
        let _ = writeln!(
            out,
            "Modules of at least 150 lines carrying no `MARK:` annotation. These \
             were read or searched during the audit, but have no durable \
             annotation to show for it, so they are the first candidates for the \
             next pass.\n"
        );
        let _ = writeln!(out, "| File | Code lines |");
        let _ = writeln!(out, "| --- | ---: |");
        for file in unannotated {
            let _ = writeln!(out, "| `{}` | {} |", file.path, file.code_lines);
        }
        let _ = writeln!(out);
    }

    if !markers.problems.is_empty() {
        let _ = writeln!(out, "## Marker problems\n");
        for problem in &markers.problems {
            let _ = writeln!(out, "* {}", cell(&problem.to_string()));
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "## Not covered\n");
    let _ = writeln!(
        out,
        "* **TLS and link authentication.** Certificate pinning, cipher policy \
         and the link password handshake are exercised by integration tests, not \
         by this harness."
    );
    let _ = writeln!(
        out,
        "* **Resource exhaustion under load.** Bounded queues, connection limits \
         and compression ceilings are asserted in tests; there is no sustained \
         flood harness here."
    );
    let _ = writeln!(
        out,
        "* **Fuzzing.** The soak generator is deterministic and seeded, so it \
         covers the paths its grammar reaches and nothing else. A coverage-guided \
         fuzzer is the correct next step."
    );
    let _ = writeln!(
        out,
        "* **Dependency advisories.** No lockfile audit is performed; run \
         `cargo audit` for that."
    );
    out
}

/// Render `reports/SPEED.md`.
pub fn speed(env: &Environment, markers: &Markers, report: &SpeedReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Speed report\n");
    banner(&mut out, "SPEED.md");

    let _ = writeln!(out, "## Summary\n");
    let slowest = report
        .cases
        .iter()
        .max_by(|left, right| left.sample.median_ns.total_cmp(&right.sample.median_ns));
    let _ = writeln!(out, "| Measure | Value |");
    let _ = writeln!(out, "| --- | --- |");
    let _ = writeln!(out, "| Cases | {} |", report.cases.len());
    let _ = writeln!(out, "| Operations per round | {} |", report.iterations);
    let _ = writeln!(out, "| Rounds | {} |", report.rounds);
    if let Some(case) = slowest {
        let _ = writeln!(
            out,
            "| Slowest case | `{}` at {} |",
            case.name,
            duration(case.sample.median_ns)
        );
    }
    let noisy = report
        .cases
        .iter()
        .filter(|case| case.sample.cv_pct > 10.0)
        .count();
    let _ = writeln!(out, "| Cases above 10% variation | {noisy} |");
    let _ = writeln!(out, "| Commit | `{}` |", env.commit);
    let _ = writeln!(out);

    let _ = writeln!(out, "## Measurements\n");
    let _ = writeln!(
        out,
        "`median` is the typical round and `min` the best one; a large gap \
         between them means the machine interfered. `cv` is the standard \
         deviation across rounds as a percentage of the mean: above 10% the row \
         is noise, not a result.\n"
    );
    let _ = writeln!(
        out,
        "| Case | Median | Min | Max | cv | Implied rate | Iterations |"
    );
    let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: | ---: | ---: |");
    for case in &report.cases {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {:.1}% | {} | {} |",
            case.name,
            duration(case.sample.median_ns),
            duration(case.sample.min_ns),
            duration(case.sample.max_ns),
            case.sample.cv_pct,
            rate(case.sample.ops_per_second),
            case.sample.iterations
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Interpretation\n");
    let _ = writeln!(out, "| Case | What the number means |");
    let _ = writeln!(out, "| --- | --- |");
    for case in &report.cases {
        let _ = writeln!(out, "| `{}` | {} |", case.name, cell(case.note));
    }
    let _ = writeln!(out);

    marker_register(&mut out, markers, &["speed"], "Marked hot paths");

    let _ = writeln!(out, "## Method\n");
    let _ = writeln!(
        out,
        "* One case at a time, one thread, no `RUSTFLAGS`, no `target-cpu=native`: \
         the numbers describe the default build, which is what ships."
    );
    let _ = writeln!(
        out,
        "* Each round times a fixed number of operations after a warm-up pass. \
         The harness folds a checksum so the optimiser cannot delete the work."
    );
    let _ = writeln!(
        out,
        "* Allocation is included wherever the real path allocates: parsing \
         builds a `Message`, while serialisation reuses one buffer."
    );
    let _ = writeln!(
        out,
        "* This is not a replacement for `cargo bench --bench dispatch` and \
         friends, which use criterion and report confidence intervals. It exists \
         so a report can be generated from a single command with the environment \
         fingerprinted."
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## Limits\n");
    let _ = writeln!(
        out,
        "* Absolute values mean little across machines; compare two runs of this \
         binary on the same host, or the same case across revisions."
    );
    let _ = writeln!(
        out,
        "* A debug build is not representative. Generate reports with \
         `--release`, which the profile line above records."
    );
    let _ = writeln!(
        out,
        "* These cases measure library functions in isolation. They say nothing \
         about syscall cost, lock contention or fan-out under a real client load; \
         `BENCH` on a live server and the fan-out criterion bench cover those \
         separately."
    );
    out
}

/// Header block shared by every generated file.
fn banner(out: &mut String, name: &str) {
    let _ = writeln!(
        out,
        "> Generated by `cargo run --bin audit -- report`. Do not edit by hand: \
         regenerate `{name}` instead.\n"
    );
}

/// Environment table.
fn environment_table(out: &mut String, env: &Environment) {
    let _ = writeln!(out, "| Property | Value |");
    let _ = writeln!(out, "| --- | --- |");
    let _ = writeln!(out, "| Generated | {} |", env.generated);
    let _ = writeln!(out, "| Commit | `{}` |", env.commit);
    let _ = writeln!(out, "| Target | `{}` |", env.target);
    let _ = writeln!(out, "| Profile | {} |", env.profile);
    let _ = writeln!(out, "| Toolchain | `{}` |", env.rustc);
    let _ = writeln!(out, "| Logical CPUs | {} |", env.cores);
}

/// Marker tables grouped by the requested categories.
fn marker_register(out: &mut String, markers: &Markers, categories: &[&str], title: &str) {
    let selected = markers.in_categories(categories);
    let _ = writeln!(out, "## {title}\n");
    if selected.is_empty() {
        let _ = writeln!(out, "No markers in this category.\n");
        return;
    }
    let _ = writeln!(out, "| ID | Severity | Location | Note |");
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    for marker in selected {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} |",
            marker.id,
            marker.severity,
            location(marker),
            cell(&marker.text)
        );
    }
    let _ = writeln!(out);
}

/// Link to a marker's source line, relative to `reports/`.
fn location(marker: &Marker) -> String {
    format!(
        "[{}:{}](../{}#L{})",
        marker.file, marker.line, marker.file, marker.line
    )
}

/// Human-readable duration.
pub fn duration(nanoseconds: f64) -> String {
    if nanoseconds >= 1_000_000.0 {
        format!("{:.2} ms", nanoseconds / 1_000_000.0)
    } else if nanoseconds >= 1_000.0 {
        format!("{:.2} us", nanoseconds / 1_000.0)
    } else {
        format!("{nanoseconds:.1} ns")
    }
}

/// Human-readable rate.
pub fn rate(operations: f64) -> String {
    if operations >= 1e6 {
        format!("{:.1} M/s", operations / 1e6)
    } else if operations >= 1e3 {
        format!("{:.0} k/s", operations / 1e3)
    } else {
        format!("{operations:.0} /s")
    }
}

/// Escape a Markdown table cell.
fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_scale() {
        assert_eq!(duration(12.34), "12.3 ns");
        assert_eq!(duration(1_500.0), "1.50 us");
        assert_eq!(duration(2_000_000.0), "2.00 ms");
    }

    #[test]
    fn rates_scale() {
        assert_eq!(rate(12.0), "12 /s");
        assert_eq!(rate(1_500.0), "2 k/s");
        assert_eq!(rate(7_800_000.0), "7.8 M/s");
    }

    #[test]
    fn cells_escape_pipes() {
        assert_eq!(cell("a | b"), "a \\| b");
        assert_eq!(cell("two\nlines"), "two lines");
    }

    #[test]
    fn environment_is_populated() {
        let env = environment();
        assert!(!env.generated.is_empty());
        assert!(env.cores >= 1);
        assert!(matches!(env.profile, "debug" | "release"));
    }
}
