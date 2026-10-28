//! Executable security checks and the parser soak harness.
//!
//! The static marker register says what was reviewed; these checks say what
//! actually holds when the code runs. Each one builds its own hostile input, so
//! a regression shows up as a failed row rather than a sentence in a design
//! document.

use ircd::protocol::{Message, ParseError};
use ircd::util::{constant_time_eq, wildcard_match};

use crate::speed::measure;

/// The string a failed check reports at most.
const MAX_RECORDED_FAILURES: usize = 8;

/// Outcome of one check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Check {
    /// Short identifier used in the report.
    pub id: &'static str,
    /// What is being asserted.
    pub name: String,
    /// Whether the assertion held.
    pub passed: bool,
    /// Evidence: inputs tested, or the failures.
    pub detail: String,
}

/// Result of feeding generated input to the parser.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Soak {
    /// Seed, so a run is reproducible.
    pub seed: u64,
    /// Lines generated.
    pub iterations: u64,
    /// Lines the parser accepted.
    pub accepted: usize,
    /// Lines the parser rejected.
    pub rejected: usize,
    /// Accepted lines whose invariants were checked.
    pub invariants_checked: usize,
    /// Invariant violations observed.
    pub failure_count: usize,
    /// Up to [`MAX_RECORDED_FAILURES`] violations, with the input escaped.
    pub failures: Vec<String>,
    /// Rejection reasons, most common first.
    pub histogram: Vec<(&'static str, usize)>,
}

/// Timing for one input size.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Scaling {
    /// Input length in bytes.
    pub bytes: usize,
    /// Median cost of one call.
    pub ns_per_call: f64,
    /// Median cost attributed to one byte.
    pub ns_per_byte: f64,
}

/// One timing comparison that is evidence, not a proof.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Probe {
    /// What was measured.
    pub name: String,
    /// Median nanoseconds per call.
    pub median_ns: f64,
}

/// Everything the security harness produced.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SecurityReport {
    /// Individual assertions.
    pub checks: Vec<Check>,
    /// Generated-input results.
    pub soak: Soak,
    /// Wildcard matching cost by input size.
    pub scaling: Vec<Scaling>,
    /// Timing comparisons around the constant-time comparison.
    pub probes: Vec<Probe>,
}

impl SecurityReport {
    /// Number of failed checks.
    pub fn failed(&self) -> usize {
        self.checks.iter().filter(|check| !check.passed).count() + self.soak.failure_count
    }
}

/// Run every check.
pub fn run(soak_iterations: u64, seed: u64) -> SecurityReport {
    let mut report = SecurityReport {
        checks: vec![
            control_characters(),
            length_ceiling(),
            parameter_ceiling(),
            tag_relay(),
        ],
        ..SecurityReport::default()
    };

    report.soak = soak(soak_iterations, seed);
    report.checks.push(Check {
        id: "C-SOAK",
        name: "Generated input never panics and always yields a decision".to_owned(),
        passed: report.soak.accepted > 0 && report.soak.failure_count == 0,
        detail: format!(
            "{} lines, {} accepted, {} rejected, {} invariant failures",
            report.soak.iterations,
            report.soak.accepted,
            report.soak.rejected,
            report.soak.failure_count
        ),
    });

    report.scaling = scaling();
    report.checks.push(wildcard_scaling_check(&report.scaling));
    report.probes = probes();
    report
}

/// Every C0 control byte, plus `DEL`, in a middle and a trailing parameter.
fn control_characters() -> Check {
    let mut failures = Vec::new();
    let mut vectors = 0usize;
    for byte in (0u8..=0x1f).chain(std::iter::once(0x7f)) {
        let character = char::from(byte);
        for line in [
            format!("PRIVMSG #channel :a{character}b"),
            format!(":ali{character}ce PRIVMSG #channel :hello"),
            format!("PRIVMSG #chan{character}nel :hello"),
            format!("PRIVMSG #channel {character}hello"),
            format!("@{character}=x PRIVMSG #channel :hello"),
        ] {
            vectors += 1;
            if let Err(error) = Message::parse(&line, 512) {
                if error != ParseError::InvalidControl {
                    failures.push(format!(
                        "{byte:#04x} rejected as {error:?} rather than InvalidControl"
                    ));
                }
            } else {
                failures.push(format!("{byte:#04x} accepted in {:?}", escape(&line)));
            }
        }
    }
    Check {
        id: "C-CTRL",
        name: "Control characters are rejected at the parse edge".to_owned(),
        passed: failures.is_empty(),
        detail: if failures.is_empty() {
            format!("{vectors} vectors, all rejected with InvalidControl")
        } else {
            summarise(&failures)
        },
    }
}

/// Length limits on the line, the tag block and the serialiser.
fn length_ceiling() -> Check {
    let mut failures = Vec::new();
    const LIMIT: usize = 512;

    // `PRIVMSG #c :` is 12 bytes, so the body that just fits is 500 bytes.
    let exact = format!("PRIVMSG #c :{}", "x".repeat(LIMIT - 12));
    assert_eq!(exact.len(), LIMIT);
    if Message::parse(&exact, LIMIT).is_err() {
        failures.push("a line of exactly max_len was rejected".to_owned());
    }
    let over = format!("PRIVMSG #c :{}", "x".repeat(LIMIT - 11));
    match Message::parse(&over, LIMIT) {
        Err(ParseError::TooLong(_)) => {}
        other => failures.push(format!("max_len + 1 byte gave {other:?}")),
    }

    // Tags get their own budget, and spending it must not stretch the message.
    let tag_overflow = format!("@+a={} PRIVMSG #c :hi", "v".repeat(4_200));
    match Message::parse(&tag_overflow, LIMIT) {
        Err(ParseError::TooLong(_)) => {}
        other => failures.push(format!("oversized tag block gave {other:?}")),
    }
    let tag_ok = format!("@+a={} PRIVMSG #c :hi", "v".repeat(3_000));
    if Message::parse(&tag_ok, LIMIT).is_err() {
        failures.push("a tag block inside the budget was rejected".to_owned());
    }

    // The serialiser must never exceed the ceiling, including degenerate ones.
    let message = Message::parse(&exact, LIMIT).expect("exact-length line parses");
    for ceiling in [0usize, 1, 2, 3, 512] {
        let encoded = message.to_bytes_limited(ceiling);
        if encoded.len() > ceiling.max(2) {
            failures.push(format!(
                "to_bytes_limited({ceiling}) produced {} bytes",
                encoded.len()
            ));
        }
    }
    let long = Message {
        command: "PRIVMSG".to_owned(),
        params: vec!["#c".to_owned(), "y".repeat(2_000)],
        ..Message::default()
    };
    if long.to_bytes_limited(LIMIT).len() > LIMIT {
        failures.push("to_bytes_limited truncated past its ceiling".to_owned());
    }

    Check {
        id: "C-LEN",
        name: "Line, tag and serialisation ceilings hold at the boundary".to_owned(),
        passed: failures.is_empty(),
        detail: if failures.is_empty() {
            format!("boundaries at {LIMIT} bytes, tag budget {API_TAG_BUDGET} bytes")
        } else {
            summarise(&failures)
        },
    }
}

/// Tag budget as advertised by the parser's constants, quoted for the report.
const API_TAG_BUDGET: usize = 4096;

/// The 15-parameter ceiling.
fn parameter_ceiling() -> Check {
    let mut failures = Vec::new();
    let fifteen = format!("CMD {}", vec!["p"; 15].join(" "));
    if Message::parse(&fifteen, 512).is_err() {
        failures.push("15 parameters were rejected".to_owned());
    }
    let sixteen = format!("CMD {}", vec!["p"; 16].join(" "));
    match Message::parse(&sixteen, 512) {
        Err(ParseError::TooManyParams) => {}
        other => failures.push(format!("16 parameters gave {other:?}")),
    }
    match Message::parse("CMD :trailing only", 512) {
        Ok(message) if message.params == ["trailing only"] => {}
        other => failures.push(format!("trailing parameter gave {other:?}")),
    }
    Check {
        id: "C-PARAM",
        name: "Parameter count and trailing form follow RFC 1459".to_owned(),
        passed: failures.is_empty(),
        detail: if failures.is_empty() {
            "15 accepted, 16 rejected, trailing parameter preserved".to_owned()
        } else {
            summarise(&failures)
        },
    }
}

/// Client tag relay rules.
fn tag_relay() -> Check {
    let mut failures = Vec::new();
    let mut message = Message::command("PRIVMSG");
    message.push_tag("time", "2026-10-28T00:00:00Z");
    message.push_tag("account", "alice");
    message.push_tag("label", "abc");
    message.push_tag("+draft/reply", "xyz");
    message.push_tag("vendor/tag", "value");

    let plain = message.client_tags(&[]);
    if plain.iter().any(|(key, _)| !key.starts_with('+')) {
        failures.push(format!("server tags were relayed: {plain:?}"));
    }
    if !plain.iter().any(|(key, _)| key == "+draft/reply") {
        failures.push("a `+`-prefixed client tag was dropped".to_owned());
    }

    let allowlisted = message.client_tags(&["vendor/tag".to_owned()]);
    if !allowlisted.iter().any(|(key, _)| key == "vendor/tag") {
        failures.push("an allowlisted vendor tag was dropped".to_owned());
    }
    if plain.iter().any(|(key, _)| key == "vendor/tag") {
        failures.push("an unlisted vendor tag was relayed".to_owned());
    }

    let mut flood = Message::command("PRIVMSG");
    for index in 0..4 {
        flood.push_tag(format!("+bulk{index}"), "v".repeat(3_000));
    }
    let relayed = flood.client_tags(&[]);
    let total: usize = relayed
        .iter()
        .map(|(key, value)| key.len() + value.len() + 2)
        .sum();
    if total > API_TAG_BUDGET {
        failures.push(format!("relayed tags total {total} bytes"));
    }

    Check {
        id: "C-TAG",
        name: "Only client tags are relayed, inside the size budget".to_owned(),
        passed: failures.is_empty(),
        detail: if failures.is_empty() {
            format!("server tags blocked, allowlist honoured, flood clipped to {total} bytes")
        } else {
            summarise(&failures)
        },
    }
}

/// Feed generated lines to the parser and check every accepted one.
fn soak(iterations: u64, seed: u64) -> Soak {
    let mut rng = XorShift64::new(seed);
    let mut soak = Soak {
        seed,
        iterations,
        ..Soak::default()
    };
    let mut histogram: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();

    for _ in 0..iterations {
        let line = generate(&mut rng);
        let message = match Message::parse(&line, 512) {
            Ok(message) => message,
            Err(error) => {
                soak.rejected += 1;
                *histogram.entry(reason(&error)).or_insert(0) += 1;
                continue;
            }
        };
        soak.accepted += 1;
        soak.invariants_checked += 1;

        let mut encoded = Vec::with_capacity(128);
        message.write_to(&mut encoded);
        let body = encoded.strip_suffix(b"\r\n");
        let mut violations = Vec::new();
        let Some(body) = body else {
            violations.push("serialised line has no trailing CRLF".to_owned());
            record(&mut soak, &line, &violations);
            continue;
        };
        if body.windows(2).any(|pair| pair == b"\r\n") {
            violations.push("serialised body contains an interior CRLF".to_owned());
        }
        if body.iter().any(|byte| *byte < 0x20 || *byte == 0x7f) {
            violations.push("serialised body contains a control character".to_owned());
        }
        let Ok(text) = std::str::from_utf8(body) else {
            violations.push("serialised body is not valid UTF-8".to_owned());
            record(&mut soak, &line, &violations);
            continue;
        };
        match Message::parse(text, 8_192) {
            Ok(again) => {
                if again.command != message.command
                    || again.params != message.params
                    || again.prefix != message.prefix
                    || again.tags != message.tags
                {
                    violations
                        .push("re-parsing the serialised form changed the message".to_owned());
                }
            }
            Err(error) => violations.push(format!(
                "serialised form does not parse: {}",
                reason(&error)
            )),
        }
        if !violations.is_empty() {
            record(&mut soak, &line, &violations);
        }
    }

    let mut histogram: Vec<(&'static str, usize)> = histogram.into_iter().collect();
    histogram.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(right.0)));
    soak.histogram = histogram;
    soak
}

/// Record a violation, keeping the input reproduced byte-exactly.
fn record(soak: &mut Soak, line: &str, violations: &[String]) {
    soak.failure_count += 1;
    if soak.failures.len() < MAX_RECORDED_FAILURES {
        soak.failures
            .push(format!("{:?}: {}", escape(line), violations.join(", ")));
    }
}

/// Name a rejection reason without the variable part of the payload.
fn reason(error: &ParseError) -> &'static str {
    match error {
        ParseError::Empty => "empty",
        ParseError::MissingCommand => "missing command",
        ParseError::InvalidCommand(_) => "invalid command",
        ParseError::TooManyParams => "too many parameters",
        ParseError::TooLong(_) => "too long",
        ParseError::InvalidTag => "invalid tag",
        ParseError::InvalidControl => "control character",
    }
}

/// Build one generated line.
///
/// Most iterations are shaped like a real message so the invariants are
/// exercised on accepted input; the control bytes and odd fragments make sure
/// rejection paths are hit too.
fn generate(rng: &mut XorShift64) -> String {
    const TEXT: &[&str] = &[
        "hello there",
        "a:b",
        "with; semicolon",
        "back\\slash",
        "",
        "é and 日本",
        "\u{0}",
        "\u{1}",
        "\u{7f}",
        "  leading space",
        "trailing ",
    ];
    const VERBS: &[&str] = &["PRIVMSG", "NOTICE", "JOIN", "PART", "NICK", "PING", "001"];
    const PREFIXES: &[&str] = &[
        "",
        ":alice!user@host",
        ":irc.example.org",
        ":bad prefix with spaces",
    ];
    const FRAGMENTS: &[&str] = &[
        "PRIVMSG",
        "#chan",
        "&local",
        "alice",
        ":",
        "@time=2026-10-28T00:00:00Z",
        "@a=b;c=d",
        "@+draft/reply=abc",
        "trailing words",
        "\u{1}",
        "\u{7f}",
        "\r",
        "\n",
        "fe80::1",
        "$a:*",
        "*!*@*",
        "MOD",
        "\u{7f}",
    ];

    // Every rejection path gets its own share, so the histogram in the report
    // is not dominated by the control-character guard alone.
    match rng.below(20) {
        0 => return format!("PRIVMSG #chan :{}", "x".repeat(600)),
        1 => return format!("CMD {}", vec!["p"; 20].join(" ")),
        _ => {}
    }

    // Seven in ten lines are well formed; the rest are fragment soup.
    if rng.below(10) < 7 {
        let verb = VERBS[rng.below(VERBS.len() as u64) as usize];
        let prefix = PREFIXES[rng.below(PREFIXES.len() as u64) as usize];
        let text = TEXT[rng.below(TEXT.len() as u64) as usize];
        let tags = if rng.below(4) == 0 { "@+x=y " } else { "" };
        let target = if rng.below(2) == 0 { "#chan" } else { "alice" };
        return format!("{tags}{prefix} {verb} {target} :{text}");
    }

    let count = 1 + rng.below(20) as usize;
    let mut line = String::with_capacity(count * 6);
    for _ in 0..count {
        line.push_str(FRAGMENTS[rng.below(FRAGMENTS.len() as u64) as usize]);
    }
    line
}

/// Escape controls so a failing input can be pasted back into a test.
fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\0' => out.push_str("\\0"),
            other if (other as u32) < 0x20 || other as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", other as u32));
            }
            other => out.push(other),
        }
    }
    out
}

/// Cost of an adversarial mask match at three input sizes.
fn scaling() -> Vec<Scaling> {
    let pattern = "*a*a*a*a*a*a*a*b";
    [1_024usize, 10_240, 102_400]
        .into_iter()
        .map(|bytes| {
            let text = "a".repeat(bytes);
            let iterations = (2_000_000 / bytes as u64).clamp(5, 2_000);
            let sample = measure(iterations, 5, || u64::from(wildcard_match(pattern, &text)));
            Scaling {
                bytes,
                ns_per_call: sample.median_ns,
                ns_per_byte: sample.median_ns / bytes as f64,
            }
        })
        .collect()
}

/// Assert that per-byte cost stays flat as the input grows.
///
/// With a fixed pattern the greedy matcher walks the text a bounded number of
/// times, so cost must be linear in the input. A super-linear result here would
/// mean a hostile mask can burn unbounded CPU on one line.
fn wildcard_scaling_check(scaling: &[Scaling]) -> Check {
    let mut failures = Vec::new();
    if let (Some(first), Some(last)) = (scaling.first(), scaling.last()) {
        if first.ns_per_byte > 0.0 {
            let growth = last.ns_per_byte / first.ns_per_byte;
            if growth > 3.0 {
                failures.push(format!(
                    "per-byte cost grew {growth:.1}x between {} and {} bytes",
                    first.bytes, last.bytes
                ));
            }
        }
    } else {
        failures.push("no scaling samples were taken".to_owned());
    }
    Check {
        id: "C-WILD",
        name: "Adversarial wildcard matching stays linear in the input".to_owned(),
        passed: failures.is_empty(),
        detail: if failures.is_empty() {
            scaling
                .iter()
                .map(|point| format!("{} B: {:.2} ns/B", point.bytes, point.ns_per_byte))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            summarise(&failures)
        },
    }
}

/// Timing around the constant-time comparison.
///
/// The strings are 4 KiB so an early exit is measurable: at 64 bytes both
/// variants fit in a couple of vector loads and the difference disappears. The
/// numbers are direction only, because a shared VM cannot prove the absence of
/// a timing leak, but the gap between the two `str_eq` rows is the leak a
/// password oracle looks for.
fn probes() -> Vec<Probe> {
    let left = "a".repeat(4_096);
    let same = left.clone();
    let mut differs_first = left.clone();
    differs_first.replace_range(0..1, "b");
    let mut differs_last = left.clone();
    differs_last.replace_range(4_095..4_096, "b");

    let cases = [
        ("constant_time_eq/equal", &same),
        ("constant_time_eq/differs_first", &differs_first),
        ("constant_time_eq/differs_last", &differs_last),
    ];
    let mut probes = Vec::with_capacity(6);
    for (name, right) in cases {
        let sample = measure(20_000, 5, || u64::from(constant_time_eq(&left, right)));
        probes.push(Probe {
            name: name.to_owned(),
            median_ns: sample.median_ns,
        });
    }
    let comparisons = [
        ("str_eq/equal", &same),
        ("str_eq/differs_first", &differs_first),
        ("str_eq/differs_last", &differs_last),
    ];
    for (name, right) in comparisons {
        let sample = measure(20_000, 5, || u64::from(left == *right));
        probes.push(Probe {
            name: name.to_owned(),
            median_ns: sample.median_ns,
        });
    }
    probes
}

/// Join failures for a report cell, keeping it readable.
fn summarise(failures: &[String]) -> String {
    let shown = failures
        .iter()
        .take(4)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    if failures.len() > 4 {
        format!("{shown}; and {} more", failures.len() - 4)
    } else {
        shown
    }
}

/// Small deterministic PRNG (xorshift64), so a failing run is reproducible from
/// its seed without pulling a dependency into the audit tool.
struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    /// Uniform value in `0..bound`, where `bound >= 1`.
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_matrix_passes() {
        assert!(control_characters().passed, "{:?}", control_characters());
    }

    #[test]
    fn ceilings_pass() {
        assert!(length_ceiling().passed);
        assert!(parameter_ceiling().passed);
    }

    #[test]
    fn tag_rules_pass() {
        let check = tag_relay();
        assert!(check.passed, "{}", check.detail);
    }

    #[test]
    fn soak_is_reproducible_and_clean() {
        let first = soak(2_000, 42);
        let second = soak(2_000, 42);
        assert_eq!(first.accepted, second.accepted);
        assert_eq!(first.rejected, second.rejected);
        assert_eq!(first.failure_count, 0, "{:?}", first.failures);
        assert!(first.accepted > 0, "no input was accepted");
    }

    #[test]
    fn scaling_and_probes_are_populated() {
        let points = scaling();
        assert_eq!(points.len(), 3);
        assert!(points.iter().all(|point| point.ns_per_byte > 0.0));
        assert_eq!(probes().len(), 6);
    }

    #[test]
    fn escaping_keeps_controls_visible() {
        assert_eq!(escape("a\r\nb"), "a\\r\\nb");
        assert_eq!(escape("\u{1}"), "\\x01");
        assert_eq!(escape("\u{7f}"), "\\x7f");
    }

    #[test]
    fn prng_is_deterministic_and_seed_zero_is_replaced() {
        assert_eq!(XorShift64::new(7).next(), XorShift64::new(7).next());
        assert_ne!(XorShift64::new(0).0, 0);
    }
}
