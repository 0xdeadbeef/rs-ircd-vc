//! In-process speed harness.
//!
//! Every case runs a fixed number of operations per round with a warm-up pass
//! and reports the distribution of per-round timings rather than a single
//! figure. Registering results in one table with a coefficient of variation
//! makes a noisy run visible instead of letting it look authoritative: a case
//! with `cv` above roughly 10% on this machine is not a result to quote.
//!
//! Nothing here uses `criterion`, threads or SIMD autovectorisation flags. One
//! case runs at a time on one thread, the closures consume their own output
//! through [`std::hint::black_box`], and a checksum is folded into the outer
//! loop so the optimiser cannot delete the work.

use std::hint::black_box;
use std::time::Instant;

use ircd::commands;
use ircd::protocol::{Message, Numeric};
use ircd::server::channel::BanEntry;
use ircd::util::wildcard_match;

/// One measured case.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Sample {
    /// Fastest round, in nanoseconds per operation.
    pub min_ns: f64,
    /// Median round, in nanoseconds per operation.
    pub median_ns: f64,
    /// Slowest round, in nanoseconds per operation.
    pub max_ns: f64,
    /// Standard deviation across rounds, as a percentage of the mean.
    pub cv_pct: f64,
    /// Operations per second implied by the median.
    pub ops_per_second: f64,
    /// Operations timed per round.
    pub iterations: u64,
    /// Rounds timed.
    pub rounds: usize,
}

/// A named measurement plus the interpretation it deserves.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Case {
    /// Stable label such as `parse/plain`.
    pub name: &'static str,
    /// What the number means, and what it does not.
    pub note: &'static str,
    /// Measurements.
    pub sample: Sample,
}

/// A full run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpeedReport {
    /// Cases in report order.
    pub cases: Vec<Case>,
    /// Operations per round requested.
    pub iterations: u64,
    /// Rounds requested.
    pub rounds: usize,
}

/// Time `body` and summarise the rounds.
///
/// `body` must return a value derived from its work so the optimiser cannot
/// remove the call; the value is folded into a checksum that is itself
/// black-boxed.
pub fn measure<F>(iterations: u64, rounds: usize, mut body: F) -> Sample
where
    F: FnMut() -> u64,
{
    let iterations = iterations.max(1);
    let rounds = rounds.max(1);
    let warmup = (iterations / 8).max(1);

    let mut checksum = 0u64;
    for _ in 0..warmup {
        checksum ^= black_box(body());
    }

    let mut per_round = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let started = Instant::now();
        for _ in 0..iterations {
            checksum ^= black_box(body());
        }
        let elapsed = started.elapsed().as_secs_f64() * 1e9;
        per_round.push(elapsed / iterations as f64);
    }
    black_box(checksum);

    per_round.sort_by(f64::total_cmp);
    let mean = per_round.iter().sum::<f64>() / per_round.len() as f64;
    let variance = per_round
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / per_round.len() as f64;
    let median = per_round[per_round.len() / 2];
    let min = per_round[0];
    let max = per_round[per_round.len() - 1];

    Sample {
        min_ns: min,
        median_ns: median,
        max_ns: max,
        cv_pct: if mean > 0.0 {
            variance.sqrt() / mean * 100.0
        } else {
            0.0
        },
        ops_per_second: if median > 0.0 { 1e9 / median } else { 0.0 },
        iterations,
        rounds,
    }
}

/// Run every case once.
pub fn run(iterations: u64, rounds: usize) -> SpeedReport {
    let plain = ":alice!user@example.org PRIVMSG #channel :hello there, this is a message";
    let tagged = "@time=2026-10-28T12:00:00.000Z;account=alice;+draft/reply=abc123 \
                  :alice!user@example.org PRIVMSG #channel :hello there, this is a message";

    let mut cases = Vec::new();

    cases.push(Case {
        name: "parse/plain",
        note: "one prefix, two parameters; allocates each present field",
        sample: measure(iterations, rounds, || {
            Message::parse(plain, 512).map_or(0, |message| message.params.len() as u64)
        }),
    });

    cases.push(Case {
        name: "parse/tagged",
        note: "three IRCv3 tags plus the same body as `parse/plain`",
        sample: measure(iterations, rounds, || {
            Message::parse(tagged, 512).map_or(0, |message| message.tags.len() as u64)
        }),
    });

    cases.push(Case {
        name: "parse/reject_control",
        note: "the injection guard: cost of rejecting a line with one control byte",
        sample: measure(iterations, rounds, || {
            u64::from(Message::parse("PRIVMSG #c :a\u{1}b", 512).is_err())
        }),
    });

    let untagged = Message {
        prefix: Some("alice!user@example.org".to_owned()),
        command: "PRIVMSG".to_owned(),
        params: vec![
            "#channel".to_owned(),
            "hello there, this is a message".to_owned(),
        ],
        tags: Vec::new(),
    };
    let mut tagged_message = untagged.clone();
    tagged_message.push_tag("time", "2026-10-28T12:00:00.000Z");
    tagged_message.push_tag("account", "alice");
    tagged_message.push_tag("+draft/reply", "abc123");

    let mut buffer = Vec::with_capacity(512);
    cases.push(Case {
        name: "serialise/untagged",
        note: "reuses one buffer, so this is the encode cost without allocation",
        sample: measure(iterations, rounds, || {
            buffer.clear();
            untagged.write_to(&mut buffer);
            buffer.len() as u64
        }),
    });

    let mut tagged_buffer = Vec::with_capacity(512);
    cases.push(Case {
        name: "serialise/tagged",
        note: "three tags including one client tag; same reused-buffer method",
        sample: measure(iterations, rounds, || {
            tagged_buffer.clear();
            tagged_message.write_to(&mut tagged_buffer);
            tagged_buffer.len() as u64
        }),
    });

    cases.push(Case {
        name: "casemap/fold",
        note: "RFC 1459 fold of a 24-byte nickname into a fresh String",
        sample: measure(iterations, rounds, || {
            ircd::casemap::CaseMapping::Rfc1459
                .fold("Alice[test]~nickname")
                .len() as u64
        }),
    });

    cases.push(Case {
        name: "casemap/eq",
        note: "case-insensitive comparison with no allocation",
        sample: measure(iterations, rounds, || {
            u64::from(ircd::casemap::CaseMapping::Rfc1459.eq("Alice[test]", "alice{test}"))
        }),
    });

    cases.push(Case {
        name: "wildcard/hostmask",
        note: "`*!*@*.example.org` against a matching mask",
        sample: measure(iterations, rounds, || {
            u64::from(wildcard_match(
                "*!*@*.example.org",
                "alice!user@host.example.org",
            ))
        }),
    });

    cases.push(Case {
        name: "wildcard/miss",
        note: "the same mask against a non-matching host, so the scan runs to the end",
        sample: measure(iterations, rounds, || {
            u64::from(wildcard_match(
                "*!*@*.example.org",
                "alice!user@host.example.net",
            ))
        }),
    });

    cases.push(Case {
        name: "ban/match_16th",
        note: "16 entries, match on the last one; the derived masks are built once",
        sample: {
            let entries: Vec<BanEntry> = (0..16)
                .map(|index| BanEntry {
                    mask: format!("*!*@{index}.example.org"),
                    set_by: "oper".to_owned(),
                    set_at: 0,
                })
                .collect();
            let full = "alice!user@host.example.org";
            let user_host = "user@host.example.org";
            measure(iterations, rounds, || {
                let hit = entries
                    .iter()
                    .any(|entry| entry.matches_mask("alice", full, user_host, Some("alice")));
                // The 16th entry is the only match, so a hit proves the whole
                // list was walked rather than the first entry short-circuiting.
                hit as u64
            })
        },
    });

    cases.push(Case {
        name: "dispatch/hit",
        note: "command table lookup for an existing verb",
        sample: measure(iterations, rounds, || {
            commands::lookup("PRIVMSG").map_or(0, |spec| spec.min_params as u64)
        }),
    });

    cases.push(Case {
        name: "dispatch/miss",
        note: "lookup of a verb that does not exist",
        sample: measure(iterations, rounds, || {
            u64::from(commands::lookup("NOSUCHCOMMAND").is_some())
        }),
    });

    cases.push(Case {
        name: "validate/nickname",
        note: "RFC 1459 nickname validation, one pass over the bytes",
        sample: measure(iterations, rounds, || {
            u64::from(commands::valid_nickname("Alice_[test]", 30))
        }),
    });

    cases.push(Case {
        name: "format/numeric",
        note: "numeric reply rendered through Display, which allocates",
        sample: measure(iterations, rounds, || {
            format!("{}", Numeric::RPL_WELCOME).len() as u64
        }),
    });

    SpeedReport {
        cases,
        iterations,
        rounds,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measurement_is_positive_and_bounded() {
        let sample = measure(1_000, 3, || 1);
        assert!(sample.median_ns > 0.0);
        assert!(sample.min_ns <= sample.median_ns);
        assert!(sample.median_ns <= sample.max_ns);
        assert_eq!(sample.iterations, 1_000);
        assert_eq!(sample.rounds, 3);
    }

    #[test]
    fn every_case_runs() {
        let report = run(50, 2);
        assert!(report.cases.len() >= 14);
        for case in &report.cases {
            assert!(
                case.sample.median_ns > 0.0,
                "{} produced no measurable time",
                case.name
            );
            assert!(!case.note.is_empty(), "{} has no note", case.name);
        }
    }

    #[test]
    fn case_names_are_unique() {
        let report = run(20, 1);
        let mut names: Vec<&str> = report.cases.iter().map(|case| case.name).collect();
        names.sort_unstable();
        let unique = names.len();
        names.dedup();
        assert_eq!(names.len(), unique);
    }
}
