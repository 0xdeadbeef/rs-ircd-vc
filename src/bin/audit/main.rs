//! Audit harness: marker register, speed measurements and security checks.
//!
//! Run `cargo run --release --bin audit -- report` to regenerate `reports/`.
//! The binary reads the source tree, measures the library in-process and writes
//! Markdown plus a JSON bundle. It never starts the daemon, opens a socket or
//! reads a configuration file, so it is safe to run in CI.

mod inventory;
mod markers;
mod report;
mod security;
mod speed;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::inventory::SourceInventory;
use crate::markers::Markers;
use crate::speed::SpeedReport;

/// Default soak iterations: enough to cover the generator's grammar without
/// making a report run feel slow.
const DEFAULT_SOAK: u64 = 50_000;

/// Default operations per timed round.
const DEFAULT_ITERATIONS: u64 = 20_000;

/// Default timed rounds per case.
const DEFAULT_ROUNDS: usize = 7;

/// Seed for the soak generator.
const DEFAULT_SEED: u64 = 0x5eed_cafe;

#[derive(Debug, Parser)]
#[command(
    name = "audit",
    about = "Generate speed and security reports for rs-ircd",
    long_about = None
)]
struct Cli {
    /// Repository root; defaults to the build's manifest directory.
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    /// Emit JSON instead of a text summary.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List and validate `MARK:` annotations.
    Markers {
        /// Exit non-zero when a marker is malformed or duplicated.
        #[arg(long)]
        check: bool,
    },
    /// Measure the hot paths on this machine.
    Speed {
        /// Operations timed per round.
        #[arg(long, default_value_t = DEFAULT_ITERATIONS)]
        iterations: u64,
        /// Rounds timed per case.
        #[arg(long, default_value_t = DEFAULT_ROUNDS)]
        rounds: usize,
    },
    /// Run the executable security checks and the parser soak.
    Security {
        /// Lines fed to the parser.
        #[arg(long, default_value_t = DEFAULT_SOAK)]
        soak: u64,
        /// Seed for the generator, so failures are reproducible.
        #[arg(long, default_value_t = DEFAULT_SEED)]
        seed: u64,
    },
    /// Generate the reports directory from one run.
    Report {
        /// Directory to write into.
        #[arg(long, default_value = "reports")]
        out: PathBuf,
        /// Operations timed per round.
        #[arg(long, default_value_t = DEFAULT_ITERATIONS)]
        iterations: u64,
        /// Rounds timed per case.
        #[arg(long, default_value_t = DEFAULT_ROUNDS)]
        rounds: usize,
        /// Lines fed to the parser.
        #[arg(long, default_value_t = DEFAULT_SOAK)]
        soak: u64,
        /// Seed for the generator.
        #[arg(long, default_value_t = DEFAULT_SEED)]
        seed: u64,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("audit: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let root = cli
        .root
        .clone()
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")));

    match cli.command {
        Command::Markers { check } => markers_command(&root, cli.json, check),
        Command::Speed { iterations, rounds } => speed_command(&root, cli.json, iterations, rounds),
        Command::Security { soak, seed } => security_command(&root, cli.json, soak, seed),
        Command::Report {
            out,
            iterations,
            rounds,
            soak,
            seed,
        } => report_command(&root, &out, iterations, rounds, soak, seed),
    }
}

fn markers_command(root: &Path, json: bool, check: bool) -> Result<ExitCode> {
    let found = Markers::scan(root);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "markers": found.markers,
                "problems": found.problems,
            }))?
        );
    } else {
        for marker in &found.markers {
            println!(
                "{:<8} {:<8} {:<16} {}:{}",
                marker.severity, marker.category, marker.id, marker.file, marker.line
            );
            println!("         {}", marker.text);
        }
        println!(
            "\n{} markers, {} problems",
            found.markers.len(),
            found.problems.len()
        );
        for problem in &found.problems {
            println!("problem: {problem}");
        }
    }
    Ok(if check && !found.problems.is_empty() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn speed_command(root: &Path, json: bool, iterations: u64, rounds: usize) -> Result<ExitCode> {
    let env = report::environment();
    let measured = speed::run(iterations, rounds);
    write_speed(&env, &Markers::scan(root), &measured, json)?;
    for case in &measured.cases {
        println!(
            "{:<24} {:>10}  min {:>10}  cv {:>5.1}%",
            case.name,
            report::duration(case.sample.median_ns),
            report::duration(case.sample.min_ns),
            case.sample.cv_pct
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn security_command(root: &Path, json: bool, soak: u64, seed: u64) -> Result<ExitCode> {
    let env = report::environment();
    let checked = security::run(soak, seed);
    for check in &checked.checks {
        println!(
            "{:<6} {:<8} {} - {}",
            check.id,
            if check.passed { "pass" } else { "FAIL" },
            check.name,
            check.detail
        );
    }
    println!(
        "soak: {} lines, {} accepted, {} rejected, {} invariant failures",
        checked.soak.iterations,
        checked.soak.accepted,
        checked.soak.rejected,
        checked.soak.failure_count
    );
    let markers = Markers::scan(root);
    let inventory = SourceInventory::scan(root);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "environment": env,
                "security": checked,
                "markers": markers.markers,
                "inventory": inventory,
            }))?
        );
    }
    Ok(if checked.failed() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn report_command(
    root: &Path,
    out: &Path,
    iterations: u64,
    rounds: usize,
    soak: u64,
    seed: u64,
) -> Result<ExitCode> {
    let env = report::environment();
    let markers = Markers::scan(root);
    let inventory = SourceInventory::scan(root);
    let checked = security::run(soak, seed);
    let measured = speed::run(iterations, rounds);

    std::fs::create_dir_all(out).with_context(|| format!("cannot create {}", out.display()))?;
    let files = [
        (
            "AUDIT.md",
            report::index(&env, &markers, &inventory, &checked, &measured),
        ),
        (
            "SECURITY.md",
            report::security(&env, &markers, &inventory, &checked),
        ),
        ("SPEED.md", report::speed(&env, &markers, &measured)),
    ];
    for (name, contents) in files {
        let path = out.join(name);
        std::fs::write(&path, contents)
            .with_context(|| format!("cannot write {}", path.display()))?;
        println!("wrote {}", path.display());
    }

    let bundle = serde_json::json!({
        "environment": env,
        "markers": markers.markers,
        "problems": markers.problems,
        "inventory": inventory,
        "security": checked,
        "speed": measured,
    });
    let path = out.join("audit.json");
    std::fs::write(&path, serde_json::to_string_pretty(&bundle)?)
        .with_context(|| format!("cannot write {}", path.display()))?;
    println!("wrote {}", path.display());

    println!(
        "\n{} markers ({} problems), {} checks ({} failed), soak {} lines ({} failures)",
        markers.markers.len(),
        markers.problems.len(),
        checked.checks.len(),
        checked.checks.iter().filter(|check| !check.passed).count(),
        checked.soak.iterations,
        checked.soak.failure_count
    );

    Ok(if markers.problems.is_empty() && checked.failed() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Print the speed report as JSON, or defer to the caller's table.
fn write_speed(
    env: &report::Environment,
    markers: &Markers,
    measured: &SpeedReport,
    json: bool,
) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "environment": env,
                "speed": measured,
                "markers": markers.markers,
            }))?
        );
    }
    Ok(())
}
