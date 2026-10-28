//! Command-line entry point.

use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};

use ircd::config::Config;
use ircd::server::Server;
use ircd::util::sha256_hex;
use ircd::{daemon, logging, net};

/// IRC daemon implementing RFC 1459 and RFC 2810-2813.
#[derive(Debug, Parser)]
#[command(name = "rs-ircd", version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(
        short,
        long,
        value_name = "FILE",
        default_value = "ircd.toml",
        global = true
    )]
    config: PathBuf,

    /// Validate the configuration and exit.
    #[arg(long, global = true)]
    check: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write an example configuration file.
    Init {
        /// Destination path.
        #[arg(default_value = "ircd.toml")]
        path: PathBuf,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Print the SHA-256 hash of a password read from stdin.
    Hash,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // A missing .env is normal in production, where the service manager
    // provides the environment.
    let _ = dotenvy::dotenv();

    match &cli.command {
        Some(Command::Init { path, force }) => {
            if path.exists() && !force {
                bail!("{} already exists (use --force)", path.display());
            }
            std::fs::write(path, Config::sample())
                .with_context(|| format!("cannot write {}", path.display()))?;
            println!("wrote {}", path.display());
            Ok(())
        }
        Some(Command::Hash) => {
            let mut password = String::new();
            std::io::stdin()
                .read_to_string(&mut password)
                .context("cannot read the password from stdin")?;
            println!("{}", sha256_hex(password.trim_end().as_bytes()));
            Ok(())
        }
        None => run(cli),
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let config = Config::load(&cli.config)
        .with_context(|| format!("cannot load {}", cli.config.display()))?;
    if cli.check {
        println!("{}: configuration OK", cli.config.display());
        return Ok(());
    }

    // Daemonising must happen before the runtime starts: fork in a
    // multithreaded process is undefined behaviour.
    daemon::daemonize(&config.daemon).context("cannot daemonise")?;

    let logging = Arc::new(logging::init(&config.logging).context("cannot start logging")?);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ircd-worker")
        .build()
        .context("cannot start the Tokio runtime")?;

    runtime.block_on(async move {
        let server = Server::new(Arc::new(config), Some(cli.config))
            .context("cannot initialise server state")?;
        server.attach_logging(Arc::clone(&logging));
        net::run(server, logging).await.context("server failed")
    })
}
