#![forbid(unsafe_code)]
#![deny(
    clippy::all,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    missing_docs,
    rust_2018_idioms
)]

//! `skybouncer` CLI entrypoint and operational command suite.
//!
//! Orchestrates the live Jetstream firehose streamer, non-followed account bypass gate,
//! pluggable Jev System-1 classifier, and sovereign PDS moderation list mutator with graceful
//! shutdown, structured telemetry, and operational subcommands (`status`, `pardon`, `simulate`, `daemon`).

use std::path::Path;

use skybouncer::error::SkybouncerError;
use tokio_util::sync::CancellationToken;

/// Loads environment variables from a `.env` file if it exists on disk.
fn load_dotenv_file(path: &Path) {
    skybouncer::env::load_dotenv_file(path);
}

/// Prints general command-line usage information.
fn print_help() {
    println!(
        "🛡️ Skybouncer v{} - Sovereign Automated Moderation Service for Bluesky",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    print!("{}", skybouncer::cli::help_text());
}

#[tokio::main]
async fn main() -> Result<(), SkybouncerError> {
    // 1. Load .env file from current working directory if present
    load_dotenv_file(Path::new(".env"));

    let args: Vec<String> = std::env::args().collect();
    let subcmd = args.get(1).map(|s| s.as_str()).unwrap_or("daemon");

    if args.iter().any(|a| a == "--help" || a == "-h") || subcmd == "help" {
        print_help();
        return Ok(());
    }

    match subcmd {
        "status" => skybouncer::app::run_cli_status(&args[2..]).await,
        "pardon" => skybouncer::app::run_cli_pardon(&args[2..]).await,
        "simulate" => skybouncer::app::run_cli_simulate(&args[2..]).await,
        "daemon" => {
            let daemon_args = if args.len() > 2 {
                &args[2..]
            } else {
                &args[0..0]
            };
            skybouncer::daemon::run(daemon_args, CancellationToken::new()).await
        }
        arg if arg.starts_with("--") => {
            // Backward-compatible invocation where flags are passed directly without "daemon" keyword:
            // e.g. `skybouncer --dry-run`
            skybouncer::daemon::run(&args[1..], CancellationToken::new()).await
        }
        other => {
            eprintln!("❌ Unknown command: '{other}'");
            println!();
            print_help();
            Err(SkybouncerError::Config(format!(
                "Unknown command: '{other}'"
            )))
        }
    }
}
