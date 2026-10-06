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

/// Dispatches a full argument vector (including the program name) to the matching subcommand.
///
/// Kept in the binary but delegating to the testable [`skybouncer::app::dispatch`].
async fn dispatch(args: &[String]) -> Result<(), SkybouncerError> {
    skybouncer::app::dispatch(args, CancellationToken::new()).await
}

#[tokio::main]
async fn main() -> Result<(), SkybouncerError> {
    // 1. Load .env file from current working directory if present
    load_dotenv_file(Path::new(".env"));

    let args: Vec<String> = std::env::args().collect();
    dispatch(&args).await
}
