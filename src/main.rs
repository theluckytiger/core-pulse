mod auth;
mod cli;
mod clock;
mod config;
mod demo;
mod device;
mod event;
mod geoip;
mod health;
mod ingest;
mod net;
mod probes;
mod store;
mod web;

use std::io::IsTerminal;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    init_logging();
    cli::run(cli::Cli::parse()).await
}

/// Logs go to stderr. Under systemd the journal adds its own timestamps.
fn init_logging() {
    let filter =
        EnvFilter::try_from_env("CORE_PULSE_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let logger = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(std::io::stderr().is_terminal())
        .with_writer(std::io::stderr);

    if std::env::var_os("JOURNAL_STREAM").is_some() {
        logger.without_time().init();
    } else {
        logger.init();
    }
}
