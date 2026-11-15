//! Command line interface.

mod user;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Result;
use chrono::{Local, TimeZone};
use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::geoip::{self, GeoIp};
use crate::probes::ProbeMatcher;
use crate::store::Store;
use crate::{clock, demo, ingest, net, web};

#[derive(Parser)]
#[command(version, about = "Self-hosted security and traffic monitor")]
pub struct Cli {
    /// Config file
    #[arg(
        short,
        long,
        global = true,
        default_value = "/etc/core-pulse/config.toml"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the collectors and the web dashboard
    Serve {
        /// Use an in-memory database with fake data instead of reading real logs
        #[arg(long)]
        demo: bool,
    },
    /// Check the config file and exit
    CheckConfig,
    /// Show what is stored and how far each source has read
    Status,
    /// Manage dashboard users
    #[command(subcommand)]
    User(user::UserCommand),
    /// Download this month's free DB-IP country database
    UpdateGeoip,
    /// Forget what was read from logs so the next start reads them again,
    /// for example after adding login forms. Stop the service first.
    Reread,
}

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve { demo: true } => serve_demo(&cli.config).await,
        Command::Serve { demo: false } => serve(&cli.config).await,
        Command::CheckConfig => check_config(&cli.config),
        Command::Status => status(&cli.config),
        Command::User(command) => {
            let config = Config::load(&cli.config)?;
            user::run(command, &mut Store::open(&config.storage.database)?)
        }
        Command::UpdateGeoip => geoip::update(&Config::load(&cli.config)?.geoip.database),
        Command::Reread => {
            let config = Config::load(&cli.config)?;
            Store::open(&config.storage.database)?.forget_collected()?;
            println!("Done. The next start reads every log again; users and sessions are kept.");
            Ok(())
        }
    }
}

async fn serve(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let ingest_store = Store::open(&config.storage.database)?;
    let web_store = Store::open(&config.storage.database)?;

    let network = net::Live::default();
    let ingest = ingest::start(&config, ingest_store, network.clone())?;
    tracing::info!("reading {}", config.source_names().join(", "));
    let geo = GeoIp::open(&config.geoip.database);
    let store = Arc::new(Mutex::new(web_store));
    let served = web::serve(&config, store, network, geo, false).await;
    ingest.shutdown().await;
    served
}

/// Demo mode runs without a config file so anyone can try it.
async fn serve_demo(config_path: &Path) -> Result<()> {
    let mut config = if config_path.exists() {
        Config::load(config_path)?
    } else {
        Config::default()
    };
    for (key, name) in [(demo::LAPTOP_KEY, "laptop"), (demo::PHONE_KEY, "phone")] {
        config
            .ssh_keys
            .entry(key.into())
            .or_insert_with(|| name.into());
    }
    let mut store = Store::open_in_memory()?;
    let probes = ProbeMatcher::new(&config.probes)?;
    demo::seed(&mut store, &probes, clock::now(), demo::DAYS)?;
    let (requests, events) = store.counts()?;
    tracing::info!(
        "demo mode: {requests} requests and {events} security events over {} days",
        demo::DAYS
    );
    let network = Arc::new(RwLock::new(net::demo_snapshot(clock::now())));
    let store = Arc::new(Mutex::new(store));
    web::serve(&config, store, network, GeoIp::demo(), true).await
}

fn check_config(path: &Path) -> Result<()> {
    let config = Config::load(path)?;
    let listen: Vec<String> = config.server.listen.iter().map(|a| a.to_string()).collect();

    println!("{} is valid", path.display());
    println!("  listen:   {}", listen.join(", "));
    println!("  database: {}", config.storage.database.display());
    println!("  sources:  {}", config.source_names().join(", "));
    Ok(())
}

fn status(path: &Path) -> Result<()> {
    let config = Config::load(path)?;
    let status = Store::open(&config.storage.database)?.status()?;
    let time = |ts: Option<i64>| {
        ts.and_then(|ts| Local.timestamp_opt(ts, 0).single())
            .map_or("-".to_string(), |t| t.format("%Y-%m-%d %H:%M").to_string())
    };

    println!(
        "database   {} ({:.1} MB)",
        config.storage.database.display(),
        status.bytes as f64 / 1_048_576.0
    );
    println!("requests   {}", status.requests);
    println!("security   {}", status.security_events);
    println!(
        "range      {} to {}",
        time(status.oldest),
        time(status.newest)
    );
    for (source, updated) in &status.sources {
        println!("source     {source}, saved {}", time(Some(*updated)));
    }
    Ok(())
}
