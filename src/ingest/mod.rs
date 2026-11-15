//! Log collectors and the single writer that stores what they read.
//!
//! File sources each run on their own thread and the journal sources as
//! async tasks. They all send batches to one writer thread that owns the
//! database connection.

mod fail2ban;
mod journal;
pub mod nginx;
mod realip;
mod sshd;
mod syslog;
mod systemd;
mod tail;
mod ufw;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;
use chrono::Local;
use tokio::sync::{mpsc, watch};

use crate::clock::{self, DAY};
use crate::config::{Config, LogSource};
use crate::probes::ProbeMatcher;
use crate::store::{Batch, Retention, SourceState, Store};
use crate::{auth, net};
use journal::{JournalSource, Parse};
use nginx::NginxParser;
use tail::{Position, Tailer};

pub enum Message {
    Save(Batch),
    /// Apply retention and the size cap.
    Maintain,
}

const POLL: Duration = Duration::from_secs(1);
const LINES_PER_BATCH: usize = 2000;
const MAINTAIN_EVERY: Duration = Duration::from_secs(3600);

pub struct Ingest {
    stop_readers: Arc<AtomicBool>,
    stop_tasks: watch::Sender<bool>,
    readers: Vec<JoinHandle<()>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    writer: JoinHandle<()>,
}

/// How a file source turns lines into events.
enum LineParser {
    Nginx {
        parser: Box<NginxParser>,
        probes: Arc<ProbeMatcher>,
    },
    Fail2ban,
    Sshd,
    Ufw,
}

/// Starts every configured source, and the network sampler that keeps
/// `network` up to date. Must be called inside the tokio runtime.
pub fn start(config: &Config, store: Store, network: net::Live) -> Result<Ingest> {
    let probes = Arc::new(ProbeMatcher::new(&config.probes)?);
    let (files, journals) = sources(config, &probes)?;
    let since = clock::now() - i64::from(config.storage.raw_retention_days) * DAY;

    let (tx, rx) = mpsc::channel(64);
    let (stop_tasks, stop_rx) = watch::channel(false);
    let stop_readers = Arc::new(AtomicBool::new(false));

    let mut readers = Vec::new();
    for (name, path, parser) in files {
        let resume = store.source_state(&name)?.and_then(|s| {
            Some(Position {
                file_id: s.file_id?,
                offset: s.position?,
            })
        });
        let tail = Tailer::new(path, resume);
        let (tx, stop) = (tx.clone(), stop_readers.clone());
        let thread = std::thread::Builder::new()
            .name(name.clone())
            .spawn(move || read_file(name, tail, parser, tx, stop))?;
        readers.push(thread);
    }
    if config.network.enabled {
        let (tx, stop) = (tx.clone(), stop_readers.clone());
        let thread = std::thread::Builder::new()
            .name("network".into())
            .spawn(move || net::run(network, tx, stop))?;
        readers.push(thread);
    }

    let mut tasks = Vec::new();
    if !journals.is_empty() {
        journal::warn_if_unreadable();
    }
    for source in journals {
        let cursor = store.source_state(&source.name)?.and_then(|s| s.cursor);
        tasks.push(tokio::spawn(journal::follow(
            source,
            cursor,
            since,
            tx.clone(),
            stop_rx.clone(),
        )));
    }
    tasks.push(tokio::spawn(maintain_hourly(tx, stop_rx)));

    let retention = Retention::from(&config.storage);
    let writer = std::thread::Builder::new()
        .name("writer".into())
        .spawn(move || write_loop(store, rx, retention))?;

    Ok(Ingest {
        stop_readers,
        stop_tasks,
        readers,
        tasks,
        writer,
    })
}

impl Ingest {
    /// Stops all sources and waits until everything read so far is stored.
    pub async fn shutdown(self) {
        self.stop_readers.store(true, Ordering::Relaxed);
        let _ = self.stop_tasks.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
        let (readers, writer) = (self.readers, self.writer);
        let _ = tokio::task::spawn_blocking(move || {
            for reader in readers {
                let _ = reader.join();
            }
            // The writer stops once every sender is gone and the queue is empty.
            let _ = writer.join();
        })
        .await;
    }
}

type FileSources = Vec<(String, PathBuf, LineParser)>;

fn sources(
    config: &Config,
    probes: &Arc<ProbeMatcher>,
) -> Result<(FileSources, Vec<JournalSource>)> {
    let mut files = Vec::new();
    let mut journals = Vec::new();

    for source in &config.nginx {
        let parser = Box::new(NginxParser::new(source, &config.real_ip)?);
        let probes = probes.clone();
        files.push((
            format!("nginx:{}", source.name),
            source.path.clone(),
            LineParser::Nginx { parser, probes },
        ));
    }
    if let Some(fail2ban) = &config.fail2ban {
        files.push((
            "fail2ban".into(),
            fail2ban.log.clone(),
            LineParser::Fail2ban,
        ));
    }
    match &config.ssh {
        Some(LogSource::File { path }) => {
            files.push(("ssh".into(), path.clone(), LineParser::Sshd))
        }
        Some(LogSource::Journal { unit }) => journals.push(JournalSource {
            name: "ssh".into(),
            filter: vec![
                "-u".into(),
                unit.clone().unwrap_or_else(|| "ssh.service".into()),
            ],
            parse: Parse::Security(sshd::parse),
        }),
        None => {}
    }
    match &config.ufw {
        Some(LogSource::File { path }) => files.push(("ufw".into(), path.clone(), LineParser::Ufw)),
        Some(LogSource::Journal { unit }) => journals.push(JournalSource {
            name: "ufw".into(),
            filter: match unit {
                Some(unit) => vec!["-u".into(), unit.clone()],
                None => vec!["_TRANSPORT=kernel".into()],
            },
            parse: Parse::Security(ufw::parse),
        }),
        None => {}
    }
    if config.systemd.is_some() {
        journals.push(JournalSource {
            name: "systemd".into(),
            // Messages from the service manager itself; debug chatter left out.
            filter: vec!["_PID=1".into(), "--priority=info".into()],
            parse: Parse::System(systemd::parse),
        });
    }
    Ok((files, journals))
}

impl LineParser {
    /// Adds the event for `line` to the batch. False when the line holds none.
    fn parse(&self, line: &str, now: i64, batch: &mut Batch) -> bool {
        let event = match self {
            Self::Nginx { parser, probes } => match parser.parse(line, probes) {
                Some(request) => {
                    batch.security.extend(parser.login(&request));
                    batch.http.push(request);
                    return true;
                }
                None => return false,
            },
            Self::Fail2ban => fail2ban::parse(line, &Local),
            Self::Sshd | Self::Ufw => syslog::parse(line, &Local, now).and_then(|l| match self {
                Self::Sshd if l.program.starts_with("sshd") => sshd::parse(l.message, l.ts),
                Self::Ufw if l.program == "kernel" => ufw::parse(l.message, l.ts),
                _ => None,
            }),
        };
        match event {
            Some(event) => {
                batch.security.push(event);
                true
            }
            None => false,
        }
    }
}

fn read_file(
    name: String,
    mut tail: Tailer,
    parser: LineParser,
    tx: mpsc::Sender<Message>,
    stop: Arc<AtomicBool>,
) {
    let mut failing = false;
    let mut warned_format = false;

    while !stop.load(Ordering::Relaxed) {
        let lines = match tail.read_lines(LINES_PER_BATCH) {
            Ok(lines) => {
                failing = false;
                lines
            }
            Err(e) => {
                if !failing {
                    tracing::warn!("{name}: {e}");
                    failing = true;
                }
                std::thread::sleep(POLL);
                continue;
            }
        };
        if lines.is_empty() {
            std::thread::sleep(POLL);
            continue;
        }

        let now = clock::now();
        let mut batch = Batch {
            source: name.clone(),
            ..Batch::default()
        };
        let parsed = lines
            .iter()
            .filter(|line| parser.parse(line, now, &mut batch))
            .count();
        if parsed == 0
            && lines.len() >= 10
            && matches!(parser, LineParser::Nginx { .. })
            && !warned_format
        {
            tracing::warn!("{name}: lines do not match the configured log format");
            warned_format = true;
        }
        batch.state = tail.position().map(|p| SourceState {
            file_id: Some(p.file_id),
            position: Some(p.offset),
            cursor: None,
        });
        if tx.blocking_send(Message::Save(batch)).is_err() {
            return;
        }
    }
}

async fn maintain_hourly(tx: mpsc::Sender<Message>, mut stop: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(MAINTAIN_EVERY);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if tx.send(Message::Maintain).await.is_err() {
                    return;
                }
            }
            _ = stop.changed() => return,
        }
    }
}

fn write_loop(mut store: Store, mut rx: mpsc::Receiver<Message>, retention: Retention) {
    while let Some(message) = rx.blocking_recv() {
        let now = clock::now();
        match message {
            Message::Save(batch) => {
                if let Err(e) = store.save(&batch, now, &retention) {
                    let events = batch.http.len() + batch.security.len();
                    tracing::error!("{}: could not save {events} events: {e:#}", batch.source);
                }
            }
            Message::Maintain => maintain(&mut store, now, &retention),
        }
    }
}

fn maintain(store: &mut Store, now: i64, retention: &Retention) {
    match store.enforce_retention(now, retention) {
        Ok(c) if c.expired + c.over_cap > 0 => tracing::info!(
            "retention: removed {} expired and {} over the size cap, {} MB in use",
            c.expired,
            c.over_cap,
            c.bytes / (1024 * 1024)
        ),
        Ok(_) => {}
        Err(e) => tracing::error!("retention failed: {e:#}"),
    }
    if let Err(e) = store.delete_stale_sessions(now, now - auth::IDLE_TIMEOUT) {
        tracing::error!("session cleanup failed: {e:#}");
    }
}
