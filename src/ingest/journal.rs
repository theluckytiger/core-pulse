//! Follows the systemd journal with `journalctl --follow --output=json`.
//!
//! The cursor of the last entry read is saved with each batch, so after a
//! restart reading continues right after it. journald caps message size
//! (LineMax), which keeps every line bounded.

use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

use crate::event::{SecurityEvent, SystemEvent};
use crate::store::{Batch, SourceState};

use super::Message;

const BATCH_SIZE: usize = 500;
const FLUSH_EVERY: Duration = Duration::from_secs(1);
const RETRY_AFTER: Duration = Duration::from_secs(30);

pub struct JournalSource {
    pub name: String,
    /// journalctl filter arguments, like ["-u", "ssh.service"].
    pub filter: Vec<String>,
    pub parse: Parse,
}

/// Turns a journal message into the kind of event the source produces.
pub enum Parse {
    Security(fn(&str, i64) -> Option<SecurityEvent>),
    System(fn(&str, i64) -> Option<SystemEvent>),
}

#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "__CURSOR")]
    cursor: String,
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    realtime_us: String,
    /// A string, or an array of bytes when the message is not valid UTF-8.
    #[serde(rename = "MESSAGE", default)]
    message: serde_json::Value,
}

/// journalctl shows nothing, without an error, when it may not read the
/// system journal. Check up front and say what is missing.
pub fn warn_if_unreadable() {
    let readable = ["/var/log/journal", "/run/log/journal"]
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .flatten()
        .filter_map(|machine| std::fs::read_dir(machine.path()).ok())
        .flatten()
        .flatten()
        .any(|file| {
            file.file_name().to_string_lossy().starts_with("system")
                && std::fs::File::open(file.path()).is_ok()
        });
    if !readable {
        tracing::warn!(
            "cannot read the system journal, so SSH and firewall events will be missing; \
             add this user to the systemd-journal or adm group"
        );
    }
}

/// Reads until `stop` turns true. `cursor` is where the last run stopped;
/// without one, reading starts at `since` (unix seconds).
pub async fn follow(
    source: JournalSource,
    mut cursor: Option<String>,
    since: i64,
    tx: mpsc::Sender<Message>,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let result = tokio::select! {
            r = read(&source, &mut cursor, since, &tx) => r,
            _ = stop.changed() => return,
        };
        match result {
            Ok(()) => tracing::warn!("{}: journalctl exited, restarting", source.name),
            Err(e) => tracing::warn!("{}: {e:#}", source.name),
        }
        tokio::select! {
            _ = tokio::time::sleep(RETRY_AFTER) => {}
            _ = stop.changed() => return,
        }
    }
}

/// Catches up on the history first and only then follows new entries:
/// `journalctl --follow` skips part of older history on some systemd
/// versions (seen on 252), while a plain read returns all of it.
async fn read(
    source: &JournalSource,
    cursor: &mut Option<String>,
    since: i64,
    tx: &mpsc::Sender<Message>,
) -> anyhow::Result<()> {
    stream(source, cursor, since, false, tx).await?;
    stream(source, cursor, since, true, tx).await
}

async fn stream(
    source: &JournalSource,
    cursor: &mut Option<String>,
    since: i64,
    follow: bool,
    tx: &mpsc::Sender<Message>,
) -> anyhow::Result<()> {
    let mut command = Command::new("journalctl");
    command.args(["--output=json", "--output-fields=MESSAGE", "--no-pager"]);
    if follow {
        command.arg("--follow");
    }
    match cursor {
        Some(c) => command.arg(format!("--after-cursor={c}")),
        None => command.arg(format!("--since=@{since}")),
    };
    command
        .args(&source.filter)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stderr"))?;

    // journalctl explains missing permissions on stderr; surface that.
    let name = source.name.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::warn!("{name}: journalctl: {line}");
        }
    });

    let mut lines = BufReader::new(stdout).lines();
    let mut security = Vec::new();
    let mut system = Vec::new();
    let mut unsaved = 0;
    let mut ended = false;
    while !ended {
        match timeout(FLUSH_EVERY, lines.next_line()).await {
            Ok(Ok(Some(line))) => {
                if let Ok(entry) = serde_json::from_str::<Entry>(&line) {
                    if let (Some(message), Ok(us)) =
                        (entry.message.as_str(), entry.realtime_us.parse::<i64>())
                    {
                        let ts = us / 1_000_000;
                        match source.parse {
                            Parse::Security(parse) => security.extend(parse(message, ts)),
                            Parse::System(parse) => system.extend(parse(message, ts)),
                        }
                    }
                    *cursor = Some(entry.cursor);
                    unsaved += 1;
                }
                // Save in batches, and now and then while skipping unrelated entries.
                if security.len() + system.len() < BATCH_SIZE && unsaved < 10 * BATCH_SIZE {
                    continue;
                }
            }
            // End of output: save what is left, then stop.
            Ok(Ok(None)) => ended = true,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {} // quiet for a second: save what we have
        }
        if unsaved > 0 {
            let batch = Batch {
                source: source.name.clone(),
                security: std::mem::take(&mut security),
                system: std::mem::take(&mut system),
                state: Some(SourceState {
                    cursor: cursor.clone(),
                    ..SourceState::default()
                }),
                ..Batch::default()
            };
            if tx.send(Message::Save(batch)).await.is_err() {
                return Ok(());
            }
            unsaved = 0;
        }
    }
    child.wait().await?;
    Ok(())
}
