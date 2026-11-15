//! Country of an IP address, from a country database in MaxMind format such
//! as the free DB-IP Lite one. The file is picked up again when it changes,
//! so a monthly update needs no restart.

use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use chrono::{Datelike, Months, NaiveDate, Utc};
use flate2::read::GzDecoder;
use maxminddb::{Reader, geoip2};

const RECHECK: Duration = Duration::from_secs(600);
/// The country file is about 8 MB; anything far bigger is not one.
const MAX_SIZE: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Country {
    pub code: String,
    pub name: String,
}

pub struct GeoIp {
    /// None in demo mode, where every address is a documentation one and
    /// countries are made up.
    path: Option<PathBuf>,
    state: RwLock<Loaded>,
}

#[derive(Default)]
struct Loaded {
    reader: Option<Reader<Vec<u8>>>,
    modified: Option<SystemTime>,
    checked: Option<Instant>,
}

impl GeoIp {
    pub fn open(path: &Path) -> Self {
        let geo = Self {
            path: Some(path.to_path_buf()),
            state: RwLock::default(),
        };
        geo.refresh();
        geo
    }

    pub fn demo() -> Self {
        Self {
            path: None,
            state: RwLock::default(),
        }
    }

    /// True when lookups can return anything, for showing the data credit.
    pub fn available(&self) -> bool {
        self.refresh();
        self.path.is_none() || self.state.read().is_ok_and(|s| s.reader.is_some())
    }

    pub fn country(&self, ip: IpAddr) -> Option<Country> {
        if self.path.is_none() {
            return Some(demo_country(ip));
        }
        self.refresh();
        let state = self.state.read().ok()?;
        let record = state
            .reader
            .as_ref()?
            .lookup(ip)
            .ok()?
            .decode::<geoip2::Country>()
            .ok()??;
        let code = record.country.iso_code?;
        Some(Country {
            code: code.to_string(),
            name: record.country.names.english.unwrap_or(code).to_string(),
        })
    }

    /// Loads the file again when it changed, checking at most every few minutes.
    fn refresh(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let due = |s: &Loaded| s.checked.is_none_or(|t| t.elapsed() >= RECHECK);
        if !self.state.read().is_ok_and(|s| due(&s)) {
            return;
        }
        let Ok(mut state) = self.state.write() else {
            return;
        };
        if !due(&state) {
            return;
        }
        state.checked = Some(Instant::now());
        let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        if modified.is_none() {
            state.reader = None;
            return;
        }
        if modified == state.modified && state.reader.is_some() {
            return;
        }
        match Reader::open_readfile(path) {
            Ok(reader) => {
                tracing::info!("loaded country database {}", path.display());
                state.reader = Some(reader);
                state.modified = modified;
            }
            Err(e) => tracing::warn!("cannot read country database {}: {e}", path.display()),
        }
    }
}

fn demo_country(ip: IpAddr) -> Country {
    const COUNTRIES: [(&str, &str); 6] = [
        ("DE", "Germany"),
        ("US", "United States"),
        ("NL", "Netherlands"),
        ("CN", "China"),
        ("FR", "France"),
        ("BR", "Brazil"),
    ];
    let last = match ip {
        IpAddr::V4(v4) => v4.octets()[3] as usize,
        IpAddr::V6(v6) => v6.segments()[7] as usize,
    };
    let (code, name) = COUNTRIES[last % COUNTRIES.len()];
    Country {
        code: code.into(),
        name: name.into(),
    }
}

/// Downloads the free DB-IP country database and swaps it in. Early in a
/// month the new file may not be out yet, so last month's is tried next.
pub fn update(path: &Path) -> Result<()> {
    let today = Utc::now().date_naive();
    let last_month = today.checked_sub_months(Months::new(1)).unwrap_or(today);
    let mut failure = None;
    for month in [today, last_month] {
        let url = download_url(month);
        match fetch(&url) {
            Ok(data) => {
                install(path, &data)?;
                println!("updated {} from {url}", path.display());
                return Ok(());
            }
            Err(e) => failure = Some(e.context(url)),
        }
    }
    Err(failure.unwrap_or_else(|| anyhow::anyhow!("nothing to download")))
}

pub fn download_url(month: NaiveDate) -> String {
    format!(
        "https://download.db-ip.com/free/dbip-country-lite-{}-{:02}.mmdb.gz",
        month.year(),
        month.month()
    )
}

/// curl does the HTTPS part, so core-pulse carries no TLS code of its own.
fn fetch(url: &str) -> Result<Vec<u8>> {
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--max-time",
            "300",
            url,
        ])
        .output()
        .context("cannot run curl")?;
    if !output.status.success() {
        bail!(
            "download failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut data = Vec::new();
    GzDecoder::new(output.stdout.as_slice())
        .take(MAX_SIZE)
        .read_to_end(&mut data)
        .context("the download is not a gzip file")?;
    Ok(data)
}

/// Checks the file opens before it replaces the old one, then swaps it in
/// with a rename, so readers never see half a file.
fn install(path: &Path, data: &[u8]) -> Result<()> {
    Reader::from_source(data).context("the download is not a country database")?;
    let partial = path.with_extension("mmdb.part");
    std::fs::write(&partial, data)
        .with_context(|| format!("cannot write {}", partial.display()))?;
    std::fs::rename(&partial, path).with_context(|| format!("cannot replace {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_monthly_url() {
        let month = NaiveDate::from_ymd_opt(2026, 3, 1).unwrap();
        assert_eq!(
            download_url(month),
            "https://download.db-ip.com/free/dbip-country-lite-2026-03.mmdb.gz"
        );
    }

    #[test]
    fn missing_database_means_no_countries() {
        let geo = GeoIp::open(Path::new("/nonexistent/country.mmdb"));
        assert!(!geo.available());
        assert_eq!(geo.country("192.0.2.1".parse().unwrap()), None);
    }

    #[test]
    fn refuses_to_install_a_broken_download() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("country.mmdb");
        assert!(install(&path, b"not a database").is_err());
        assert!(!path.exists());
    }
}
