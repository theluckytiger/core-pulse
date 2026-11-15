//! Config file: loading, defaults and validation.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use serde::Deserialize;

use crate::ingest::nginx::NginxParser;
use crate::probes::{ProbeMatcher, ProbeRule, default_rules};

/// nginx's built-in "combined" log format.
pub const COMBINED_FORMAT: &str = r#"$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent""#;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub real_ip: RealIpConfig,
    #[serde(default)]
    pub nginx: Vec<NginxSource>,
    pub fail2ban: Option<Fail2banSource>,
    pub ssh: Option<LogSource>,
    pub ufw: Option<LogSource>,
    /// Failed services, read from the journal. An empty [systemd] table turns it on.
    pub systemd: Option<SystemdConfig>,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub geoip: GeoIpConfig,
    /// Names for SSH key fingerprints, so logins say "laptop" instead of "SHA256:...".
    #[serde(default)]
    pub ssh_keys: BTreeMap<String, String>,
    #[serde(default = "default_rules")]
    pub probes: Vec<ProbeRule>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemdConfig {}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeoIpConfig {
    /// A country database in MaxMind format, such as the free DB-IP Lite one.
    /// Countries are shown only when the file exists.
    pub database: PathBuf,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            database: PathBuf::from("/var/lib/core-pulse/dbip-country-lite.mmdb"),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    /// Sample interface counters and TCP connections from /proc.
    pub enabled: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: Vec<SocketAddr>,
    /// URL prefix when served under a sub-path, like "/core-pulse". Empty for "/".
    pub base_path: String,
    /// The reverse proxy in front of core-pulse. Its X-Real-IP header gives
    /// the visitor address used for login limits and logs.
    pub trusted_proxies: Vec<IpNet>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub database: PathBuf,
    pub raw_retention_days: u32,
    pub hourly_retention_days: u32,
    pub max_db_size_mb: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RealIpConfig {
    /// Proxies in front of nginx (a CDN, a load balancer). Requests from them
    /// carry the visitor address in `header`.
    pub trusted_proxies: Vec<IpNet>,
    pub header: ClientIpHeader,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientIpHeader {
    #[default]
    XForwardedFor,
    XRealIp,
    CfConnectingIp,
}

impl ClientIpHeader {
    /// The nginx variable that logs this header.
    pub fn nginx_variable(self) -> &'static str {
        match self {
            Self::XForwardedFor => "$http_x_forwarded_for",
            Self::XRealIp => "$http_x_real_ip",
            Self::CfConnectingIp => "$http_cf_connecting_ip",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NginxSource {
    pub name: String,
    pub path: PathBuf,
    /// The `log_format` string from nginx.conf.
    #[serde(default = "combined_format")]
    pub format: String,
    /// Formats used before the current one, for older lines still in the file.
    #[serde(default)]
    pub previous_formats: Vec<String>,
    /// Site name to record when the format has no $host.
    pub site: Option<String>,
    /// Login forms of the apps behind this nginx, found by their POST.
    #[serde(default)]
    pub logins: Vec<LoginForm>,
}

/// A web app's login form. A POST to `path` is a sign-in: one of the
/// `success` codes means it worked. It failed on one of the `failure` codes,
/// or, when that is not set, on any other 2xx-4xx answer.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginForm {
    /// Shown on the dashboard, like "Shop admin".
    pub name: String,
    /// Where the form posts to, without the query string.
    pub path: String,
    #[serde(default = "default_login_success")]
    pub success: Vec<u16>,
    /// False for customers' logins: they are counted, but not listed, and a
    /// new device or country is not flagged.
    #[serde(default = "default_staff")]
    pub staff: bool,
    /// Set this when a form answers other things with the same codes, like a
    /// two-step login that shows the code form with 200. Empty: count only
    /// successes.
    pub failure: Option<Vec<u16>>,
}

fn default_login_success() -> Vec<u16> {
    vec![302, 303]
}

fn default_staff() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fail2banSource {
    #[serde(default = "default_fail2ban_log")]
    pub log: PathBuf,
}

/// Where SSH or firewall messages come from.
#[derive(Debug, Deserialize)]
#[serde(tag = "from", rename_all = "lowercase")]
pub enum LogSource {
    /// The systemd journal. Without a unit, kernel messages are read (UFW).
    Journal { unit: Option<String> },
    /// A plain log file such as /var/log/auth.log.
    File { path: PathBuf },
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            real_ip: RealIpConfig::default(),
            nginx: Vec::new(),
            fail2ban: None,
            ssh: None,
            ufw: None,
            systemd: None,
            network: NetworkConfig::default(),
            geoip: GeoIpConfig::default(),
            ssh_keys: BTreeMap::new(),
            probes: default_rules(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: vec![SocketAddr::from(([127, 0, 0, 1], 8790))],
            base_path: String::new(),
            trusted_proxies: Vec::new(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database: PathBuf::from("/var/lib/core-pulse/core-pulse.db"),
            raw_retention_days: 90,
            hourly_retention_days: 365,
            max_db_size_mb: 1024,
        }
    }
}

fn combined_format() -> String {
    COMBINED_FORMAT.to_string()
}

fn default_fail2ban_log() -> PathBuf {
    PathBuf::from("/var/log/fail2ban.log")
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        let mut config: Config =
            toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))?;
        config
            .validate()
            .with_context(|| format!("invalid config {}", path.display()))?;
        Ok(config)
    }

    /// Short names of the enabled sources, for status output.
    pub fn source_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .nginx
            .iter()
            .map(|s| format!("nginx:{}", s.name))
            .collect();
        if self.fail2ban.is_some() {
            names.push("fail2ban".into());
        }
        if let Some(source) = &self.ssh {
            names.push(format!("ssh ({})", source.describe()));
        }
        if let Some(source) = &self.ufw {
            names.push(format!("ufw ({})", source.describe()));
        }
        if self.systemd.is_some() {
            names.push("systemd".into());
        }
        if self.network.enabled {
            names.push("network".into());
        }
        names
    }

    fn validate(&mut self) -> Result<()> {
        self.server.validate()?;
        self.storage.validate()?;
        self.validate_sources()?;
        ProbeMatcher::new(&self.probes)?;
        Ok(())
    }

    fn validate_sources(&self) -> Result<()> {
        let mut names = HashSet::new();
        for source in &self.nginx {
            let name = &source.name;
            ensure!(
                !name.trim().is_empty(),
                "every [[nginx]] source needs a name"
            );
            ensure!(
                names.insert(name.as_str()),
                "duplicate nginx source '{name}'"
            );
            ensure!(
                source.path.is_absolute(),
                "nginx '{name}': path must be absolute"
            );
            // Building the parser checks every format and the variables it needs.
            NginxParser::new(source, &self.real_ip)?;
            if let Some(site) = &source.site {
                ensure!(
                    !site.trim().is_empty(),
                    "nginx '{name}': site must not be empty"
                );
            }
            for form in &source.logins {
                ensure!(
                    !form.name.trim().is_empty() && form.path.starts_with('/'),
                    "nginx '{name}': every login needs a name and a path starting with /"
                );
            }
        }

        if let Some(fail2ban) = &self.fail2ban {
            ensure!(
                fail2ban.log.is_absolute(),
                "fail2ban.log must be an absolute path"
            );
        }
        for (section, source) in [("ssh", &self.ssh), ("ufw", &self.ufw)] {
            match source {
                Some(LogSource::Journal { unit: Some(unit) }) => {
                    ensure!(!unit.trim().is_empty(), "{section}.unit must not be empty");
                }
                Some(LogSource::File { path }) => {
                    ensure!(
                        path.is_absolute(),
                        "{section}.path must be an absolute path"
                    );
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl ServerConfig {
    fn validate(&mut self) -> Result<()> {
        ensure!(
            !self.listen.is_empty(),
            "server.listen needs at least one address"
        );
        for addr in &self.listen {
            ensure!(
                is_local(addr.ip()),
                "server.listen: {addr} is not a loopback or private address. \
                 Keep core-pulse off the public network and put nginx in front."
            );
        }
        self.base_path = normalize_base_path(&self.base_path)?;
        Ok(())
    }
}

impl StorageConfig {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.database.is_absolute(),
            "storage.database must be an absolute path"
        );
        ensure!(
            (1..=3650).contains(&self.raw_retention_days),
            "storage.raw_retention_days must be between 1 and 3650"
        );
        ensure!(
            self.hourly_retention_days >= self.raw_retention_days,
            "storage.hourly_retention_days must be at least raw_retention_days"
        );
        ensure!(
            self.max_db_size_mb >= 16,
            "storage.max_db_size_mb must be at least 16"
        );
        Ok(())
    }
}

impl LogSource {
    fn describe(&self) -> String {
        match self {
            Self::Journal { unit: Some(unit) } => format!("journal, unit {unit}"),
            Self::Journal { unit: None } => "journal, kernel".to_string(),
            Self::File { path } => format!("file {}", path.display()),
        }
    }
}

fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        // fc00::/7 is the IPv6 private (unique local) range.
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// "/core-pulse/" becomes "/core-pulse", "/" becomes "".
fn normalize_base_path(raw: &str) -> Result<String> {
    let path = raw.trim_end_matches('/');
    if path.is_empty() {
        return Ok(String::new());
    }
    let allowed = |c: char| c.is_ascii_alphanumeric() || "/-_.".contains(c);
    ensure!(
        path.starts_with('/')
            && path.chars().all(allowed)
            && !path.contains("//")
            && !path.contains(".."),
        "server.base_path '{raw}' must look like /some-path"
    );
    Ok(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config> {
        let mut config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn example_config_is_valid() {
        let config = parse(include_str!("../config.example.toml")).unwrap();
        assert_eq!(config.nginx.len(), 1);
        assert!(config.fail2ban.is_some());
        assert!(matches!(
            config.ufw,
            Some(LogSource::Journal { unit: None })
        ));
    }

    #[test]
    fn empty_config_uses_defaults() {
        let config = parse("").unwrap();
        assert_eq!(config.server.listen[0].to_string(), "127.0.0.1:8790");
        assert_eq!(config.storage.raw_retention_days, 90);
        assert!(config.nginx.is_empty());
        assert!(!config.probes.is_empty());
    }

    #[test]
    fn rejects_public_listen_address() {
        let err = parse("[server]\nlisten = [\"0.0.0.0:8790\"]").unwrap_err();
        assert!(err.to_string().contains("not a loopback or private"));
    }

    #[test]
    fn accepts_private_listen_addresses() {
        parse("[server]\nlisten = [\"10.0.0.1:8790\", \"[::1]:8790\"]").unwrap();
    }

    #[test]
    fn normalizes_base_path() {
        assert_eq!(normalize_base_path("/core-pulse/").unwrap(), "/core-pulse");
        assert_eq!(normalize_base_path("/").unwrap(), "");
        assert!(normalize_base_path("core-pulse").is_err());
        assert!(normalize_base_path("/a/../b").is_err());
    }

    #[test]
    fn real_ip_header_must_be_in_the_log_format() {
        let text = r#"
            [real_ip]
            trusted_proxies = ["192.0.2.0/24"]
            header = "cf-connecting-ip"

            [[nginx]]
            name = "web"
            path = "/var/log/nginx/access.log"
        "#;
        let err = parse(text).unwrap_err();
        assert!(format!("{err:#}").contains("$http_cf_connecting_ip"));
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(parse("[server]\nlisten_on = []").is_err());
    }

    #[test]
    fn rejects_bad_probe_pattern() {
        assert!(parse("[[probes]]\nname = \"x\"\npattern = \"(\"").is_err());
    }
}
