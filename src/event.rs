//! Events the collectors produce and the store keeps.

use std::net::IpAddr;

/// One request from an nginx access log.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub ts: i64,
    pub site: String,
    /// Visitor address, after resolving trusted proxies.
    pub client_ip: IpAddr,
    /// Address that connected to nginx.
    pub peer_ip: IpAddr,
    pub method: String,
    /// Path without the query string.
    pub path: String,
    /// The query string, kept only for probes.
    pub query: Option<String>,
    pub status: u16,
    pub bytes: u64,
    pub user_agent: String,
    /// Name of the probe rule that matched, if any.
    pub probe: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityKind {
    Ban,
    Unban,
    SshFail,
    SshLogin,
    FirewallBlock,
    /// A sign-in to a web app or to core-pulse itself.
    Login,
    LoginFail,
}

impl SecurityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ban => "ban",
            Self::Unban => "unban",
            Self::SshFail => "ssh_fail",
            Self::SshLogin => "ssh_login",
            Self::FirewallBlock => "fw_block",
            Self::Login => "login",
            Self::LoginFail => "login_fail",
        }
    }
}

/// A fail2ban action, a login attempt or a firewall block.
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub ts: i64,
    pub kind: SecurityKind,
    /// fail2ban jail, "sshd", "ufw", or the app that was signed in to.
    pub source: String,
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub detail: Option<String>,
}

/// Something that happened on the server itself, not from the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemEvent {
    pub ts: i64,
    pub kind: SystemKind,
    /// The unit, such as "certbot.service".
    pub name: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemKind {
    ServiceFailed,
    /// A service finished cleanly, which shows an earlier failure is fixed.
    ServiceOk,
}

impl SystemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ServiceFailed => "service_failed",
            Self::ServiceOk => "service_ok",
        }
    }
}
