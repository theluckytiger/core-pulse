//! Works out the visitor address when nginx sits behind trusted proxies.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::config::{ClientIpHeader, RealIpConfig};

pub struct RealIp {
    trusted: Vec<IpNet>,
    header: ClientIpHeader,
}

impl RealIp {
    pub fn new(config: &RealIpConfig) -> Self {
        Self {
            trusted: config.trusted_proxies.clone(),
            header: config.header,
        }
    }

    /// The nginx variable (without `$`) that holds the visitor address, if
    /// any proxies are trusted.
    pub fn variable(&self) -> Option<&'static str> {
        (!self.trusted.is_empty()).then(|| &self.header.nginx_variable()[1..])
    }

    /// `peer` connected to nginx; `header` is the logged header value.
    /// The header is only believed when the peer is a trusted proxy.
    pub fn resolve(&self, peer: IpAddr, header: Option<&str>) -> IpAddr {
        if !self.is_trusted(peer) {
            return peer;
        }
        let Some(value) = header.filter(|v| !v.is_empty() && *v != "-") else {
            return peer;
        };
        match self.header {
            // Every proxy appends the address it saw, and earlier entries can
            // be faked by the client. Walk from the right and stop at the
            // first address that is not one of our proxies.
            ClientIpHeader::XForwardedFor => {
                for part in value.rsplit(',') {
                    match part.trim().parse::<IpAddr>() {
                        Ok(ip) if self.is_trusted(ip) => continue,
                        Ok(ip) => return ip,
                        Err(_) => return peer,
                    }
                }
                peer
            }
            ClientIpHeader::XRealIp | ClientIpHeader::CfConnectingIp => {
                value.trim().parse().unwrap_or(peer)
            }
        }
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROXY: &str = "198.51.100.10";

    fn real_ip(header: ClientIpHeader) -> RealIp {
        RealIp::new(&RealIpConfig {
            trusted_proxies: vec!["198.51.100.0/24".parse().unwrap()],
            header,
        })
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ignores_the_header_from_untrusted_peers() {
        let r = real_ip(ClientIpHeader::XForwardedFor);
        assert_eq!(
            r.resolve(ip("203.0.113.5"), Some("192.0.2.1")),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn takes_the_client_from_a_trusted_proxy() {
        let r = real_ip(ClientIpHeader::XForwardedFor);
        assert_eq!(r.resolve(ip(PROXY), Some("192.0.2.1")), ip("192.0.2.1"));
        assert_eq!(r.resolve(ip(PROXY), Some("2001:db8::7")), ip("2001:db8::7"));
    }

    #[test]
    fn a_faked_header_entry_does_not_win() {
        // The client sent "192.0.2.66"; the proxy appended the real address.
        let r = real_ip(ClientIpHeader::XForwardedFor);
        assert_eq!(
            r.resolve(ip(PROXY), Some("192.0.2.66, 203.0.113.5")),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn skips_our_own_proxies_in_the_chain() {
        let r = real_ip(ClientIpHeader::XForwardedFor);
        assert_eq!(
            r.resolve(ip(PROXY), Some("203.0.113.5, 198.51.100.20")),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn falls_back_to_the_peer_on_bad_values() {
        let r = real_ip(ClientIpHeader::XForwardedFor);
        assert_eq!(r.resolve(ip(PROXY), Some("-")), ip(PROXY));
        assert_eq!(r.resolve(ip(PROXY), Some("unknown")), ip(PROXY));
        assert_eq!(r.resolve(ip(PROXY), None), ip(PROXY));
    }

    #[test]
    fn single_value_headers() {
        let r = real_ip(ClientIpHeader::CfConnectingIp);
        assert_eq!(r.resolve(ip(PROXY), Some("192.0.2.9")), ip("192.0.2.9"));
        assert_eq!(r.variable(), Some("http_cf_connecting_ip"));
    }
}
