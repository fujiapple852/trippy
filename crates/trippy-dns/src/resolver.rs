use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use thiserror::Error;

/// A DNS resolver.
pub trait Resolver {
    /// Perform a blocking DNS hostname lookup and return the resolved IPv4 or IPv6 addresses.
    fn lookup(&self, hostname: impl AsRef<str>) -> Result<ResolvedIpAddrs>;

    /// Perform a blocking reverse DNS lookup of `IpAddr` and return a `DnsEntry`.
    ///
    /// As this method is blocking it will never return a `DnsEntry::Pending`.
    #[must_use]
    fn reverse_lookup(&self, addr: impl Into<IpAddr>) -> DnsEntry;

    /// Perform a blocking reverse DNS lookup of `IpAddr` and return a `DnsEntry` with `AS`
    /// information.
    ///
    /// See [`Resolver::reverse_lookup`]
    #[must_use]
    fn reverse_lookup_with_asinfo(&self, addr: impl Into<IpAddr>) -> DnsEntry;

    /// Perform a lazy reverse DNS lookup of `IpAddr` and return a `DnsEntry`.
    ///
    /// If the `IpAddr` has already been resolved then `DnsEntry::Resolved` is returned immediately.
    ///
    /// Otherwise, the `IpAddr` is enqueued to be resolved in the background and a
    /// `DnsEntry::Pending` is returned.
    ///
    /// If the entry exists but is `DnsEntry::Timeout` then it is changed to be `DnsEntry::Pending`
    /// and enqueued.
    ///
    /// If enqueuing times out then the entry is changed to be `DnsEntry::Timeout` and returned.
    #[must_use]
    fn lazy_reverse_lookup(&self, addr: impl Into<IpAddr>) -> DnsEntry;

    /// Perform a lazy reverse DNS lookup of `IpAddr` and return a `DnsEntry` with `AS` information.
    ///
    /// See [`Resolver::lazy_reverse_lookup`]
    #[must_use]
    fn lazy_reverse_lookup_with_asinfo(&self, addr: impl Into<IpAddr>) -> DnsEntry;
}

/// A DNS resolver error result.
pub type Result<T> = std::result::Result<T, Error>;

/// A DNS resolver error.
#[derive(Error, Debug)]
pub enum Error {
    #[error("DNS lookup failed")]
    LookupFailed(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("ASN origin query failed")]
    QueryAsnOriginFailed,
    #[error("ASN query failed")]
    QueryAsnFailed,
    #[error("origin query txt parse failed: {0}")]
    ParseOriginQueryFailed(String),
    #[error("asn query txt parse failed: {0}")]
    ParseAsnQueryFailed(String),
}

/// The output of a successful DNS lookup.
#[derive(Debug, Clone)]
pub struct ResolvedIpAddrs(pub(super) Vec<IpAddr>);

impl ResolvedIpAddrs {
    pub fn iter(&self) -> impl Iterator<Item = &'_ IpAddr> {
        self.0.iter()
    }
}

impl IntoIterator for ResolvedIpAddrs {
    type Item = IpAddr;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// The state of reverse DNS resolution.
#[derive(Debug, Clone)]
pub enum DnsEntry {
    /// The reverse DNS resolution of `IpAddr` is pending.
    Pending(IpAddr),
    /// The reverse DNS resolution of `IpAddr` has resolved.
    Resolved(Resolved),
    /// The `IpAddr` could not be resolved.
    NotFound(Unresolved),
    /// The reverse DNS resolution of `IpAddr` failed.
    Failed(IpAddr),
    /// The reverse DNS resolution of `IpAddr` timed out.
    Timeout(IpAddr),
}

/// The resolved hostnames of a `DnsEntry`.
#[derive(Debug, Clone)]
pub struct ResolvedHostnames<'a>(pub(super) std::slice::Iter<'a, String>);

impl<'a> Iterator for ResolvedHostnames<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(String::as_str)
    }
}

impl DnsEntry {
    /// The resolved hostnames.
    #[must_use]
    pub fn hostnames(&self) -> ResolvedHostnames<'_> {
        match self {
            Self::Resolved(Resolved::WithAsInfo(_, hosts, _) | Resolved::Normal(_, hosts)) => {
                ResolvedHostnames(hosts.iter())
            }
            Self::Pending(_) | Self::Timeout(_) | Self::NotFound(_) | Self::Failed(_) =>
            {
                #[expect(clippy::iter_on_empty_collections)]
                ResolvedHostnames([].iter())
            }
        }
    }
}

/// Information about a resolved `IpAddr`.
#[derive(Debug, Clone)]
pub enum Resolved {
    /// Resolved without `AsInfo`.
    Normal(IpAddr, Vec<String>),
    /// Resolved with `AsInfo`.
    WithAsInfo(IpAddr, Vec<String>, AsInfo),
}

/// Information about an unresolved `IpAddr`.
#[derive(Debug, Clone)]
pub enum Unresolved {
    /// Unresolved without `AsInfo`.
    Normal(IpAddr),
    /// Unresolved with `AsInfo`.
    WithAsInfo(IpAddr, AsInfo),
}

/// Information about an autonomous System (AS).
#[derive(Debug, Clone, Default)]
pub struct AsInfo {
    /// The autonomous system Number.
    ///
    /// This is returned without the AS prefix i.e. `12301`.
    pub asn: String,
    /// The AS prefix.
    ///
    /// Given in CIDR notation i.e. `81.0.100.0/22`.
    pub prefix: String,
    /// The country code.
    ///
    /// Given as a ISO format i.e. `HU`.
    pub cc: String,
    /// AS registry name.
    ///
    /// Given as a string i.e. `ripencc`.
    pub registry: String,
    /// Allocation date.
    ///
    /// Given as an ISO date i.e. `1999-02-25`.
    pub allocated: String,
    /// The autonomous system (AS) Name.
    ///
    /// Given as a string i.e. `INVITECH, HU`.
    pub name: String,
}

impl Display for DnsEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        #[expect(clippy::match_same_arms)]
        match self {
            Self::Resolved(Resolved::Normal(_, hosts)) => write!(f, "{}", hosts.join(" ")),
            Self::Resolved(Resolved::WithAsInfo(_, hosts, asinfo)) => {
                write!(f, "AS{} {}", asinfo.asn, hosts.join(" "))
            }
            Self::Pending(ip) => write!(f, "{ip}"),
            Self::Timeout(ip) => write!(f, "Timeout: {ip}"),
            Self::NotFound(Unresolved::Normal(ip)) => write!(f, "{ip}"),
            Self::NotFound(Unresolved::WithAsInfo(ip, asinfo)) => {
                write!(f, "AS{} {}", asinfo.asn, ip)
            }
            Self::Failed(ip) => write!(f, "Failed: {ip}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_iterator_returns_each_hostname_once() {
        let entry = DnsEntry::Resolved(Resolved::Normal(
            IpAddr::from_str("1.1.1.1").unwrap(),
            vec!["one".to_string(), "two".to_string(), "three".to_string()],
        ));

        let mut iter = entry.hostnames();
        assert_eq!(iter.next(), Some("one"));
        assert_eq!(iter.next(), Some("two"));
        assert_eq!(iter.next(), Some("three"));
        assert_eq!(iter.next(), None);
    }
}
