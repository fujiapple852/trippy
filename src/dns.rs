//! A DNS resolver.
//!
//! This module provides a cheaply cloneable, non-blocking, caching, forward
//! and reverse DNS resolver which support the ability to lookup Autonomous
//! System (AS) information.
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;
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
    LookupFailed(Box<dyn std::error::Error>),
}

/// The output of a successful DNS lookup.
#[derive(Debug, Clone)]
pub struct ResolvedIpAddrs(Vec<IpAddr>);

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

/// Information about a resolved `IpAddr`.
#[derive(Debug, Clone)]
pub enum Resolved {
    /// Resolved without AsInfo.
    Normal(IpAddr, Vec<String>),
    /// Resolved with AsInfo.
    WithAsInfo(IpAddr, Vec<String>, AsInfo),
}

/// Information about an unresolved `IpAddr`.
#[derive(Debug, Clone)]
pub enum Unresolved {
    /// Unresolved without AsInfo.
    Normal(IpAddr),
    /// Unresolved with AsInfo.
    WithAsInfo(IpAddr, AsInfo),
}

impl Display for DnsEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::match_same_arms)]
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

/// Autonomous System (AS) information.
#[derive(Debug, Clone, Default)]
pub struct AsInfo {
    /// The Autonomous System Number.
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
    /// The Autonomous System Name.
    ///
    /// Given as a string i.e. `INVITECH, HU`.
    pub name: String,
}

/// The address family.
#[derive(Debug, Copy, Clone)]
pub enum IpAddrFamily {
    /// Internet Protocol v4.
    Ipv4,
    /// Internet Protocol v6.
    Ipv6,
}

/// How DNS queries will be resolved.
#[derive(Debug, Copy, Clone)]
pub enum DnsResolveMethod {
    /// Resolve using the OS resolver.
    System,
    /// Resolve using the `/etc/resolv.conf` DNS configuration.
    Resolv,
    /// Resolve using the Google `8.8.8.8` DNS service.
    Google,
    /// Resolve using the Cloudflare `1.1.1.1` DNS service.
    Cloudflare,
}

/// Configuration for the `DnsResolver`.
#[derive(Debug, Copy, Clone)]
pub struct DnsResolverConfig {
    /// The method to use for DNS resolution.
    pub resolve_method: DnsResolveMethod,
    /// The address family to lookup.
    pub addr_family: IpAddrFamily,
    /// The timeout for DNS resolution.
    pub timeout: Duration,
}

impl DnsResolverConfig {
    /// Create an IPv4 `DnsResolverConfig`.
    #[must_use]
    pub fn new_ipv4(resolve_method: DnsResolveMethod, timeout: Duration) -> Self {
        Self {
            resolve_method,
            addr_family: IpAddrFamily::Ipv4,
            timeout,
        }
    }

    /// Create an IPv6 `DnsResolverConfig`.
    #[must_use]
    pub fn new_ipv6(resolve_method: DnsResolveMethod, timeout: Duration) -> Self {
        Self {
            resolve_method,
            addr_family: IpAddrFamily::Ipv6,
            timeout,
        }
    }
}

/// A cheaply cloneable, non-blocking, caching, forward and reverse DNS resolver.
#[derive(Clone)]
pub struct DnsResolver {
    inner: Rc<inner::DnsResolverInner>,
}

impl DnsResolver {
    /// Create and start a new `DnsResolver`.
    pub fn start(config: DnsResolverConfig) -> anyhow::Result<Self> {
        Ok(Self {
            inner: Rc::new(inner::DnsResolverInner::start(config)?),
        })
    }

    /// Get the `DnsResolverConfig`.
    #[must_use]
    pub fn config(&self) -> &DnsResolverConfig {
        self.inner.config()
    }

    /// Flush the cache of responses.
    pub fn flush(&self) {
        self.inner.flush();
    }
}

impl Resolver for DnsResolver {
    fn lookup(&self, hostname: impl AsRef<str>) -> Result<ResolvedIpAddrs> {
        self.inner.lookup(hostname.as_ref())
    }
    #[must_use]
    fn reverse_lookup(&self, addr: impl Into<IpAddr>) -> DnsEntry {
        self.inner.reverse_lookup(addr.into(), false, false)
    }
    #[must_use]
    fn reverse_lookup_with_asinfo(&self, addr: impl Into<IpAddr>) -> DnsEntry {
        self.inner.reverse_lookup(addr.into(), true, false)
    }
    #[must_use]
    fn lazy_reverse_lookup(&self, addr: impl Into<IpAddr>) -> DnsEntry {
        self.inner.reverse_lookup(addr.into(), false, true)
    }
    #[must_use]
    fn lazy_reverse_lookup_with_asinfo(&self, addr: impl Into<IpAddr>) -> DnsEntry {
        self.inner.reverse_lookup(addr.into(), true, true)
    }
}

/// Private impl of resolver.
mod inner {
    use crate::dns::{
        AsInfo, DnsEntry, DnsResolveMethod, DnsResolverConfig, Error, IpAddrFamily, Resolved,
        ResolvedIpAddrs, Result, Unresolved,
    };
    use anyhow::anyhow;
    use crossbeam::channel::{bounded, Receiver, Sender};
    use hickory_resolver::config::{LookupIpStrategy, ResolverConfig, ResolverOpts};
    use hickory_resolver::error::ResolveErrorKind;
    use hickory_resolver::proto::rr::RecordType;
    use hickory_resolver::{Name, Resolver};
    use itertools::Itertools;
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    /// The maximum number of in-flight reverse DNS resolutions that may be
    const RESOLVER_MAX_QUEUE_SIZE: usize = 100;

    /// The duration wait to enqueue a `DnsEntry::Pending` to the resolver before returning
    /// `DnsEntry::Timeout`.
    const RESOLVER_QUEUE_TIMEOUT: Duration = Duration::from_millis(10);

    /// Alias for a cache of reverse DNS lookup entries.
    type Cache = Arc<RwLock<HashMap<IpAddr, DnsEntry>>>;

    #[derive(Clone)]
    enum DnsProvider {
        TrustDns(Arc<Resolver>),
        DnsLookup,
    }

    #[derive(Debug, Clone)]
    pub struct DnsResolveRequest {
        addr: IpAddr,
        with_asinfo: bool,
    }

    /// Resolver implementation.
    pub struct DnsResolverInner {
        config: DnsResolverConfig,
        provider: DnsProvider,
        tx: Sender<DnsResolveRequest>,
        addr_cache: Cache,
    }

    impl DnsResolverInner {
        pub fn start(config: DnsResolverConfig) -> anyhow::Result<Self> {
            let (tx, rx) = bounded(RESOLVER_MAX_QUEUE_SIZE);
            let addr_cache = Arc::new(RwLock::new(HashMap::new()));

            let provider = if matches!(config.resolve_method, DnsResolveMethod::System) {
                DnsProvider::DnsLookup
            } else {
                let mut options = ResolverOpts::default();
                options.timeout = config.timeout;
                options.ip_strategy = match config.addr_family {
                    IpAddrFamily::Ipv4 => LookupIpStrategy::Ipv4Only,
                    IpAddrFamily::Ipv6 => LookupIpStrategy::Ipv6Only,
                };
                let res = match config.resolve_method {
                    DnsResolveMethod::Resolv => Resolver::from_system_conf(),
                    DnsResolveMethod::Google => Resolver::new(ResolverConfig::google(), options),
                    DnsResolveMethod::Cloudflare => {
                        Resolver::new(ResolverConfig::cloudflare(), options)
                    }
                    DnsResolveMethod::System => unreachable!(),
                }?;
                let resolver = Arc::new(res);
                DnsProvider::TrustDns(resolver)
            };

            // spawn a thread to process the resolve queue
            {
                let cache = addr_cache.clone();
                let provider = provider.clone();
                thread::spawn(move || resolver_queue_processor(rx, &provider, &cache));
            }
            Ok(Self {
                config,
                provider,
                tx,
                addr_cache,
            })
        }

        pub fn config(&self) -> &DnsResolverConfig {
            &self.config
        }

        pub fn lookup(&self, hostname: &str) -> Result<ResolvedIpAddrs> {
            match &self.provider {
                DnsProvider::TrustDns(resolver) => Ok(resolver
                    .lookup_ip(hostname)
                    .map_err(|err| Error::LookupFailed(Box::new(err)))?
                    .iter()
                    .collect::<Vec<_>>()),
                DnsProvider::DnsLookup => Ok(dns_lookup::lookup_host(hostname)
                    .map_err(|err| Error::LookupFailed(Box::new(err)))?
                    .into_iter()
                    .filter(|addr| {
                        matches!(
                            (self.config.addr_family, addr),
                            (IpAddrFamily::Ipv4, IpAddr::V4(_))
                                | (IpAddrFamily::Ipv6, IpAddr::V6(_))
                        )
                    })
                    .collect::<Vec<_>>()),
            }
            .map(ResolvedIpAddrs)
        }

        pub fn reverse_lookup(&self, addr: IpAddr, with_asinfo: bool, lazy: bool) -> DnsEntry {
            if lazy {
                self.lazy_reverse_lookup(addr, with_asinfo)
            } else {
                reverse_lookup(&self.provider, addr, with_asinfo)
            }
        }

        fn lazy_reverse_lookup(&self, addr: IpAddr, with_asinfo: bool) -> DnsEntry {
            let mut enqueue = false;

            // Check if we have already attempted to resolve this `IpAddr` and return the current
            // `DnsEntry` if so, otherwise add it in a state of `DnsEntry::Pending`.
            let mut dns_entry = self
                .addr_cache
                .write()
                .entry(addr)
                .or_insert_with(|| {
                    enqueue = true;
                    DnsEntry::Pending(addr)
                })
                .clone();

            // If the entry exists but has timed out, then set it as DnsEntry::Pending and enqueue
            // it again.
            if let DnsEntry::Timeout(addr) = dns_entry {
                *self
                    .addr_cache
                    .write()
                    .get_mut(&addr)
                    .expect("addr must be in cache") = DnsEntry::Pending(addr);
                dns_entry = DnsEntry::Pending(addr);
                enqueue = true;
            }

            // If this is a newly added `DnsEntry` then send it to the channel to be resolved in the
            // background.  We do this after the above to ensure we aren't holding the
            // lock on the cache, which is usd by the resolver and so would deadlock.
            if enqueue {
                if self
                    .tx
                    .send_timeout(
                        DnsResolveRequest { addr, with_asinfo },
                        RESOLVER_QUEUE_TIMEOUT,
                    )
                    .is_ok()
                {
                    dns_entry
                } else {
                    *self
                        .addr_cache
                        .write()
                        .get_mut(&addr)
                        .expect("addr must be in cache") = DnsEntry::Timeout(addr);
                    DnsEntry::Timeout(addr)
                }
            } else {
                dns_entry
            }
        }

        pub fn flush(&self) {
            self.addr_cache.write().clear();
        }
    }

    /// Process each `IpAddr` from the resolver queue and perform the reverse DNS lookup.
    ///
    /// For each `IpAddr`, perform the reverse DNS lookup and update the cache with the result
    /// (`Resolved`, `NotFound`, `Timeout` or `Failed`) for that addr.
    fn resolver_queue_processor(
        rx: Receiver<DnsResolveRequest>,
        provider: &DnsProvider,
        cache: &Cache,
    ) {
        for DnsResolveRequest { addr, with_asinfo } in rx {
            let dns_entry = reverse_lookup(provider, addr, with_asinfo);
            cache.write().insert(addr, dns_entry);
        }
    }

    fn reverse_lookup(provider: &DnsProvider, addr: IpAddr, with_asinfo: bool) -> DnsEntry {
        match &provider {
            DnsProvider::DnsLookup => {
                // we can't distinguish between a failed lookup or a genuine error and so we just
                // assume all failures are `DnsEntry::NotFound`.
                match dns_lookup::lookup_addr(&addr) {
                    Ok(dns) => DnsEntry::Resolved(Resolved::Normal(addr, vec![dns])),
                    Err(_) => DnsEntry::NotFound(Unresolved::Normal(addr)),
                }
            }
            DnsProvider::TrustDns(resolver) => match resolver.reverse_lookup(addr) {
                Ok(name) => {
                    let hostnames = name
                        .into_iter()
                        .map(|mut s| {
                            s.0.set_fqdn(false);
                            s
                        })
                        .map(|s| s.to_string())
                        .collect();
                    if with_asinfo {
                        let as_info = lookup_asinfo(resolver, addr).unwrap_or_default();
                        DnsEntry::Resolved(Resolved::WithAsInfo(addr, hostnames, as_info))
                    } else {
                        DnsEntry::Resolved(Resolved::Normal(addr, hostnames))
                    }
                }
                Err(err) => match err.kind() {
                    ResolveErrorKind::NoRecordsFound { .. } => {
                        if with_asinfo {
                            let as_info = lookup_asinfo(resolver, addr).unwrap_or_default();
                            DnsEntry::NotFound(Unresolved::WithAsInfo(addr, as_info))
                        } else {
                            DnsEntry::NotFound(Unresolved::Normal(addr))
                        }
                    }
                    ResolveErrorKind::Timeout => DnsEntry::Timeout(addr),
                    _ => DnsEntry::Failed(addr),
                },
            },
        }
    }

    /// Lookup up `AsInfo` for an `IpAddr` address.
    fn lookup_asinfo(resolver: &Arc<Resolver>, addr: IpAddr) -> anyhow::Result<AsInfo> {
        let origin_query_txt = match addr {
            IpAddr::V4(addr) => query_asn_ipv4(resolver, addr)?,
            IpAddr::V6(addr) => query_asn_ipv6(resolver, addr)?,
        };
        let asinfo = parse_origin_query_txt(&origin_query_txt)?;
        let asn_query_txt = query_asn_name(resolver, &asinfo.asn)?;
        let as_name = parse_asn_query_txt(&asn_query_txt)?;
        Ok(AsInfo {
            asn: asinfo.asn,
            prefix: asinfo.prefix,
            cc: asinfo.cc,
            registry: asinfo.registry,
            allocated: asinfo.allocated,
            name: as_name,
        })
    }

    /// Perform the `origin` query.
    fn query_asn_ipv4(resolver: &Arc<Resolver>, addr: Ipv4Addr) -> anyhow::Result<String> {
        let query = format!(
            "{}.origin.asn.cymru.com.",
            addr.octets().iter().rev().join(".")
        );
        let name = Name::from_str(query.as_str())?;
        let response = resolver.lookup(name, RecordType::TXT)?;
        let data = response
            .iter()
            .next()
            .ok_or_else(|| anyhow!("asn origin query"))?;
        let bytes = data.as_txt().ok_or_else(|| anyhow!("asn origin query"))?;
        Ok(bytes.to_string())
    }

    /// Perform the `origin` query.
    fn query_asn_ipv6(resolver: &Arc<Resolver>, addr: Ipv6Addr) -> anyhow::Result<String> {
        let query = format!(
            "{:x}.origin6.asn.cymru.com.",
            addr.octets()
                .iter()
                .rev()
                .flat_map(|o| [o & 0x0F, (o & 0xF0) >> 4])
                .format(".")
        );
        let name = Name::from_str(query.as_str())?;
        let response = resolver.lookup(name, RecordType::TXT)?;
        let data = response
            .iter()
            .next()
            .ok_or_else(|| anyhow!("asn origin6 query"))?;
        let bytes = data.as_txt().ok_or_else(|| anyhow!("asn origin6 query"))?;
        Ok(bytes.to_string())
    }

    /// Perform the `asn` query.
    fn query_asn_name(resolver: &Arc<Resolver>, asn: &str) -> anyhow::Result<String> {
        let query = format!("AS{asn}.asn.cymru.com.");
        let name = Name::from_str(query.as_str())?;
        let response = resolver.lookup(name, RecordType::TXT)?;
        let data = response.iter().next().ok_or_else(|| anyhow!("asn query"))?;
        let bytes = data.as_txt().ok_or_else(|| anyhow!("asn query"))?;
        Ok(bytes.to_string())
    }

    /// The `origin` DNS query returns a TXT record in the formal:
    ///      `asn | prefix | cc | registry | allocated`
    ///
    /// For example:
    ///      `12301 | 81.0.100.0/22 | HU | ripencc | 2001-12-06`
    ///
    /// From this we extract all fields.
    fn parse_origin_query_txt(origin_query_txt: &str) -> anyhow::Result<AsInfo> {
        if origin_query_txt.chars().filter(|c| *c == '|').count() != 4 {
            return Err(anyhow!(
                "failed to parse AS origin txt: {}",
                origin_query_txt
            ));
        }
        let mut split = origin_query_txt.split('|');
        let asn = split.next().unwrap_or_default().trim().to_string();
        let prefix = split.next().unwrap_or_default().trim().to_string();
        let cc = split.next().unwrap_or_default().trim().to_string();
        let registry = split.next().unwrap_or_default().trim().to_string();
        let allocated = split.next().unwrap_or_default().trim().to_string();
        Ok(AsInfo {
            asn,
            prefix,
            cc,
            registry,
            allocated,
            name: String::default(),
        })
    }

    /// The `asn` DNS query returns a TXT record in the formal:
    ///      `asn | cc | registry | allocated | name`
    ///
    /// For example:
    ///      `12301 | HU | ripencc | 1999-02-25 | INVITECH, HU`
    ///
    /// From this we extract the 4th field (name, `INVITECH, HU` in this example)
    fn parse_asn_query_txt(asn_query_txt: &str) -> anyhow::Result<String> {
        if asn_query_txt.chars().filter(|c| *c == '|').count() != 4 {
            return Err(anyhow!("failed to parse AS origin txt: {}", asn_query_txt));
        }
        let mut split = asn_query_txt.split('|');
        Ok(split.nth(4).unwrap_or_default().trim().to_string())
    }
}
