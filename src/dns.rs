use crate::config::DnsResolveMethod;
use crate::dns::inner::DnsResolverInner;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;

/// The state of reverse DNS resolution.
#[derive(Debug, Clone)]
pub enum DnsEntry {
    /// The reverse DNS resolution of `IpAddr` is pending.
    Pending(IpAddr),
    /// The reverse DNS resolution of `IpAddr` has resolved.
    Resolved(Resolved),
    /// The `IpAddr` could not be resolved.
    NotFound(IpAddr),
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

impl Display for DnsEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::match_same_arms)]
        match self {
            DnsEntry::Resolved(Resolved::Normal(_, hosts)) => write!(f, "{}", hosts.join(" ")),
            DnsEntry::Resolved(Resolved::WithAsInfo(_, hosts, asinfo)) => {
                write!(f, "AS{} {}", asinfo.asn, hosts.join(" "))
            }
            DnsEntry::Pending(ip) => write!(f, "{}", ip),
            DnsEntry::NotFound(ip) => write!(f, "{}", ip),
            DnsEntry::Failed(ip) => write!(f, "Failed: {}", ip),
            DnsEntry::Timeout(ip) => write!(f, "Timeout: {}", ip),
        }
    }
}

/// Autonomous System (AS) information.
#[derive(Debug, Clone, Default)]
pub struct AsInfo {
    pub asn: String,
    pub prefix: String,
    pub cc: String,
    pub registry: String,
    pub allocated: String,
    pub name: String,
}

/// Configuration for the `DnsResolver`.
#[derive(Debug, Copy, Clone)]
pub struct DnsResolverConfig {
    pub resolve_method: DnsResolveMethod,
    pub timeout: Duration,
    pub lookup_as_info: bool,
}

impl DnsResolverConfig {
    pub fn new(resolve_method: DnsResolveMethod, timeout: Duration, lookup_as_info: bool) -> Self {
        Self {
            resolve_method,
            timeout,
            lookup_as_info,
        }
    }
}

/// A cheaply cloneable, non-blocking, caching, forward and reverse DNS resolver.
#[derive(Clone)]
pub struct DnsResolver {
    inner: Rc<DnsResolverInner>,
}

impl DnsResolver {
    pub fn new(config: DnsResolverConfig) -> Self {
        Self {
            inner: Rc::new(DnsResolverInner::new(config)),
        }
    }

    /// Resolve a DNS hostname to IP addresses.
    pub fn lookup(&self, hostname: &str) -> anyhow::Result<Vec<IpAddr>> {
        self.inner.lookup(hostname)
    }

    /// Perform a non-blocking reverse DNS lookup of `IpAddr` and return a `DnsEntry`.
    ///
    /// If the `IpAddr` has already been resolved then `DnsEntry::Resolved` is returned immediately.
    ///
    /// Otherwise, the `IpAddr` is enqueued to be resolved in the background and a `DnsEntry::Pending` is
    /// returned.
    ///
    /// If the entry exists but is `DnsEntry::Timeout` then it is changed to be `DnsEntry::Pending` and enqueued.
    ///
    /// If enqueuing times out then the entry is changed to be `DnsEntry::Timeout` and returned.
    pub fn reverse_lookup(&self, addr: IpAddr) -> DnsEntry {
        self.inner.reverse_lookup(addr)
    }

    /// Get the `DnsResolverConfig`.
    pub fn config(&self) -> &DnsResolverConfig {
        self.inner.config()
    }

    pub fn flush(&self) {
        self.inner.flush();
    }
}

/// Private impl of resolver.
mod inner {
    use crate::dns::{AsInfo, DnsEntry, DnsResolveMethod, DnsResolverConfig, Resolved};
    use anyhow::anyhow;
    use crossbeam::channel::{bounded, Receiver, Sender};
    use itertools::Itertools;
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
    use trust_dns_resolver::error::ResolveErrorKind;
    use trust_dns_resolver::proto::rr::RecordType;
    use trust_dns_resolver::{Name, Resolver};

    /// The maximum number of in-flight reverse DNS resolutions that may be
    const RESOLVER_MAX_QUEUE_SIZE: usize = 100;

    /// The duration wait to enqueue a `DnsEntry::Pending` to the resolver before returning `DnsEntry::Timeout`.
    const RESOLVER_QUEUE_TIMEOUT: Duration = Duration::from_millis(10);

    /// Alias for a cache of reverse DNS lookup entries.
    type Cache = Arc<RwLock<HashMap<IpAddr, DnsEntry>>>;

    #[derive(Clone)]
    enum DnsProvider {
        TrustDns(Arc<Resolver>),
        DnsLookup,
    }

    /// Resolver implementation.
    pub struct DnsResolverInner {
        config: DnsResolverConfig,
        provider: DnsProvider,
        tx: Sender<IpAddr>,
        addr_cache: Cache,
    }

    impl DnsResolverInner {
        pub fn new(config: DnsResolverConfig) -> Self {
            let (tx, rx) = bounded(RESOLVER_MAX_QUEUE_SIZE);
            let addr_cache = Arc::new(RwLock::new(HashMap::new()));

            let provider = if let DnsResolveMethod::System = config.resolve_method {
                DnsProvider::DnsLookup
            } else {
                let mut options = ResolverOpts::default();
                options.timeout = config.timeout;
                let res = match config.resolve_method {
                    DnsResolveMethod::Resolv => Resolver::from_system_conf(),
                    DnsResolveMethod::Google => Resolver::new(ResolverConfig::google(), options),
                    DnsResolveMethod::Cloudflare => {
                        Resolver::new(ResolverConfig::cloudflare(), options)
                    }
                    DnsResolveMethod::System => unreachable!(),
                };
                let resolver = Arc::new(res.expect("resolver"));
                DnsProvider::TrustDns(resolver)
            };

            // spawn a thread to process the resolve queue
            {
                let cache = addr_cache.clone();
                let provider = provider.clone();
                thread::spawn(move || {
                    resolver_queue_processor(rx, &provider, &cache, config.lookup_as_info);
                });
            }
            Self {
                config,
                provider,
                tx,
                addr_cache,
            }
        }

        pub fn config(&self) -> &DnsResolverConfig {
            &self.config
        }

        pub fn lookup(&self, hostname: &str) -> anyhow::Result<Vec<IpAddr>> {
            match &self.provider {
                DnsProvider::TrustDns(resolver) => {
                    Ok(resolver.lookup_ip(hostname)?.iter().collect::<Vec<_>>())
                }
                DnsProvider::DnsLookup => Ok(dns_lookup::lookup_host(hostname)?),
            }
        }

        pub fn reverse_lookup(&self, addr: IpAddr) -> DnsEntry {
            let mut enqueue = false;

            // Check if we have already attempted to resolve this `IpAddr` and return the current `DnsEntry` if so,
            // otherwise add it in a state of `DnsEntry::Pending`.
            let mut dns_entry = self
                .addr_cache
                .write()
                .entry(addr)
                .or_insert_with(|| {
                    enqueue = true;
                    DnsEntry::Pending(addr)
                })
                .clone();

            // If the entry exists but has timed out, then set it as DnsEntry::Pending and enqueue it again.
            if let DnsEntry::Timeout(addr) = dns_entry {
                *self
                    .addr_cache
                    .write()
                    .get_mut(&addr)
                    .expect("addr must be in cache") = DnsEntry::Pending(addr);
                dns_entry = DnsEntry::Pending(addr);
                enqueue = true;
            }

            // If this is a newly added `DnsEntry` then send it to the channel to be resolved in the background.  We do
            // this after the above to ensure we aren't holding the lock on the cache, which is usd by the resolver and so
            // would deadlock.
            if enqueue {
                if self.tx.send_timeout(addr, RESOLVER_QUEUE_TIMEOUT).is_ok() {
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
    /// For each `IpAddr`, perform the reverse DNS lookup and update the cache with the result (`Resolved`, `NotFound`,
    /// `Timeout` or `Failed`) for that addr.
    fn resolver_queue_processor(
        rx: Receiver<IpAddr>,
        provider: &DnsProvider,
        cache: &Cache,
        asinfo_lookup: bool,
    ) {
        for addr in rx {
            let entry = match &provider {
                DnsProvider::DnsLookup => {
                    // we can't distinguish between a failed lookup or a genuine error and so we just assume all
                    // failures are `DnsEntry::NotFound`.
                    match dns_lookup::lookup_addr(&addr) {
                        Ok(dns) => DnsEntry::Resolved(Resolved::Normal(addr, vec![dns])),
                        Err(_) => DnsEntry::NotFound(addr),
                    }
                }
                DnsProvider::TrustDns(resolver) => match resolver.reverse_lookup(addr) {
                    Ok(name) => {
                        let hostnames = name.iter().map(Name::to_string).collect();
                        if asinfo_lookup {
                            let as_info = lookup_asinfo(resolver, addr).unwrap_or_default();
                            DnsEntry::Resolved(Resolved::WithAsInfo(addr, hostnames, as_info))
                        } else {
                            DnsEntry::Resolved(Resolved::Normal(addr, hostnames))
                        }
                    }
                    Err(err) => match err.kind() {
                        ResolveErrorKind::NoRecordsFound { .. } => DnsEntry::NotFound(addr),
                        ResolveErrorKind::Timeout => DnsEntry::Timeout(addr),
                        _ => DnsEntry::Failed(addr),
                    },
                },
            };
            cache.write().insert(addr, entry);
        }
    }

    /// Lookup up `AsInfo` for an `IpAddr` address.
    fn lookup_asinfo(resolver: &Arc<Resolver>, addr: IpAddr) -> anyhow::Result<AsInfo> {
        match addr {
            IpAddr::V4(addr) => lookup_asinfo_ipv4(resolver, addr),
            IpAddr::V6(_) => Ok(AsInfo::default()),
        }
    }

    /// Lookup up `AsInfo` for an `Ipv4Addr` address.
    fn lookup_asinfo_ipv4(resolver: &Arc<Resolver>, addr: Ipv4Addr) -> anyhow::Result<AsInfo> {
        let origin_query_txt = query_asn_ipv4(resolver, addr)?;
        let asinfo = parse_origin_query_txt(&origin_query_txt)?;
        let asn_query_txt = query_asn_name_ipv4(resolver, &asinfo.asn)?;
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

    /// Perform the `asn` query.
    fn query_asn_name_ipv4(resolver: &Arc<Resolver>, asn: &str) -> anyhow::Result<String> {
        let query = format!("AS{}.asn.cymru.com.", asn);
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
