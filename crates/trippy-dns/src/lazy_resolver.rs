use crate::config::Config;
use crate::resolver::{DnsEntry, ResolvedIpAddrs, Resolver, Result};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::rc::Rc;

/// How DNS queries will be resolved.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ResolveMethod {
    /// Resolve using the OS resolver.
    System,
    /// Resolve using the `/etc/resolv.conf` DNS configuration.
    Resolv,
    /// Resolve using the Google `8.8.8.8` DNS service.
    Google,
    /// Resolve using the Cloudflare `1.1.1.1` DNS service.
    Cloudflare,
}

/// How to resolve IP addresses.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IpAddrFamily {
    /// Lookup IPv4 only.
    Ipv4Only,
    /// Lookup IPv6 only.
    Ipv6Only,
    /// Lookup IPv6 with a fallback to IPv4.
    Ipv6thenIpv4,
    /// Lookup IPv4 with a fallback to IPv6.
    Ipv4thenIpv6,
    /// Use the first IP address returned by the OS resolver when using `ResolveMethod::System`,
    /// otherwise lookup IPv6 with a fallback to IPv4.
    System,
}

impl Display for IpAddrFamily {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4Only => write!(f, "Ipv4Only"),
            Self::Ipv6Only => write!(f, "Ipv6Only"),
            Self::Ipv6thenIpv4 => write!(f, "Ipv6thenIpv4"),
            Self::Ipv4thenIpv6 => write!(f, "Ipv4thenIpv6"),
            Self::System => write!(f, "System"),
        }
    }
}

/// A cheaply cloneable, non-blocking, caching, forward and reverse DNS resolver.
#[derive(Clone)]
pub struct DnsResolver {
    inner: Rc<inner::DnsResolver>,
}

impl DnsResolver {
    /// Create and start a new `DnsResolver`.
    pub fn start(config: Config) -> std::io::Result<Self> {
        Ok(Self {
            inner: Rc::new(inner::DnsResolver::start(config)?),
        })
    }

    /// Get the `Config`.
    #[must_use]
    pub fn config(&self) -> &Config {
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
    fn reverse_lookup(&self, addr: impl Into<IpAddr>) -> DnsEntry {
        self.inner.reverse_lookup(addr.into(), false, false)
    }
    fn reverse_lookup_with_asinfo(&self, addr: impl Into<IpAddr>) -> DnsEntry {
        self.inner.reverse_lookup(addr.into(), true, false)
    }
    fn lazy_reverse_lookup(&self, addr: impl Into<IpAddr>) -> DnsEntry {
        self.inner.reverse_lookup(addr.into(), false, true)
    }
    fn lazy_reverse_lookup_with_asinfo(&self, addr: impl Into<IpAddr>) -> DnsEntry {
        self.inner.reverse_lookup(addr.into(), true, true)
    }
}

/// Private impl of resolver.
mod inner {
    use super::{Config, IpAddrFamily, ResolveMethod};
    use crate::resolver::{AsInfo, DnsEntry, Error, Resolved, ResolvedIpAddrs, Result, Unresolved};
    use crossbeam::channel::{bounded, Receiver, Sender};
    use hickory_resolver::config::{LookupIpStrategy, ResolverConfig, ResolverOpts};
    use hickory_resolver::name_server::TokioConnectionProvider;
    use hickory_resolver::proto::rr::RecordType;
    use hickory_resolver::proto::{ProtoError, ProtoErrorKind};
    use hickory_resolver::system_conf::read_system_conf;
    use hickory_resolver::Name;
    use hickory_resolver::{ResolveError, ResolveErrorKind, TokioResolver};
    use itertools::{Either, Itertools};
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    /// The maximum number of in-flight reverse DNS resolutions that may be
    const RESOLVER_MAX_QUEUE_SIZE: usize = 100;

    /// The duration wait to enqueue a `DnsEntry::Pending` to the resolver before returning
    /// `DnsEntry::Timeout`.
    const RESOLVER_QUEUE_TIMEOUT: Duration = Duration::from_millis(10);

    /// Alias for a cache of reverse DNS lookup entries.
    type Cache = Arc<RwLock<HashMap<IpAddr, CacheEntry>>>;

    /// A cache entry for a reverse DNS lookup.
    #[derive(Debug, Clone)]
    struct CacheEntry {
        /// The DNS entry to cache.
        entry: DnsEntry,
        /// The timestamp of the entry.
        timestamp: SystemTime,
    }

    impl CacheEntry {
        const fn new(entry: DnsEntry, timestamp: SystemTime) -> Self {
            Self { entry, timestamp }
        }

        fn set_timestamp(&mut self, timestamp: SystemTime) {
            self.timestamp = timestamp;
        }
    }

    #[derive(Clone)]
    enum DnsProvider {
        TrustDns(Arc<TokioResolver>),
        DnsLookup,
    }

    #[derive(Debug, Clone)]
    struct DnsResolveRequest {
        addr: IpAddr,
        with_asinfo: bool,
    }

    /// Resolver implementation.
    pub(super) struct DnsResolver {
        config: Config,
        provider: DnsProvider,
        tx: Sender<DnsResolveRequest>,
        addr_cache: Cache,
        runtime: tokio::runtime::Runtime,
    }

    impl DnsResolver {
        pub(super) fn start(config: Config) -> std::io::Result<Self> {
            let (tx, rx) = bounded(RESOLVER_MAX_QUEUE_SIZE);
            let addr_cache = Arc::new(RwLock::new(HashMap::new()));

            let provider = if matches!(config.resolve_method, ResolveMethod::System) {
                DnsProvider::DnsLookup
            } else {
                let mut options = ResolverOpts::default();
                #[expect(clippy::match_same_arms)]
                let ip_strategy = match config.addr_family {
                    IpAddrFamily::Ipv4Only => LookupIpStrategy::Ipv4Only,
                    IpAddrFamily::Ipv6Only => LookupIpStrategy::Ipv6Only,
                    IpAddrFamily::Ipv6thenIpv4 => LookupIpStrategy::Ipv6thenIpv4,
                    IpAddrFamily::Ipv4thenIpv6 => LookupIpStrategy::Ipv4thenIpv6,
                    // see issue #1469
                    IpAddrFamily::System => LookupIpStrategy::Ipv6thenIpv4,
                };
                options.timeout = config.timeout;
                options.ip_strategy = ip_strategy;
                let res = match config.resolve_method {
                    ResolveMethod::Resolv => {
                        let provider = TokioConnectionProvider::default();
                        let (resolver_cfg, mut options) = read_system_conf()?;
                        options.timeout = config.timeout;
                        options.ip_strategy = ip_strategy;
                        let mut builder =
                            TokioResolver::builder_with_config(resolver_cfg, provider);
                        *builder.options_mut() = options;
                        builder.build()
                    }
                    ResolveMethod::Google => {
                        let provider = TokioConnectionProvider::default();
                        let mut builder =
                            TokioResolver::builder_with_config(ResolverConfig::google(), provider);
                        *builder.options_mut() = options;
                        builder.build()
                    }
                    ResolveMethod::Cloudflare => {
                        let provider = TokioConnectionProvider::default();
                        let mut builder = TokioResolver::builder_with_config(
                            ResolverConfig::cloudflare(),
                            provider,
                        );
                        *builder.options_mut() = options;
                        builder.build()
                    }
                    ResolveMethod::System => unreachable!(),
                };
                let resolver = Arc::new(res);
                DnsProvider::TrustDns(resolver)
            };

            // start the tokio run-time
            // TODO needed? where to do this?
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            // spawn a task to process the resolve queue
            {
                let cache = addr_cache.clone();
                let provider = provider.clone();
                runtime.spawn(async { resolver_queue_processor(rx, provider, cache).await });
            }

            Ok(Self {
                config,
                provider,
                tx,
                addr_cache,
                runtime,
            })
        }

        pub(super) const fn config(&self) -> &Config {
            &self.config
        }

        pub(super) fn lookup(&self, hostname: &str) -> Result<ResolvedIpAddrs> {
            // TODO should be spawned as a task
            self.runtime.block_on(self.lookup_async(hostname))
        }

        async fn lookup_async(&self, hostname: &str) -> Result<ResolvedIpAddrs> {
            fn partition(all: Vec<IpAddr>) -> (Vec<IpAddr>, Vec<IpAddr>) {
                all.into_iter().partition_map(|ip| match ip {
                    IpAddr::V4(_) => Either::Left(ip),
                    IpAddr::V6(_) => Either::Right(ip),
                })
            }
            match &self.provider {
                DnsProvider::TrustDns(resolver) => Ok(resolver
                    .lookup_ip(hostname)
                    .await
                    .map_err(|err| Error::LookupFailed(Box::new(err)))?
                    .iter()
                    .collect::<Vec<_>>()),
                DnsProvider::DnsLookup => {
                    let all = dns_lookup::lookup_host(hostname)
                        .map_err(|err| Error::LookupFailed(Box::new(err)))?;
                    Ok(match self.config.addr_family {
                        IpAddrFamily::Ipv4Only => {
                            let (ipv4, _) = partition(all);
                            if ipv4.is_empty() {
                                vec![]
                            } else {
                                ipv4
                            }
                        }
                        IpAddrFamily::Ipv6Only => {
                            let (_, ipv6) = partition(all);
                            if ipv6.is_empty() {
                                vec![]
                            } else {
                                ipv6
                            }
                        }
                        IpAddrFamily::Ipv6thenIpv4 => {
                            let (ipv4, ipv6) = partition(all);
                            if ipv6.is_empty() {
                                ipv4
                            } else {
                                ipv6
                            }
                        }
                        IpAddrFamily::Ipv4thenIpv6 => {
                            let (ipv4, ipv6) = partition(all);
                            if ipv4.is_empty() {
                                ipv6
                            } else {
                                ipv4
                            }
                        }
                        IpAddrFamily::System => all,
                    })
                }
            }
            .map(ResolvedIpAddrs)
        }

        pub(super) fn reverse_lookup(
            &self,
            addr: IpAddr,
            with_asinfo: bool,
            lazy: bool,
        ) -> DnsEntry {
            self.runtime
                .block_on(self.reverse_lookup_async(addr, with_asinfo, lazy))
        }

        async fn reverse_lookup_async(
            &self,
            addr: IpAddr,
            with_asinfo: bool,
            lazy: bool,
        ) -> DnsEntry {
            if lazy {
                self.lazy_reverse_lookup(addr, with_asinfo).entry
            } else {
                reverse_lookup(&self.provider, addr, with_asinfo)
                    .await
                    .entry
            }
        }

        fn lazy_reverse_lookup(&self, addr: IpAddr, with_asinfo: bool) -> CacheEntry {
            let mut enqueue = false;
            let now = SystemTime::now();

            // Check if we have already attempted to resolve this `IpAddr` and return the current
            // `DnsEntry` if so, otherwise add it in a state of `DnsEntry::Pending`.
            let mut dns_entry = self
                .addr_cache
                .write()
                .entry(addr)
                .or_insert_with(|| {
                    enqueue = true;
                    CacheEntry::new(DnsEntry::Pending(addr), now)
                })
                .clone();

            // If the entry exists but is stale then enqueue it again.  The existing entry will
            // be returned until it is refreshed but with an updated timestamp to prevent it from
            // being enqueued multiple times.
            match &dns_entry.entry {
                DnsEntry::Resolved(_) | DnsEntry::NotFound(_) | DnsEntry::Failed(_) => {
                    if now.duration_since(dns_entry.timestamp).unwrap_or_default() > self.config.ttl
                    {
                        self.addr_cache
                            .write()
                            .get_mut(&addr)
                            .expect("addr must be in cache")
                            .set_timestamp(now);
                        enqueue = true;
                    }
                }
                _ => {}
            }

            // If the entry exists but has timed out, then set it as `DnsEntry::Pending` and enqueue
            // it again.
            if let DnsEntry::Timeout(addr) = dns_entry.entry {
                *self
                    .addr_cache
                    .write()
                    .get_mut(&addr)
                    .expect("addr must be in cache") =
                    CacheEntry::new(DnsEntry::Pending(addr), now);
                dns_entry = CacheEntry::new(DnsEntry::Pending(addr), now);
                enqueue = true;
            }

            // If this is a newly added `DnsEntry` then send it to the channel to be resolved in the
            // background.  We do this after the above to ensure we aren't holding the
            // lock on the cache, which is used by the resolver and so would deadlock.
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
                        .expect("addr must be in cache") =
                        CacheEntry::new(DnsEntry::Timeout(addr), now);
                    CacheEntry::new(DnsEntry::Timeout(addr), now)
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
    async fn resolver_queue_processor(
        rx: Receiver<DnsResolveRequest>,
        provider: DnsProvider,
        cache: Cache,
    ) {
        for DnsResolveRequest { addr, with_asinfo } in rx {
            let dns_entry = reverse_lookup(&provider, addr, with_asinfo).await;
            cache.write().insert(addr, dns_entry);
        }
    }

    async fn reverse_lookup(provider: &DnsProvider, addr: IpAddr, with_asinfo: bool) -> CacheEntry {
        let now = SystemTime::now();
        match &provider {
            DnsProvider::DnsLookup => {
                // we can't distinguish between a failed lookup or a genuine error, and so we just
                // assume all failures are `DnsEntry::NotFound`.
                match dns_lookup::lookup_addr(&addr) {
                    Ok(dns) => {
                        CacheEntry::new(DnsEntry::Resolved(Resolved::Normal(addr, vec![dns])), now)
                    }
                    Err(_) => CacheEntry::new(DnsEntry::NotFound(Unresolved::Normal(addr)), now),
                }
            }
            DnsProvider::TrustDns(resolver) => match resolver.reverse_lookup(addr).await {
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
                        let as_info = lookup_asinfo(resolver, addr).await.unwrap_or_default();
                        CacheEntry::new(
                            DnsEntry::Resolved(Resolved::WithAsInfo(addr, hostnames, as_info)),
                            now,
                        )
                    } else {
                        CacheEntry::new(DnsEntry::Resolved(Resolved::Normal(addr, hostnames)), now)
                    }
                }
                Err(err) => match err.kind() {
                    ResolveErrorKind::Proto(prost_err) => match prost_err.kind() {
                        ProtoErrorKind::NoRecordsFound { .. } => {
                            if with_asinfo {
                                let as_info =
                                    lookup_asinfo(resolver, addr).await.unwrap_or_default();
                                CacheEntry::new(
                                    DnsEntry::NotFound(Unresolved::WithAsInfo(addr, as_info)),
                                    now,
                                )
                            } else {
                                CacheEntry::new(DnsEntry::NotFound(Unresolved::Normal(addr)), now)
                            }
                        }
                        ProtoErrorKind::Timeout => CacheEntry::new(DnsEntry::Timeout(addr), now),
                        _ => CacheEntry::new(DnsEntry::Failed(addr), now),
                    },
                    _ => CacheEntry::new(DnsEntry::Failed(addr), now),
                },
            },
        }
    }

    /// Lookup up `AsInfo` for an `IpAddr` address.
    async fn lookup_asinfo(resolver: &Arc<TokioResolver>, addr: IpAddr) -> Result<AsInfo> {
        let origin_query_txt = match addr {
            IpAddr::V4(addr) => query_asn_ipv4(resolver, addr).await?,
            IpAddr::V6(addr) => query_asn_ipv6(resolver, addr).await?,
        };
        let asinfo = parse_origin_query_txt(&origin_query_txt)?;
        let asn_query_txt = query_asn_name(resolver, &asinfo.asn).await?;
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
    async fn query_asn_ipv4(resolver: &Arc<TokioResolver>, addr: Ipv4Addr) -> Result<String> {
        let query = format!(
            "{}.origin.asn.cymru.com.",
            addr.octets().iter().rev().join(".")
        );
        let name = Name::from_str(query.as_str()).map_err(proto_error)?;
        let response = resolver
            .lookup(name, RecordType::TXT)
            .await
            .map_err(resolve_error)?;
        let data = response
            .iter()
            .next()
            .ok_or_else(|| Error::QueryAsnOriginFailed)?;
        let bytes = data.as_txt().ok_or_else(|| Error::QueryAsnOriginFailed)?;
        Ok(bytes.to_string())
    }

    /// Perform the `origin` query.
    async fn query_asn_ipv6(resolver: &Arc<TokioResolver>, addr: Ipv6Addr) -> Result<String> {
        let query = format!(
            "{:x}.origin6.asn.cymru.com.",
            addr.octets()
                .iter()
                .rev()
                .flat_map(|o| [o & 0x0F, (o & 0xF0) >> 4])
                .format(".")
        );
        let name = Name::from_str(query.as_str()).map_err(proto_error)?;
        let response = resolver
            .lookup(name, RecordType::TXT)
            .await
            .map_err(resolve_error)?;
        let data = response
            .iter()
            .next()
            .ok_or_else(|| Error::QueryAsnOriginFailed)?;
        let bytes = data.as_txt().ok_or_else(|| Error::QueryAsnOriginFailed)?;
        Ok(bytes.to_string())
    }

    /// Perform the `asn` query.
    async fn query_asn_name(resolver: &Arc<TokioResolver>, asn: &str) -> Result<String> {
        let query = format!("AS{asn}.asn.cymru.com.");
        let name = Name::from_str(query.as_str()).map_err(proto_error)?;
        let response = resolver
            .lookup(name, RecordType::TXT)
            .await
            .map_err(resolve_error)?;
        let data = response
            .iter()
            .next()
            .ok_or_else(|| Error::QueryAsnFailed)?;
        let bytes = data.as_txt().ok_or_else(|| Error::QueryAsnFailed)?;
        Ok(bytes.to_string())
    }

    /// The `origin` DNS query returns a TXT record in the formal:
    ///      `asn | prefix | cc | registry | allocated`
    ///
    /// For example:
    ///      `12301 | 81.0.100.0/22 | HU | ripencc | 2001-12-06`
    ///
    /// From this we extract all fields.
    fn parse_origin_query_txt(origin_query_txt: &str) -> Result<AsInfo> {
        if origin_query_txt.chars().filter(|c| *c == '|').count() != 4 {
            return Err(Error::ParseOriginQueryFailed(String::from(
                origin_query_txt,
            )));
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
    fn parse_asn_query_txt(asn_query_txt: &str) -> Result<String> {
        if asn_query_txt.chars().filter(|c| *c == '|').count() != 4 {
            return Err(Error::ParseAsnQueryFailed(String::from(asn_query_txt)));
        }
        let mut split = asn_query_txt.split('|');
        Ok(split.nth(4).unwrap_or_default().trim().to_string())
    }

    /// Convert a `ResolveError` to an `Error::LookupFailed`.
    fn resolve_error(err: ResolveError) -> Error {
        Error::LookupFailed(Box::new(err))
    }

    /// Convert a `ProtoError` to an `Error::LookupFailed`.
    fn proto_error(err: ProtoError) -> Error {
        Error::LookupFailed(Box::new(err))
    }
}
