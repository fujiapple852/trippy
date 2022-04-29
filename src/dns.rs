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
    /// The reverse DNS resolution of `IpAddr` has resolved as `String`.
    Resolved(IpAddr, Vec<String>),
    /// The `IpAddr` could not be resolved.
    NotFound(IpAddr),
    /// The reverse DNS resolution of `IpAddr` failed.
    Failed(IpAddr),
    /// The reverse DNS resolution of `IpAddr` timed out.
    Timeout(IpAddr),
}

impl Display for DnsEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::match_same_arms)]
        match self {
            DnsEntry::Resolved(_, s) => write!(f, "{}", s.join(" ")),
            DnsEntry::Pending(ip) => write!(f, "{}", ip),
            DnsEntry::NotFound(ip) => write!(f, "{}", ip),
            DnsEntry::Failed(ip) => write!(f, "Failed: {}", ip),
            DnsEntry::Timeout(ip) => write!(f, "Timeout: {}", ip),
        }
    }
}

/// A cheaply cloneable, non-blocking, caching, forward and reverse DNS resolver.
#[derive(Clone)]
pub struct DnsResolver {
    inner: Rc<DnsResolverInner>,
}

impl DnsResolver {
    pub fn new(resolve_method: DnsResolveMethod, timeout: Duration) -> Self {
        Self {
            inner: Rc::new(DnsResolverInner::new(resolve_method, timeout)),
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
}

/// Private impl of resolver.
mod inner {
    use crate::dns::{DnsEntry, DnsResolveMethod};
    use crossbeam::channel::{bounded, Receiver, Sender};
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
    use trust_dns_resolver::error::ResolveErrorKind;
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
        provider: DnsProvider,
        tx: Sender<IpAddr>,
        addr_cache: Cache,
    }

    impl DnsResolverInner {
        pub fn new(method: DnsResolveMethod, timeout: Duration) -> Self {
            let (tx, rx) = bounded(RESOLVER_MAX_QUEUE_SIZE);
            let addr_cache = Arc::new(RwLock::new(HashMap::new()));

            let provider = if let DnsResolveMethod::System = method {
                DnsProvider::DnsLookup
            } else {
                let mut options = ResolverOpts::default();
                options.timeout = timeout;
                let res = match method {
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
                thread::spawn(move || resolver_queue_processor(rx, &provider, &cache));
            }
            Self {
                provider,
                tx,
                addr_cache,
            }
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
    }

    /// Process each `IpAddr` from the resolver queue and perform the reverse DNS lookup.
    ///
    /// For each `IpAddr`, perform the reverse DNS lookup and update the cache with the result (`Resolved`, `NotFound`,
    /// `Timeout` or `Failed`) for that addr.
    fn resolver_queue_processor(rx: Receiver<IpAddr>, provider: &DnsProvider, cache: &Cache) {
        for addr in rx {
            let entry = match &provider {
                DnsProvider::DnsLookup => {
                    // we can't distinguish between a failed lookup or a generate error and so we just assume all
                    // failures are `DnsEntry::NotFound`.
                    match dns_lookup::lookup_addr(&addr) {
                        Ok(dns) => DnsEntry::Resolved(addr, vec![dns]),
                        Err(_) => DnsEntry::NotFound(addr),
                    }
                }
                DnsProvider::TrustDns(resolver) => match resolver.reverse_lookup(addr) {
                    Ok(name) => {
                        DnsEntry::Resolved(addr, name.iter().map(Name::to_string).collect())
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
}
