use crate::{IpAddrFamily, ResolveMethod};
use std::time::Duration;

/// A builder for DNS `Config`.
///
/// # Example
///
/// Build a DNS `Config` for the `Ipv4Only` address family.
///
/// ```no_run
/// use trippy_dns::{Builder, IpAddrFamily};
///
/// let config = Builder::new().addr_family(IpAddrFamily::Ipv4Only).build();
pub struct Builder {
    resolve_method: ResolveMethod,
    addr_family: IpAddrFamily,
    timeout: Duration,
    ttl: Duration,
}

impl Builder {
    /// Create a new `Builder`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            resolve_method: Config::default().resolve_method,
            addr_family: Config::default().addr_family,
            timeout: Config::default().timeout,
            ttl: Config::default().ttl,
        }
    }

    /// Set the method to use for DNS resolution.
    #[must_use]
    pub const fn resolve_method(self, resolve_method: ResolveMethod) -> Self {
        Self {
            resolve_method,
            ..self
        }
    }

    /// Set the address family.
    #[must_use]
    pub const fn addr_family(self, addr_family: IpAddrFamily) -> Self {
        Self {
            addr_family,
            ..self
        }
    }

    /// Set the timeout for DNS resolution.
    #[must_use]
    pub const fn timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
    }

    /// Set the time-to-live (TTL) for DNS cache entries.
    #[must_use]
    pub const fn ttl(self, ttl: Duration) -> Self {
        Self { ttl, ..self }
    }

    /// Build the DNS `Config`.
    #[must_use]
    pub const fn build(self) -> Config {
        Config {
            resolve_method: self.resolve_method,
            addr_family: self.addr_family,
            timeout: self.timeout,
            ttl: self.ttl,
        }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for the `DnsResolver`.
#[derive(Debug, Copy, Clone)]
pub struct Config {
    /// The method to use for DNS resolution.
    pub resolve_method: ResolveMethod,
    /// The IP address resolution family.
    pub addr_family: IpAddrFamily,
    /// The timeout for DNS resolution.
    pub timeout: Duration,
    /// The time-to-live (TTL) for DNS cache entries.
    pub ttl: Duration,
}

impl Config {
    /// Create a `Config`.
    #[must_use]
    pub const fn new(
        resolve_method: ResolveMethod,
        addr_family: IpAddrFamily,
        timeout: Duration,
        ttl: Duration,
    ) -> Self {
        Self {
            resolve_method,
            addr_family,
            timeout,
            ttl,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            resolve_method: ResolveMethod::System,
            addr_family: IpAddrFamily::Ipv4thenIpv6,
            timeout: Duration::from_millis(5000),
            ttl: Duration::from_secs(300),
        }
    }
}
