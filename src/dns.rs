use dns_lookup::{lookup_addr, lookup_host};
use std::collections::HashMap;
use std::net::IpAddr;

/// Caching DNS lookup
#[derive(Debug, Default)]
pub struct DnsResolver {
    addr_cache: HashMap<IpAddr, String>,
}

impl DnsResolver {
    pub fn new() -> Self {
        Self {
            addr_cache: HashMap::new(),
        }
    }

    // TODO add caching
    #[allow(clippy::unused_self)]
    pub fn lookup(&self, hostname: &str) -> anyhow::Result<Vec<IpAddr>> {
        Ok(lookup_host(hostname)?)
    }

    pub fn reverse_lookup(&mut self, addr: IpAddr) -> &str {
        self.addr_cache
            .entry(addr)
            .or_insert_with(|| Self::do_lookup(addr))
    }

    fn do_lookup(addr: IpAddr) -> String {
        lookup_addr(&addr).unwrap_or_else(|_| String::from("unknown"))
    }
}
