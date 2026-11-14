use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{Name, RecordType};
use std::net::IpAddr;
use tokio::runtime::{Builder, Runtime};

/// Synchronous wrapper to Hickory's async resolver implementation.
pub struct Resolver {
    runtime: Runtime,
    async_resolver: TokioResolver,
}

impl Resolver {
    pub fn new(config: ResolverConfig, options: ResolverOpts) -> std::io::Result<Self> {
        let runtime = Builder::new_current_thread().enable_all().build()?;
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        *builder.options_mut() = options;
        let async_resolver = builder.build().map_err(std::io::Error::other)?;
        Ok(Self {
            runtime,
            async_resolver,
        })
    }

    pub fn lookup_ip(&self, host: &str) -> Result<LookupIp, NetError> {
        let lookup = self.async_resolver.lookup_ip(host);
        self.runtime.block_on(lookup)
    }

    pub fn reverse_lookup(&self, addr: IpAddr) -> Result<Lookup, NetError> {
        let lookup = self.async_resolver.reverse_lookup(Name::from(addr));
        self.runtime.block_on(lookup)
    }

    pub fn lookup(&self, name: Name, record_type: RecordType) -> Result<Lookup, NetError> {
        let lookup = self.async_resolver.lookup(name, record_type);
        self.runtime.block_on(lookup)
    }
}
