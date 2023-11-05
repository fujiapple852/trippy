//! A DNS resolver.
//!
//! This module provides a cheaply cloneable, non-blocking, caching, forward
//! and reverse DNS resolver which support the ability to lookup Autonomous
//! System (AS) information.

mod lazy;
mod resolver;

pub use lazy::{DnsResolveMethod, DnsResolver, DnsResolverConfig};
pub use resolver::{AsInfo, DnsEntry, Resolved, Resolver, Unresolved};
