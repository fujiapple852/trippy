//! A lazy DNS resolver.
//!
//! This module provides a cheaply cloneable, non-blocking, caching, forward
//! and reverse DNS resolver which support the ability to lookup Autonomous
//! System (AS) information.

mod lazy_resolver;
mod resolver;

pub use lazy_resolver::{Config, DnsResolver, ResolveMethod};
pub use resolver::{AsInfo, DnsEntry, Error, Resolved, Resolver, Result, Unresolved};
