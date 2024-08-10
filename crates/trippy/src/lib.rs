#![allow(
    rustdoc::broken_intra_doc_links,
    rustdoc::bare_urls,
    clippy::doc_markdown,
    clippy::doc_lazy_continuation
)]
#![doc = include_str!("../README.md")]

// Re-export the user facing libraries, so they may be used from trippy crate directly.

#[cfg(feature = "core")]
/// A network tracer.
pub mod core {
    pub use trippy_core::*;
}

#[cfg(feature = "dns")]
/// A lazy DNS resolver.
pub mod dns {
    pub use trippy_dns::*;
}

#[cfg(feature = "privilege")]
/// Discover platform privileges.
pub mod privilege {
    pub use trippy_privilege::*;
}

#[cfg(feature = "packet")]
/// Network packets.
pub mod packet {
    pub use trippy_packet::*;
}
