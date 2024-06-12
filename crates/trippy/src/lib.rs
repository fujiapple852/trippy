#![allow(rustdoc::broken_intra_doc_links, rustdoc::bare_urls)]
#![doc = include_str!("../../../README.md")]

// Re-export the user facing libraries, so they may be used from trippy crate directly.

/// A network tracer.
pub mod core {
    pub use trippy_core::*;
}

/// A lazy DNS resolver.
pub mod dns {
    pub use trippy_dns::*;
}

/// Discover platform privileges.
pub mod privilege {
    pub use trippy_privilege::*;
}
