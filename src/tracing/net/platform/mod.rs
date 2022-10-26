pub mod byte_order;
pub use byte_order::PlatformIpv4FieldByteOrder;

#[cfg(unix)]
pub mod unix;

#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use windows::*;
