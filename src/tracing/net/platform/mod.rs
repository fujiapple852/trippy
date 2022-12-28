pub mod byte_order;
pub use byte_order::PlatformIpv4FieldByteOrder;

#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use self::windows::*;
