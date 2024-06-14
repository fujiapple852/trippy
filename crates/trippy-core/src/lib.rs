//! Trippy - A network tracing library.
//!
//! This crate provides the core network tracing facility used by the
//! standalone [Trippy](https://trippy.cli.rs) application.
//!
//! Note: the public API is not stable and is highly likely to change
//! in the future.
//!
//! # Example
//!
//! The following example builds and runs a tracer with default configuration
//! and prints out the tracing data for each round:
//!
//! ```no_run
//! # fn main() -> anyhow::Result<()> {
//! # use std::net::IpAddr;
//! # use std::str::FromStr;
//! use trippy_core::Builder;
//!
//! let addr = IpAddr::from_str("1.1.1.1")?;
//! Builder::new(addr, |round| println!("{:?}", round)).start()?;
//! # Ok(())
//! # }
//! ```
//!
//! The following example traces using the UDP protocol with the Dublin ECMP
//! strategy with fixed src and dest ports.  It also operates in unprivileged
//! mode (only supported on some platforms):
//!
//! ```no_run
//! # fn main() -> anyhow::Result<()> {
//! # use std::net::IpAddr;
//! # use std::str::FromStr;
//! use trippy_core::{Builder, MultipathStrategy, Port, PortDirection, PrivilegeMode, Protocol};
//!
//! let addr = IpAddr::from_str("1.1.1.1")?;
//! Builder::new(addr, |round| println!("{:?}", round))
//!     .privilege_mode(PrivilegeMode::Unprivileged)
//!     .protocol(Protocol::Udp)
//!     .multipath_strategy(MultipathStrategy::Dublin)
//!     .port_direction(PortDirection::FixedBoth(Port(33000), Port(3500)))
//!     .start()?;
//! # Ok(())
//! # }
//! ```
#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(
    clippy::module_name_repetitions,
    clippy::struct_field_names,
    clippy::use_self,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn,
    clippy::cast_possible_truncation,
    clippy::missing_errors_doc
)]
#![deny(unsafe_code)]

mod builder;
mod config;
mod constants;
mod error;
mod net;
mod probe;
mod tracer;
mod types;

/// Packet wire formats.
pub mod packet;

pub use builder::Builder;
pub use config::{
    defaults, ChannelConfig, ChannelConfigBuilder, Config, ConfigBuilder, IcmpExtensionParseMode,
    MultipathStrategy, PortDirection, PrivilegeMode, Protocol,
};
pub use net::channel::TracerChannel;
pub use net::source::SourceAddr;
pub use net::{PlatformImpl, SocketImpl};
pub use probe::{
    Extension, Extensions, IcmpPacketType, MplsLabelStack, MplsLabelStackMember, Probe,
    ProbeComplete, ProbeState, UnknownExtension,
};
pub use tracer::{CompletionReason, Tracer, TracerRound};
pub use types::{
    Flags, MaxInflight, MaxRounds, PacketSize, PayloadPattern, Port, Round, Sequence, TimeToLive,
    TraceId, TypeOfService,
};
