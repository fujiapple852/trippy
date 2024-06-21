//! Trippy - A network tracing library.
//!
//! This crate provides the core network tracing facility used by the
//! standalone [Trippy](https://trippy.cli.rs) application.
//!
//! The public API is designed to offer a flexible and powerful way to perform network tracing,
//! with support for various protocols and strategies. It allows users to customize the tracing
//! process extensively, including the choice of protocol, the strategy for handling equal-cost
//! multi-path routing, and more.
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
//! Builder::new(addr)
//!     .build()?
//!     .run_with(|round| println!("{:?}", round))?;
//! # Ok(())
//! # }
//! ```
//!
//! The following example traces using the UDP protocol with the Dublin ECMP
//! strategy with fixed src and dest ports. It also operates in unprivileged
//! mode (only supported on some platforms):
//!
//! ```no_run
//! # fn main() -> anyhow::Result<()> {
//! # use std::net::IpAddr;
//! # use std::str::FromStr;
//! use trippy_core::{Builder, MultipathStrategy, Port, PortDirection, PrivilegeMode, Protocol};
//!
//! let addr = IpAddr::from_str("1.1.1.1")?;
//! Builder::new(addr)
//!     .privilege_mode(PrivilegeMode::Unprivileged)
//!     .protocol(Protocol::Udp)
//!     .multipath_strategy(MultipathStrategy::Dublin)
//!     .port_direction(PortDirection::FixedBoth(Port(33000), Port(3500)))
//!     .build()?
//!     .run_with(|round| println!("{:?}", round))?;
//! # Ok(())
//! # }
//! ```
//!
//! # See Also
//!
//! - [`Builder`] - Build a [`Tracer`].
//! - [`Tracer::run`] - Run the tracer on the current thread.
//! - [`Tracer::run_with`] - Run the tracer with a custom round handler.
//! - [`Tracer::spawn`] - Run the tracer on a new thread.
//! - [`Tracer::spawn_with`] - Run the tracer on a new thread with a custom round handler.
#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(
    clippy::module_name_repetitions,
    clippy::struct_field_names,
    clippy::use_self,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn,
    clippy::cast_possible_truncation,
    clippy::missing_errors_doc,
    clippy::cast_precision_loss
)]
#![deny(unsafe_code)]

mod builder;
mod config;
mod constants;
mod error;
mod flows;
mod net;
mod probe;
mod state;
mod strategy;
mod tracer;
mod types;

use net::channel::TracerChannel;
use net::source::SourceAddr;

pub use builder::Builder;
pub use config::{
    defaults, IcmpExtensionParseMode, MultipathStrategy, PortDirection, PrivilegeMode, Protocol,
};
pub use constants::MAX_TTL;
pub use error::TracerError;
pub use flows::{FlowEntry, FlowId};
pub use probe::{
    Extension, Extensions, IcmpPacketType, MplsLabelStack, MplsLabelStackMember, Probe,
    ProbeComplete, ProbeState, UnknownExtension,
};
pub use state::{Hop, TraceState};
pub use strategy::{CompletionReason, TracerRound, TracerStrategy};
pub use tracer::Tracer;
pub use types::{
    Flags, MaxInflight, MaxRounds, PacketSize, PayloadPattern, Port, Round, Sequence, TimeToLive,
    TraceId, TypeOfService,
};
