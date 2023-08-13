#![doc = include_str!("../../README.md")]
#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(
    clippy::module_name_repetitions,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn,
    clippy::cast_possible_truncation,
    clippy::missing_errors_doc
)]
#![deny(unsafe_code)]

mod config;
mod constants;
mod error;
mod net;
mod probe;
mod tracer;
mod types;
mod util;

pub use config::{
    MultipathStrategy, PortDirection, TracerAddrFamily, TracerChannelConfig, TracerConfig,
    TracerProtocol,
};
pub use net::channel::TracerChannel;
pub use net::packet;
pub use net::source::SourceAddr;
pub use probe::{IcmpPacketType, Probe, ProbeStatus};
pub use tracer::{Tracer, TracerRound};
