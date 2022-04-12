//! Trippy, a network diagnostic tool.
//!
#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(
    clippy::module_name_repetitions,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn
)]
#![forbid(unsafe_code)]

mod icmp;
pub use icmp::{IcmpTracer, IcmpTracerConfig, Probe, ProbeStatus};
