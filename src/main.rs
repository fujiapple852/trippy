#![warn(clippy::all, clippy::pedantic, clippy::nursery, rust_2018_idioms)]
#![allow(
    clippy::module_name_repetitions,
    clippy::option_if_let_else,
    clippy::missing_const_for_fn,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
#![forbid(unsafe_code)]

use crate::backend::Trace;
use crate::dns::DnsResolver;
use crate::icmp::IcmpTracerConfig;
use clap::Parser;
use config::Args;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::process::exit;
use std::sync::Arc;
use std::thread;

mod backend;
mod config;
mod dns;
mod frontend;
mod icmp;

/// The maximum number of hops we allow.
pub const MAX_HOPS: usize = 256;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let hostname = args.hostname;
    let first_ttl = args.first_ttl;
    let max_ttl = args.max_ttl;
    let max_inflight = args.max_inflight;
    let read_timeout = humantime::parse_duration(&args.read_timeout)?;
    let min_round_duration = humantime::parse_duration(&args.min_round_duration)?;
    let max_round_duration = humantime::parse_duration(&args.max_round_duration)?;
    let grace_duration = humantime::parse_duration(&args.grace_duration)?;
    let preserve_screen = args.preserve_screen;

    if min_round_duration > max_round_duration {
        eprintln!(
            "max_round_duration ({:?}) must not be less than min_round_duration ({:?})",
            max_round_duration, min_round_duration
        );
        exit(-1);
    }

    let resolver = DnsResolver::new();
    let trace_data = Arc::new(RwLock::new(Trace::default()));
    let target_addr: IpAddr = resolver.lookup(&hostname)?[0];
    let trace_identifier = u16::try_from(std::process::id() % u32::from(u16::MAX))?;
    let tracer_config = IcmpTracerConfig::new(
        target_addr,
        trace_identifier,
        first_ttl,
        max_ttl,
        grace_duration,
        max_inflight,
        read_timeout,
        min_round_duration,
        max_round_duration,
    );

    // Run the backend on a separate thread
    {
        let trace_data = trace_data.clone();
        thread::spawn(move || backend::run_backend(&tracer_config, trace_data));
    }

    // Run the TUI on the main thread
    frontend::run_frontend(target_addr, &trace_data, preserve_screen)?;
    Ok(())
}
