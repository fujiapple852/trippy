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
use crate::config::{
    validate_grace_duration, validate_max_inflight, validate_read_timeout, validate_report_cycles,
    validate_round_duration, validate_ttl, validate_tui_refresh_rate, Mode,
};
use crate::dns::DnsResolver;
use crate::icmp::IcmpTracerConfig;
use crate::report::{run_report_csv, run_report_json, run_report_stream};
use clap::Parser;
use config::Args;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;

mod backend;
mod config;
mod dns;
mod frontend;
mod icmp;
mod report;

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
    let preserve_screen = args.tui_preserve_screen;
    let tui_refresh_rate = humantime::parse_duration(&args.tui_refresh_rate)?;
    let report_cycles = args.report_cycles;
    validate_ttl(first_ttl, max_ttl);
    validate_max_inflight(max_inflight);
    validate_read_timeout(read_timeout);
    validate_round_duration(min_round_duration, max_round_duration);
    validate_grace_duration(read_timeout, grace_duration);
    validate_tui_refresh_rate(tui_refresh_rate);
    validate_report_cycles(report_cycles);
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
        thread::Builder::new()
            .name("backend".into())
            .spawn(move || {
                backend::run_backend(&tracer_config, trace_data).expect("backend failed")
            })?;
    }

    match args.mode {
        Mode::Tui => {
            frontend::run_frontend(
                hostname,
                target_addr,
                &trace_data,
                tracer_config,
                tui_refresh_rate,
                preserve_screen,
            )?;
        }
        Mode::Stream => run_report_stream(&hostname, target_addr, min_round_duration, &trace_data),
        Mode::Csv => run_report_csv(&hostname, target_addr, report_cycles, &trace_data),
        Mode::Json => run_report_json(&hostname, target_addr, report_cycles, &trace_data),
        Mode::Table => todo!(),
    }

    Ok(())
}
