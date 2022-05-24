use crate::{DnsResolver, Trace, TraceInfo};
use anyhow::anyhow;
use comfy_table::presets::{ASCII_MARKDOWN, UTF8_FULL};
use comfy_table::{ContentArrangement, Table};
use itertools::Itertools;
use parking_lot::RwLock;
use serde::{Serialize, Serializer};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

/// Generate a CSV report of trace data.
pub fn run_report_csv(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    let trace = wait_for_round(&info.data, report_cycles)?;
    println!("Target,TargetIp,Hop,Addrs,Loss%,Snt,Recv,Last,Avg,Best,Wrst,StdDev,");
    for hop in trace.hops().iter() {
        let ttl = hop.ttl();
        let hosts = hop.addrs().map(|ip| resolver.reverse_lookup(*ip)).join(":");
        let host = if hosts.is_empty() {
            String::from("???")
        } else {
            hosts
        };
        let sent = hop.total_sent();
        let recv = hop.total_recv();
        let last = hop
            .last_ms()
            .map_or_else(|| String::from("???"), |last| format!("{:.1}", last));
        let best = hop
            .best_ms()
            .map_or_else(|| String::from("???"), |best| format!("{:.1}", best));
        let worst = hop
            .worst_ms()
            .map_or_else(|| String::from("???"), |worst| format!("{:.1}", worst));
        let stddev = hop.stddev_ms();
        let avg = hop.avg_ms();
        let loss_pct = hop.loss_pct();
        println!(
            "{},{},{},{},{:.1}%,{},{},{},{:.1},{},{},{:.1}",
            info.target_hostname,
            info.target_addr,
            ttl,
            host,
            loss_pct,
            sent,
            recv,
            last,
            avg,
            best,
            worst,
            stddev
        );
    }
    Ok(())
}

#[derive(Serialize)]
pub struct Report {
    pub info: ReportInfo,
    pub hops: Vec<ReportHop>,
}

#[derive(Serialize)]
pub struct ReportInfo {
    pub target: Host,
}

#[derive(Serialize)]
pub struct ReportHop {
    ttl: u8,
    hosts: Vec<Host>,
    #[serde(serialize_with = "fixed_width")]
    loss_pct: f64,
    sent: usize,
    #[serde(serialize_with = "fixed_width")]
    last: f64,
    recv: usize,
    #[serde(serialize_with = "fixed_width")]
    avg: f64,
    #[serde(serialize_with = "fixed_width")]
    best: f64,
    #[serde(serialize_with = "fixed_width")]
    worst: f64,
    #[serde(serialize_with = "fixed_width")]
    stddev: f64,
}

#[derive(Serialize)]
pub struct Host {
    pub ip: String,
    pub hostname: String,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn fixed_width<S>(val: &f64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{:.2}", val))
}

/// Generate a CSV report of trace data.
pub fn run_report_json(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    let trace = wait_for_round(&info.data, report_cycles)?;
    let hops: Vec<ReportHop> = trace
        .hops()
        .iter()
        .map(|hop| {
            let hosts: Vec<_> = hop
                .addrs()
                .map(|ip| Host {
                    ip: ip.to_string(),
                    hostname: resolver.reverse_lookup(*ip).to_string(),
                })
                .collect();
            ReportHop {
                ttl: hop.ttl(),
                hosts,
                loss_pct: hop.loss_pct(),
                sent: hop.total_sent(),
                last: hop.last_ms().unwrap_or_default(),
                recv: hop.total_recv(),
                avg: hop.avg_ms(),
                best: hop.best_ms().unwrap_or_default(),
                worst: hop.worst_ms().unwrap_or_default(),
                stddev: hop.stddev_ms(),
            }
        })
        .collect();

    let report = Report {
        info: ReportInfo {
            target: Host {
                ip: info.target_addr.to_string(),
                hostname: info.target_hostname.to_string(),
            },
        },
        hops,
    };
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    Ok(())
}

/// Generate a markdown table report of trace data.
pub fn run_report_table_md(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    run_report_table(info, report_cycles, resolver, ASCII_MARKDOWN)
}

/// Generate a pretty table report of trace data.
pub fn run_report_table_pretty(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    run_report_table(info, report_cycles, resolver, UTF8_FULL)
}

fn run_report_table(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
    preset: &str,
) -> anyhow::Result<()> {
    let trace = wait_for_round(&info.data, report_cycles)?;
    let columns = vec![
        "Hop", "Addrs", "Loss%", "Snt", "Recv", "Last", "Avg", "Best", "Wrst", "StdDev",
    ];
    let mut table = Table::new();
    table
        .load_preset(preset)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(columns);
    for hop in trace.hops().iter() {
        let ttl = hop.ttl().to_string();
        let hosts = hop
            .addrs()
            .map(|ip| resolver.reverse_lookup(*ip).to_string())
            .join("\n");
        let host = if hosts.is_empty() {
            String::from("???")
        } else {
            hosts
        };
        let sent = hop.total_sent().to_string();
        let recv = hop.total_recv().to_string();
        let last = hop
            .last_ms()
            .map_or_else(|| String::from("???"), |last| format!("{:.1}", last));
        let best = hop
            .best_ms()
            .map_or_else(|| String::from("???"), |best| format!("{:.1}", best));
        let worst = hop
            .worst_ms()
            .map_or_else(|| String::from("???"), |worst| format!("{:.1}", worst));
        let stddev = format!("{:.1}", hop.stddev_ms());
        let avg = format!("{:.1}", hop.avg_ms());
        let loss_pct = format!("{:.1}", hop.loss_pct());
        table.add_row(vec![
            &ttl, &host, &loss_pct, &sent, &recv, &last, &avg, &best, &worst, &stddev,
        ]);
    }
    println!("{table}");
    Ok(())
}

/// Display a continuous stream of trace data.
pub fn run_report_stream(info: &TraceInfo) -> anyhow::Result<()> {
    println!("Tracing to {} ({})", info.target_hostname, info.target_addr);
    loop {
        let trace_data = &info.data.read().clone();
        if let Some(err) = trace_data.error() {
            return Err(anyhow!("error: {}", err));
        }
        for hop in trace_data.hops() {
            let ttl = hop.ttl();
            let addrs = hop.addrs().collect::<Vec<_>>();
            let sent = hop.total_sent();
            let recv = hop.total_recv();
            let last = hop
                .last_ms()
                .map(|last| format!("{:.1}", last))
                .unwrap_or_default();
            let best = hop
                .best_ms()
                .map(|best| format!("{:.1}", best))
                .unwrap_or_default();
            let worst = hop
                .worst_ms()
                .map(|worst| format!("{:.1}", worst))
                .unwrap_or_default();
            let stddev = hop.stddev_ms();
            let avg = hop.avg_ms();
            let loss_pct = hop.loss_pct();
            println!(
                "ttl={} addrs={:?} loss_pct={:.1}, sent={} recv={} last={} best={} worst={} avg={:.1} stddev={:.1}",
                ttl, addrs, loss_pct, sent, recv, last, best, worst, avg, stddev
            );
        }
        sleep(info.min_round_duration);
    }
}

/// Block until trace data for round `round` is available.
fn wait_for_round(trace_data: &Arc<RwLock<Trace>>, report_cycles: usize) -> anyhow::Result<Trace> {
    let mut trace = trace_data.read().clone();
    while trace.round().is_none() || trace.round() < Some(report_cycles - 1) {
        trace = trace_data.read().clone();
        if let Some(err) = trace.error() {
            return Err(anyhow!("error: {}", err));
        }
        sleep(Duration::from_millis(100));
    }
    Ok(trace)
}
