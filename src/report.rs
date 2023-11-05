use crate::{Trace, TraceInfo};
use anyhow::anyhow;
use comfy_table::presets::{ASCII_MARKDOWN, UTF8_FULL};
use comfy_table::{ContentArrangement, Table};
use itertools::Itertools;
use parking_lot::RwLock;
use serde::{Serialize, Serializer};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use trippy::dns::{DnsResolver, Resolver};

/// Generate a CSV report of trace data.
pub fn run_report_csv(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    let trace = wait_for_round(&info.data, report_cycles)?;
    println!("Target,TargetIp,Hop,IPs,Addrs,Loss%,Snt,Recv,Last,Avg,Best,Wrst,StdDev,");
    for hindex in trace.hop_range() {
        let ttl = trace.ttl(hindex);
        let ips = trace.addrs(hindex).join(":");
        let ip = if ips.is_empty() {
            String::from("???")
        } else {
            ips
        };
        let hosts = trace
            .addrs(hindex)
            .map(|ip| resolver.reverse_lookup(*ip))
            .join(":");
        let host = if hosts.is_empty() {
            String::from("???")
        } else {
            hosts
        };
        let sent = trace.total_sent(hindex);
        let recv = trace.total_recv(hindex);
        let last = trace
            .last_ms(hindex)
            .map_or_else(|| String::from("???"), |last| format!("{last:.1}"));
        let best = trace
            .best_ms(hindex)
            .map_or_else(|| String::from("???"), |best| format!("{best:.1}"));
        let worst = trace
            .worst_ms(hindex)
            .map_or_else(|| String::from("???"), |worst| format!("{worst:.1}"));
        let stddev = trace.stddev_ms(hindex);
        let avg = trace.avg_ms(hindex);
        let loss_pct = trace.loss_pct(hindex);
        println!(
            "{},{},{},{},{},{:.1}%,{},{},{},{:.1},{},{},{:.1}",
            info.target_hostname,
            info.target_addr,
            ttl,
            ip,
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
    serializer.serialize_str(&format!("{val:.2}"))
}

/// Generate a CSV report of trace data.
pub fn run_report_json(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    let trace = wait_for_round(&info.data, report_cycles)?;
    let hops: Vec<ReportHop> = trace
        .hop_range()
        .map(|hindex| {
            let hosts: Vec<_> = trace
                .addrs(hindex)
                .map(|ip| Host {
                    ip: ip.to_string(),
                    hostname: resolver.reverse_lookup(*ip).to_string(),
                })
                .collect();
            ReportHop {
                ttl: trace.ttl(hindex),
                hosts,
                loss_pct: trace.loss_pct(hindex),
                sent: trace.total_sent(hindex),
                last: trace.last_ms(hindex).unwrap_or_default(),
                recv: trace.total_recv(hindex),
                avg: trace.avg_ms(hindex),
                best: trace.best_ms(hindex).unwrap_or_default(),
                worst: trace.worst_ms(hindex).unwrap_or_default(),
                stddev: trace.stddev_ms(hindex),
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
        "Hop", "IPs", "Addrs", "Loss%", "Snt", "Recv", "Last", "Avg", "Best", "Wrst", "StdDev",
    ];
    let mut table = Table::new();
    table
        .load_preset(preset)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(columns);
    for hindex in trace.hop_range() {
        let ttl = trace.ttl(hindex).to_string();
        let ips = trace.addrs(hindex).join("\n");
        let ip = if ips.is_empty() {
            String::from("???")
        } else {
            ips
        };
        let hosts = trace
            .addrs(hindex)
            .map(|ip| resolver.reverse_lookup(*ip).to_string())
            .join("\n");
        let host = if hosts.is_empty() {
            String::from("???")
        } else {
            hosts
        };
        let sent = trace.total_sent(hindex).to_string();
        let recv = trace.total_recv(hindex).to_string();
        let last = trace
            .last_ms(hindex)
            .map_or_else(|| String::from("???"), |last| format!("{last:.1}"));
        let best = trace
            .best_ms(hindex)
            .map_or_else(|| String::from("???"), |best| format!("{best:.1}"));
        let worst = trace
            .worst_ms(hindex)
            .map_or_else(|| String::from("???"), |worst| format!("{worst:.1}"));
        let stddev = format!("{:.1}", trace.stddev_ms(hindex));
        let avg = format!("{:.1}", trace.avg_ms(hindex));
        let loss_pct = format!("{:.1}", trace.loss_pct(hindex));
        table.add_row(vec![
            &ttl, &ip, &host, &loss_pct, &sent, &recv, &last, &avg, &best, &worst, &stddev,
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
        for hindex in trace_data.hop_range() {
            let ttl = trace_data.ttl(hindex);
            let addrs = trace_data.addrs(hindex).collect::<Vec<_>>();
            let sent = trace_data.total_sent(hindex);
            let recv = trace_data.total_recv(hindex);
            let last = trace_data
                .last_ms(hindex)
                .map(|last| format!("{last:.1}"))
                .unwrap_or_default();
            let best = trace_data
                .best_ms(hindex)
                .map(|best| format!("{best:.1}"))
                .unwrap_or_default();
            let worst = trace_data
                .worst_ms(hindex)
                .map(|worst| format!("{worst:.1}"))
                .unwrap_or_default();
            let stddev = trace_data.stddev_ms(hindex);
            let avg = trace_data.avg_ms(hindex);
            let loss_pct = trace_data.loss_pct(hindex);
            println!(
                "ttl={ttl} addrs={addrs:?} loss_pct={loss_pct:.1}, sent={sent} recv={recv} last={last} best={best} worst={worst} avg={avg:.1} stddev={stddev:.1}"
            );
        }
        sleep(info.min_round_duration);
    }
}

/// Run a trace without generating any output.
pub fn run_report_silent(info: &TraceInfo, report_cycles: usize) -> anyhow::Result<()> {
    wait_for_round(&info.data, report_cycles)?;
    Ok(())
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
