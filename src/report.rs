use crate::{DnsResolver, Trace};
use itertools::Itertools;
use parking_lot::RwLock;
use serde::{Serialize, Serializer};
use std::net::IpAddr;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

/// Generate a CSV report of trace data.
pub fn run_report_csv(
    hostname: &str,
    target_addr: IpAddr,
    report_cycles: usize,
    trace_data: &Arc<RwLock<Trace>>,
) {
    let mut resolver = DnsResolver::default();
    let trace = wait_for_round(trace_data, report_cycles);
    println!("Target,TargetIp,Hop,Addrs,Loss%,Snt,Recv,Last,Avg,Best,Wrst,StdDev,");
    for hop in trace.hops().iter() {
        let ttl = hop.ttl();
        let hosts = hop
            .addrs()
            .map(|ip| resolver.reverse_lookup(*ip).to_string())
            .join(":");
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
            hostname, target_addr, ttl, host, loss_pct, sent, recv, last, avg, best, worst, stddev
        );
    }
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
    hostname: &str,
    target_addr: IpAddr,
    report_cycles: usize,
    trace_data: &Arc<RwLock<Trace>>,
) {
    let mut resolver = DnsResolver::default();
    let trace = wait_for_round(trace_data, report_cycles);
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
                ip: target_addr.to_string(),
                hostname: hostname.to_string(),
            },
        },
        hops,
    };
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

/// Display a continuous stream of tracing data.
pub fn run_report_stream(
    hostname: &str,
    target_addr: IpAddr,
    interval: Duration,
    trace_data: &Arc<RwLock<Trace>>,
) {
    println!("Tracing to {} ({})", hostname, target_addr);
    loop {
        let trace_data = trace_data.read().clone();
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
        sleep(interval);
    }
}

/// Block until trace data for round `round` is available.
fn wait_for_round(trace_data: &Arc<RwLock<Trace>>, round: usize) -> Trace {
    let mut trace = trace_data.read().clone();
    while trace.round() < round - 1 {
        trace = trace_data.read().clone();
        sleep(Duration::from_millis(100));
    }
    trace
}
