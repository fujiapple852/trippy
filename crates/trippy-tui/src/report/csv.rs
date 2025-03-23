use crate::app::TraceInfo;
use crate::report::types::fixed_width;
use itertools::Itertools;
use serde::Serialize;
use std::net::IpAddr;
use tracing::instrument;
use trippy_dns::Resolver;

/// Generate a CSV report of trace data.
#[instrument(skip_all, level = "trace")]
pub fn report<R: Resolver>(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &R,
) -> anyhow::Result<()> {
    let trace = super::wait_for_round(&info.data, report_cycles)?;
    let mut writer = csv::Writer::from_writer(std::io::stdout());
    for hop in trace.hops() {
        let row = CsvRow::new(
            &info.target_hostname,
            info.data.target_addr(),
            hop,
            resolver,
        );
        writer.serialize(row)?;
    }
    Ok(())
}

#[derive(Serialize)]
pub struct CsvRow {
    #[serde(rename = "Target")]
    pub target_hostname: String,
    #[serde(rename = "TargetIp")]
    pub target_addr: IpAddr,
    #[serde(rename = "Hop")]
    pub ttl: u8,
    #[serde(rename = "IPs")]
    pub ip: String,
    #[serde(rename = "Addrs")]
    pub host: String,
    #[serde(rename = "Loss%")]
    #[serde(serialize_with = "fixed_width")]
    pub loss_pct: f64,
    #[serde(rename = "Snt")]
    pub sent: usize,
    #[serde(rename = "Recv")]
    pub recv: usize,
    #[serde(rename = "Last")]
    pub last: String,
    #[serde(rename = "Avg")]
    #[serde(serialize_with = "fixed_width")]
    pub avg: f64,
    #[serde(rename = "Best")]
    pub best: String,
    #[serde(rename = "Wrst")]
    pub worst: String,
    #[serde(rename = "StdDev")]
    #[serde(serialize_with = "fixed_width")]
    pub stddev: f64,
}

impl CsvRow {
    fn new<R: Resolver>(
        target: &str,
        target_addr: IpAddr,
        hop: &trippy_core::Hop,
        resolver: &R,
    ) -> Self {
        let ttl = hop.ttl();
        let ips = hop.addrs().join(":");
        let ip = if ips.is_empty() {
            String::from("???")
        } else {
            ips
        };
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
            .map_or_else(|| String::from("???"), |last| format!("{last:.1}"));
        let best = hop
            .best_ms()
            .map_or_else(|| String::from("???"), |best| format!("{best:.1}"));
        let worst = hop
            .worst_ms()
            .map_or_else(|| String::from("???"), |worst| format!("{worst:.1}"));
        let stddev = hop.stddev_ms();
        let avg = hop.avg_ms();
        let loss_pct = hop.loss_pct();

        Self {
            target_hostname: String::from(target),
            target_addr,
            ttl,
            ip,
            host,
            loss_pct,
            sent,
            last,
            recv,
            avg,
            best,
            worst,
            stddev,
        }
    }
}
