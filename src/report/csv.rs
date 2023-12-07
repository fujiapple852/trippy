use crate::backend::trace::Trace;
use crate::frontend::TuiConfig;
use crate::{backend, TraceInfo};
use itertools::Itertools;
use serde::Serialize;
use std::net::IpAddr;
use trippy::dns::Resolver;

/// Generate a CSV report of trace data with optional costom columns.
pub fn report<R: Resolver>(
    info: &TraceInfo,
    tui_config: &TuiConfig,
    report_cycles: usize,
    resolver: &R,
) -> anyhow::Result<()> {
    let trace = super::wait_for_round(&info.data, report_cycles)?;
    let mut writer = csv::Writer::from_writer(std::io::stdout());
    let custom_columns = &tui_config.csv_custom_columns;
    let columns = custom_columns
        .iter()
        .map(|c| Column::new_short(*c))
        .collect_vec();
    columns
        .iter()
        .map(|ch| writer.write_field(ch.display))
        .collect_vec();
    writer.write_record(None::<&[u8]>)?;
    writer.flush()?;
    for hop in trace.hops(Trace::default_flow_id()) {
        let row = CsvRow::new(&info.target_hostname, info.target_addr, hop, resolver);
        columns
            .iter()
            .map(|c| {
                let _ = writer.write_field(write_cell(c, &row));
            })
            .collect_vec();
        writer.write_record(None::<&[u8]>)?;
        writer.flush()?;
    }
    Ok(())
}
///Return the String value for the current column
fn write_cell(column: &Column, row: &CsvRow) -> String {
    match column.short {
        'G' => row.target_hostname.clone(),
        'I' => row.target_addr.to_string(),
        'H' => row.ttl.to_string(),
        'O' => row.ip.clone(),
        'T' => row.host.clone(),
        'L' => row.loss.clone(),
        'S' => row.sent.to_string(),
        'R' => row.recv.to_string(),
        'A' => row.last.clone(),
        'V' => row.avg.clone(),
        'B' => row.best.clone(),
        'W' => row.worst.clone(),
        'D' => row.stddev.clone(),
        _ => todo!(),
    }
}
#[derive(Serialize, Debug)]
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
    pub loss: String,
    #[serde(rename = "Snt")]
    pub sent: usize,
    #[serde(rename = "Recv")]
    pub recv: usize,
    #[serde(rename = "Last")]
    pub last: String,
    #[serde(rename = "Avg")]
    pub avg: String,
    #[serde(rename = "Best")]
    pub best: String,
    #[serde(rename = "Wrst")]
    pub worst: String,
    #[serde(rename = "StdDev")]
    pub stddev: String,
}
impl CsvRow {
    fn new<R: Resolver>(
        target: &str,
        target_addr: IpAddr,
        hop: &backend::trace::Hop,
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
        let stddev = format!("{:.1}", hop.stddev_ms());
        let avg = format!("{:.1}", hop.avg_ms());
        let loss = format!("{:.2}", hop.loss_pct());

        Self {
            target_hostname: String::from(target),
            target_addr,
            ttl,
            ip,
            host,
            loss,
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
#[derive(Debug, Clone)]
pub struct Column {
    pub display: &'static str,
    pub short: char,
}
impl Column {
    pub fn new(display: &'static str, short: char) -> Self {
        Self { display, short }
    }
    pub fn new_short(short: char) -> Self {
        match short {
            'G' => Self::new(DEFAULT_HEADING_TARG, short),
            'I' => Self::new(DEFAULT_HEADING_TAIP, short),
            'H' => Self::new(DEFAULT_HEADING_HOPS, short),
            'O' => Self::new(DEFAULT_HEADING_HOST, short),
            'T' => Self::new(DEFAULT_HEADING_ADDR, short),
            'L' => Self::new(DEFAULT_HEADING_LOSS, short),
            'S' => Self::new(DEFAULT_HEADING_SENT, short),
            'R' => Self::new(DEFAULT_HEADING_RECV, short),
            'A' => Self::new(DEFAULT_HEADING_LAST, short),
            'V' => Self::new(DEFAULT_HEADING_AVG, short),
            'B' => Self::new(DEFAULT_HEADING_BEST, short),
            'W' => Self::new(DEFAULT_HEADING_WRST, short),
            'D' => Self::new(DEFAULT_HEADING_STDEV, short),
            _ => todo!(),
        }
    }
}

const DEFAULT_HEADING_TARG: &str = "Target";
const DEFAULT_HEADING_TAIP: &str = "TargetIp";
const DEFAULT_HEADING_HOPS: &str = "Hop";
const DEFAULT_HEADING_HOST: &str = "IPs";
const DEFAULT_HEADING_ADDR: &str = "Addr";
const DEFAULT_HEADING_LOSS: &str = "Loss%";
const DEFAULT_HEADING_SENT: &str = "Snt";
const DEFAULT_HEADING_RECV: &str = "Recv";
const DEFAULT_HEADING_LAST: &str = "Last";
const DEFAULT_HEADING_AVG: &str = "Avg";
const DEFAULT_HEADING_BEST: &str = "Best";
const DEFAULT_HEADING_WRST: &str = "Wrst";
const DEFAULT_HEADING_STDEV: &str = "StDev";
