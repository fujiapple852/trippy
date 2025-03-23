use crate::app::TraceInfo;
use comfy_table::presets::{ASCII_MARKDOWN, UTF8_FULL};
use comfy_table::{ContentArrangement, Table};
use itertools::Itertools;
use tracing::instrument;
use trippy_dns::Resolver;

/// Generate a Markdown table report of trace data.
#[instrument(skip_all, level = "trace")]
pub fn report_md<R: Resolver>(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &R,
) -> anyhow::Result<()> {
    run_report_table(info, report_cycles, resolver, ASCII_MARKDOWN)
}

/// Generate a pretty table report of trace data.
#[instrument(skip_all, level = "trace")]
pub fn report_pretty<R: Resolver>(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &R,
) -> anyhow::Result<()> {
    run_report_table(info, report_cycles, resolver, UTF8_FULL)
}

fn run_report_table<R: Resolver>(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &R,
    preset: &str,
) -> anyhow::Result<()> {
    let trace = super::wait_for_round(&info.data, report_cycles)?;
    let columns = vec![
        "Hop", "IPs", "Addrs", "Loss%", "Snt", "Recv", "Last", "Avg", "Best", "Wrst", "StdDev",
    ];
    let mut table = Table::new();
    table
        .load_preset(preset)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(columns);
    for hop in trace.hops() {
        let ttl = hop.ttl().to_string();
        let ips = hop.addrs().join("\n");
        let ip = if ips.is_empty() {
            String::from("???")
        } else {
            ips
        };
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
            .map_or_else(|| String::from("???"), |last| format!("{last:.1}"));
        let best = hop
            .best_ms()
            .map_or_else(|| String::from("???"), |best| format!("{best:.1}"));
        let worst = hop
            .worst_ms()
            .map_or_else(|| String::from("???"), |worst| format!("{worst:.1}"));
        let stddev = format!("{:.1}", hop.stddev_ms());
        let avg = format!("{:.1}", hop.avg_ms());
        let loss_pct = format!("{:.1}", hop.loss_pct());
        table.add_row(vec![
            &ttl, &ip, &host, &loss_pct, &sent, &recv, &last, &avg, &best, &worst, &stddev,
        ]);
    }
    println!("{table}");
    Ok(())
}
