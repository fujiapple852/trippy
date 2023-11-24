use crate::backend::trace::Trace;
use crate::TraceInfo;
use itertools::Itertools;
use trippy::dns::{DnsResolver, Resolver};

/// Generate a CSV report of trace data.
pub fn report(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    let trace = super::wait_for_round(&info.data, report_cycles)?;
    println!("Target,TargetIp,Hop,IPs,Addrs,Loss%,Snt,Recv,Last,Avg,Best,Wrst,StdDev,");
    for hop in trace.hops(Trace::default_flow_id()) {
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
