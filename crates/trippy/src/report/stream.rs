use crate::backend::trace::Trace;
use crate::report::types::Hop;
use crate::TraceInfo;
use anyhow::anyhow;
use std::thread::sleep;
use trippy_dns::Resolver;

/// Display a continuous stream of trace data.
pub fn report<R: Resolver>(info: &TraceInfo, resolver: &R) -> anyhow::Result<()> {
    println!("Tracing to {} ({})", info.target_hostname, info.target_addr);
    loop {
        let trace_data = &info.data.read().clone();
        if let Some(err) = trace_data.error() {
            return Err(anyhow!("error: {}", err));
        }
        for hop in trace_data.hops(Trace::default_flow_id()) {
            let hop = Hop::from((hop, resolver));
            let ttl = hop.ttl;
            let addrs = hop.hosts.to_string();
            let exts = hop.extensions.to_string();
            let sent = hop.sent;
            let recv = hop.recv;
            let last = hop.last;
            let best = hop.best;
            let worst = hop.worst;
            let stddev = hop.stddev;
            let avg = hop.avg;
            let loss_pct = hop.loss_pct;
            println!(
                "ttl={ttl} addrs={addrs} exts={exts} loss_pct={loss_pct:.1} sent={sent} recv={recv} last={last:.1} best={best:.1} worst={worst:.1} avg={avg:.1} stddev={stddev:.1}"
            );
        }
        sleep(info.min_round_duration);
    }
}
