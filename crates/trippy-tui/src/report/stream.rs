use crate::app::TraceInfo;
use crate::report::types::Hop;
use anyhow::anyhow;
use std::thread::sleep;
use tracing::instrument;
use trippy_dns::Resolver;

/// Display a continuous stream of trace data.
#[instrument(skip_all, level = "trace")]
pub fn report<R: Resolver>(info: &TraceInfo, resolver: &R) -> anyhow::Result<()> {
    println!(
        "Tracing to {} ({})",
        info.target_hostname,
        info.data.target_addr()
    );
    loop {
        let trace_data = &info.data.snapshot();
        if let Some(err) = trace_data.error() {
            return Err(anyhow!("error: {}", err));
        }
        for hop in trace_data.hops() {
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
        sleep(info.data.min_round_duration());
    }
}
