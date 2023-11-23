use crate::backend::trace::Trace;
use crate::TraceInfo;
use anyhow::anyhow;
use itertools::Itertools;
use std::thread::sleep;

/// Display a continuous stream of trace data.
pub fn report(info: &TraceInfo) -> anyhow::Result<()> {
    println!("Tracing to {} ({})", info.target_hostname, info.target_addr);
    loop {
        let trace_data = &info.data.read().clone();
        if let Some(err) = trace_data.error() {
            return Err(anyhow!("error: {}", err));
        }
        for hop in trace_data.hops(Trace::default_flow_id()) {
            let ttl = hop.ttl();
            let addrs = hop.addrs().collect::<Vec<_>>();
            let exts = if let Some(ext) = hop.extensions() {
                ext.extensions
                    .iter()
                    .map(|ext| match ext {
                        trippy::tracing::Extension::Unknown(unknown) => {
                            format!(
                                "unknown(class={}, subtype={}, bytes=[{:02x}])",
                                unknown.class_num,
                                unknown.class_subtype,
                                unknown.bytes.iter().format(" ")
                            )
                        }
                        trippy::tracing::Extension::Mpls(mpls) => {
                            let labels = mpls.members.iter().map(|m| m.label).join(", ");
                            format!("mpls(labels={labels})")
                        }
                    })
                    .join("+")
            } else {
                String::from("none")
            };
            let sent = hop.total_sent();
            let recv = hop.total_recv();
            let last = hop
                .last_ms()
                .map(|last| format!("{last:.1}"))
                .unwrap_or_default();
            let best = hop
                .best_ms()
                .map(|best| format!("{best:.1}"))
                .unwrap_or_default();
            let worst = hop
                .worst_ms()
                .map(|worst| format!("{worst:.1}"))
                .unwrap_or_default();
            let stddev = hop.stddev_ms();
            let avg = hop.avg_ms();
            let loss_pct = hop.loss_pct();
            println!(
                "ttl={ttl} addrs={addrs:?} exts={exts}, loss_pct={loss_pct:.1}, sent={sent} recv={recv} last={last} best={best} worst={worst} avg={avg:.1} stddev={stddev:.1}"
            );
        }
        sleep(info.min_round_duration);
    }
}
