use crate::backend::trace::Trace;
use crate::report::types::{Hop, Host, Info, Report};
use crate::TraceInfo;
use trippy::dns::Resolver;

/// Generate a json report of trace data.
pub fn report<R: Resolver>(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &R,
) -> anyhow::Result<()> {
    let trace = super::wait_for_round(&info.data, report_cycles)?;
    let hops: Vec<Hop> = trace
        .hops(Trace::default_flow_id())
        .iter()
        .map(|hop| Hop::from((hop, resolver)))
        .collect();
    let report = Report {
        info: Info {
            target: Host {
                ip: info.target_addr,
                hostname: info.target_hostname.to_string(),
            },
        },
        hops,
    };
    Ok(serde_json::to_writer_pretty(std::io::stdout(), &report)?)
}
