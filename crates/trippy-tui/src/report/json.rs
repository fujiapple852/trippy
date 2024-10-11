use crate::app::TraceInfo;
use crate::report::types::{Hop, Host, Info, Report};
use std::thread::JoinHandle;
use trippy_dns::Resolver;

/// Generate a json report of trace data.
pub fn report<R: Resolver>(
    info: &TraceInfo,
    handle: JoinHandle<trippy_core::Result<()>>,
    resolver: &R,
) -> anyhow::Result<()> {
    let trace = super::wait_for_round(&info.data, handle)?;
    let hops: Vec<Hop> = trace
        .hops()
        .iter()
        .map(|hop| Hop::from((hop, resolver)))
        .collect();
    let report = Report {
        info: Info {
            target: Host {
                ip: info.data.target_addr(),
                hostname: info.target_hostname.to_string(),
            },
        },
        hops,
    };
    Ok(serde_json::to_writer_pretty(std::io::stdout(), &report)?)
}
