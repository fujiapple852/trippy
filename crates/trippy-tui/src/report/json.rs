use crate::app::TraceInfo;
use crate::report::types::{Hop, Host, Info, Report};
use tracing::instrument;
use trippy_dns::Resolver;

/// Generate a json report of trace data.
#[instrument(skip_all, level = "trace")]
pub fn report<R: Resolver>(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &R,
    privacy_max_ttl: Option<u8>,
) -> anyhow::Result<()> {
    let start_timestamp = chrono::Utc::now();
    let trace = super::wait_for_round(&info.data, report_cycles)?;
    let end_timestamp = chrono::Utc::now();
    let hops: Vec<Hop> = trace
        .hops()
        .iter()
        .map(|hop| {
            if privacy_max_ttl >= Some(hop.ttl()) {
                Hop::private(hop)
            } else {
                Hop::from((hop, resolver))
            }
        })
        .collect();
    let report = Report {
        info: Info {
            target: Host {
                ip: Some(info.data.target_addr()),
                hostname: info.target_hostname.clone(),
            },
            start_timestamp,
            end_timestamp,
        },
        hops,
    };
    serde_json::to_writer_pretty(std::io::stdout(), &report)?;
    Ok(())
}
