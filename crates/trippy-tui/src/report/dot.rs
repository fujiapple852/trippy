use crate::app::TraceInfo;
use petgraph::dot::{Config, Dot};
use petgraph::graphmap::DiGraphMap;
use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, Ipv4Addr};
use tracing::instrument;
use trippy_core::FlowEntry;

/// Run a trace and generate a dot file.
#[instrument(skip_all, level = "trace")]
pub fn report(info: &TraceInfo, report_cycles: usize) -> anyhow::Result<()> {
    struct DotWrapper<'a>(Dot<'a, &'a DiGraphMap<IpAddr, ()>>);
    impl Debug for DotWrapper<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            self.0.fmt(f)
        }
    }
    super::wait_for_round(&info.data, report_cycles)?;
    let trace = info.data.snapshot();
    let mut graph: DiGraphMap<IpAddr, ()> = DiGraphMap::new();
    for (flow, _id) in trace.flows() {
        for (fst, snd) in flow.entries.windows(2).map(|pair| (pair[0], pair[1])) {
            match (fst, snd) {
                (FlowEntry::Known(addr1), FlowEntry::Known(addr2)) => {
                    graph.add_edge(addr1, addr2, ());
                }
                (FlowEntry::Known(addr1), FlowEntry::Unknown) => {
                    graph.add_edge(addr1, IpAddr::V4(Ipv4Addr::UNSPECIFIED), ());
                }
                (FlowEntry::Unknown, FlowEntry::Known(addr2)) => {
                    graph.add_edge(IpAddr::V4(Ipv4Addr::UNSPECIFIED), addr2, ());
                }
                _ => {}
            }
        }
    }
    let dot = DotWrapper(Dot::with_config(&graph, &[Config::EdgeNoLabel]));
    print!("{dot:?}");
    Ok(())
}
