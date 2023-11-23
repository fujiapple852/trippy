use crate::backend::flows::FlowEntry;
use crate::backend::trace::Trace;
use crate::TraceInfo;
use anyhow::anyhow;
use comfy_table::presets::{ASCII_MARKDOWN, UTF8_FULL};
use comfy_table::{ContentArrangement, Table};
use itertools::Itertools;
use parking_lot::RwLock;
use petgraph::dot::{Config, Dot};
use petgraph::graphmap::DiGraphMap;
use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use trippy::dns::{DnsResolver, Resolver};
use trippy::tracing::Extension;

/// Generate a CSV report of trace data.
pub fn run_report_csv(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    let trace = wait_for_round(&info.data, report_cycles)?;
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

use report_types::*;

pub mod report_types {
    use crate::backend::trace::Hop;
    use serde::{Serialize, Serializer};
    use trippy::dns::Resolver;
    use trippy::tracing::{
        Extension, Extensions, MplsLabelStack, MplsLabelStackMember, UnknownExtension,
    };

    #[derive(Serialize)]
    pub struct Report {
        pub info: ReportInfo,
        pub hops: Vec<ReportHop>,
    }

    #[derive(Serialize)]
    pub struct ReportInfo {
        pub target: ReportHost,
    }

    #[derive(Serialize)]
    pub struct ReportHop {
        ttl: u8,
        hosts: Vec<ReportHost>,
        extensions: ReportExtensions,
        #[serde(serialize_with = "fixed_width")]
        loss_pct: f64,
        sent: usize,
        #[serde(serialize_with = "fixed_width")]
        last: f64,
        recv: usize,
        #[serde(serialize_with = "fixed_width")]
        avg: f64,
        #[serde(serialize_with = "fixed_width")]
        best: f64,
        #[serde(serialize_with = "fixed_width")]
        worst: f64,
        #[serde(serialize_with = "fixed_width")]
        stddev: f64,
    }

    impl<R: Resolver> From<(&'_ Hop, &'_ R)> for ReportHop {
        fn from((value, resolver): (&Hop, &R)) -> Self {
            let hosts: Vec<_> = value
                .addrs()
                .map(|ip| ReportHost {
                    ip: ip.to_string(),
                    hostname: resolver.reverse_lookup(*ip).to_string(),
                })
                .collect();
            let extensions = ReportExtensions::from(
                value
                    .extensions()
                    .map(ToOwned::to_owned)
                    .unwrap_or_default(),
            );
            Self {
                ttl: value.ttl(),
                hosts,
                extensions,
                loss_pct: value.loss_pct(),
                sent: value.total_sent(),
                last: value.last_ms().unwrap_or_default(),
                recv: value.total_recv(),
                avg: value.avg_ms(),
                best: value.best_ms().unwrap_or_default(),
                worst: value.worst_ms().unwrap_or_default(),
                stddev: value.stddev_ms(),
            }
        }
    }

    #[derive(Serialize)]
    pub struct ReportHost {
        pub ip: String,
        pub hostname: String,
    }

    // TODO flatten and rename structs/enums
    // TODO move report structs/enums to sub-module

    #[derive(Serialize)]
    pub struct ReportExtensions {
        pub extensions: Vec<ReportExtension>,
    }

    impl From<Extensions> for ReportExtensions {
        fn from(value: Extensions) -> Self {
            Self {
                extensions: value
                    .extensions
                    .into_iter()
                    .map(ReportExtension::from)
                    .collect(),
            }
        }
    }

    #[derive(Serialize)]
    pub enum ReportExtension {
        #[serde(rename = "unknown")]
        Unknown(ReportUnknownExtension),
        #[serde(rename = "mpls")]
        Mpls(ReportMplsLabelStack),
    }

    impl From<Extension> for ReportExtension {
        fn from(value: Extension) -> Self {
            match value {
                Extension::Unknown(unknown) => Self::Unknown(ReportUnknownExtension::from(unknown)),
                Extension::Mpls(mpls) => Self::Mpls(ReportMplsLabelStack::from(mpls)),
            }
        }
    }

    #[derive(Serialize)]
    pub struct ReportMplsLabelStack {
        pub members: Vec<ReportMplsLabelStackMember>,
    }

    impl From<MplsLabelStack> for ReportMplsLabelStack {
        fn from(value: MplsLabelStack) -> Self {
            Self {
                members: value
                    .members
                    .into_iter()
                    .map(ReportMplsLabelStackMember::from)
                    .collect(),
            }
        }
    }

    #[derive(Serialize)]
    pub struct ReportMplsLabelStackMember {
        pub label: u32,
        pub exp: u8,
        pub bos: u8,
        pub ttl: u8,
    }

    impl From<MplsLabelStackMember> for ReportMplsLabelStackMember {
        fn from(value: MplsLabelStackMember) -> Self {
            Self {
                label: value.label,
                exp: value.exp,
                bos: value.bos,
                ttl: value.ttl,
            }
        }
    }

    #[derive(Serialize)]
    pub struct ReportUnknownExtension {
        pub class_num: u8,
        pub class_subtype: u8,
        pub bytes: Vec<u8>,
    }

    impl From<UnknownExtension> for ReportUnknownExtension {
        fn from(value: UnknownExtension) -> Self {
            Self {
                class_num: value.class_num,
                class_subtype: value.class_subtype,
                bytes: value.bytes,
            }
        }
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn fixed_width<S>(val: &f64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("{val:.2}"))
    }
}

/// Generate a json report of trace data.
pub fn run_report_json(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    let trace = wait_for_round(&info.data, report_cycles)?;
    let hops: Vec<ReportHop> = trace
        .hops(Trace::default_flow_id())
        .iter()
        .map(|hop| ReportHop::from((hop, resolver)))
        .collect();
    let report = Report {
        info: ReportInfo {
            target: ReportHost {
                ip: info.target_addr.to_string(),
                hostname: info.target_hostname.to_string(),
            },
        },
        hops,
    };
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    Ok(())
}

/// Generate a markdown table report of trace data.
pub fn run_report_table_md(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    run_report_table(info, report_cycles, resolver, ASCII_MARKDOWN)
}

/// Generate a pretty table report of trace data.
pub fn run_report_table_pretty(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    run_report_table(info, report_cycles, resolver, UTF8_FULL)
}

fn run_report_table(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
    preset: &str,
) -> anyhow::Result<()> {
    let trace = wait_for_round(&info.data, report_cycles)?;
    let columns = vec![
        "Hop", "IPs", "Addrs", "Loss%", "Snt", "Recv", "Last", "Avg", "Best", "Wrst", "StdDev",
    ];
    let mut table = Table::new();
    table
        .load_preset(preset)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(columns);
    for hop in trace.hops(Trace::default_flow_id()) {
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

/// Display a continuous stream of trace data.
pub fn run_report_stream(info: &TraceInfo) -> anyhow::Result<()> {
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
                        Extension::Unknown(unknown) => {
                            format!(
                                "unknown(class={}, subtype={}, bytes=[{:02x}])",
                                unknown.class_num,
                                unknown.class_subtype,
                                unknown.bytes.iter().format(" ")
                            )
                        }
                        Extension::Mpls(mpls) => {
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

/// Run a trace without generating any output.
pub fn run_report_silent(info: &TraceInfo, report_cycles: usize) -> anyhow::Result<()> {
    wait_for_round(&info.data, report_cycles)?;
    Ok(())
}

/// Run a trace and generate a dot file.
pub fn run_report_dot(info: &TraceInfo, report_cycles: usize) -> anyhow::Result<()> {
    struct DotWrapper<'a>(Dot<'a, &'a DiGraphMap<IpAddr, ()>>);
    impl Debug for DotWrapper<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            self.0.fmt(f)
        }
    }
    wait_for_round(&info.data, report_cycles)?;
    let trace = info.data.read().clone();
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

/// Run a trace and report all flows observed.
pub fn run_report_flows(info: &TraceInfo, report_cycles: usize) -> anyhow::Result<()> {
    wait_for_round(&info.data, report_cycles)?;
    let trace = info.data.read().clone();
    for (flow, flow_id) in trace.flows() {
        println!("flow {flow_id}: {flow}");
    }
    Ok(())
}

/// Block until trace data for round `round` is available.
fn wait_for_round(trace_data: &Arc<RwLock<Trace>>, report_cycles: usize) -> anyhow::Result<Trace> {
    let mut trace = trace_data.read().clone();
    while trace.round(Trace::default_flow_id()).is_none()
        || trace.round(Trace::default_flow_id()) < Some(report_cycles - 1)
    {
        trace = trace_data.read().clone();
        if let Some(err) = trace.error() {
            return Err(anyhow!("error: {}", err));
        }
        sleep(Duration::from_millis(100));
    }
    Ok(trace)
}
