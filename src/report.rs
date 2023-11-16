use crate::backend::trace::Trace;
use crate::TraceInfo;
use anyhow::anyhow;
use comfy_table::presets::{ASCII_MARKDOWN, UTF8_FULL};
use comfy_table::{ContentArrangement, Table};
use itertools::Itertools;
use parking_lot::RwLock;
use serde::{Serialize, Serializer};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use trippy::dns::{DnsResolver, Resolver};

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

#[derive(Serialize)]
pub struct Report {
    pub info: ReportInfo,
    pub hops: Vec<ReportHop>,
}

#[derive(Serialize)]
pub struct ReportInfo {
    pub target: Host,
}

#[derive(Serialize)]
pub struct ReportHop {
    ttl: u8,
    hosts: Vec<Host>,
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

#[derive(Serialize)]
pub struct Host {
    pub ip: String,
    pub hostname: String,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn fixed_width<S>(val: &f64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{val:.2}"))
}

/// Generate a CSV report of trace data.
pub fn run_report_json(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    let trace = wait_for_round(&info.data, report_cycles)?;
    let hops: Vec<ReportHop> = trace
        .hops(Trace::default_flow_id())
        .iter()
        .map(|hop| {
            let hosts: Vec<_> = hop
                .addrs()
                .map(|ip| Host {
                    ip: ip.to_string(),
                    hostname: resolver.reverse_lookup(*ip).to_string(),
                })
                .collect();
            ReportHop {
                ttl: hop.ttl(),
                hosts,
                loss_pct: hop.loss_pct(),
                sent: hop.total_sent(),
                last: hop.last_ms().unwrap_or_default(),
                recv: hop.total_recv(),
                avg: hop.avg_ms(),
                best: hop.best_ms().unwrap_or_default(),
                worst: hop.worst_ms().unwrap_or_default(),
                stddev: hop.stddev_ms(),
            }
        })
        .collect();

    let report = Report {
        info: ReportInfo {
            target: Host {
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
                "ttl={ttl} addrs={addrs:?} loss_pct={loss_pct:.1}, sent={sent} recv={recv} last={last} best={best} worst={worst} avg={avg:.1} stddev={stddev:.1}"
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

pub use dot::run_report_dot;

pub mod dot {
    use crate::backend::flows::{Flow, FlowEntry, FlowId, Ttl};
    use crate::report::wait_for_round;
    use crate::TraceInfo;
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr};
    use trippy::dns::{AsInfo, DnsEntry, DnsResolver, Resolved, Resolver, Unresolved};

    /// Run a trace and generate a dot file.
    pub fn run_report_dot(
        info: &TraceInfo,
        report_cycles: usize,
        resolver: &DnsResolver,
    ) -> anyhow::Result<()> {
        let mut next_id = 0;
        let mut nodes: HashMap<IpAddr, Node> = HashMap::new();
        let mut edges: HashMap<(usize, usize), Edge> = HashMap::new();
        wait_for_round(&info.data, report_cycles)?;
        let trace = info.data.read().clone();
        for (flow, flow_id) in trace.flows() {
            process_flow_entries(
                &mut nodes,
                &mut edges,
                flow,
                *flow_id,
                &mut next_id,
                resolver,
            );
        }
        generate_dot_graph(&nodes, &edges);
        Ok(())
    }

    fn create_or_get_node_id(
        nodes: &mut HashMap<IpAddr, Node>,
        entry: FlowEntry,
        next_id: &mut usize,
        resolver: &DnsResolver,
    ) -> usize {
        match entry {
            FlowEntry::Known(ttl, addr) => *nodes
                .entry(addr)
                .or_insert_with(|| create_node(next_id, ttl, addr, resolver))
                .id(),
            FlowEntry::Unknown(ttl) => *nodes
                .entry(UNSPECIFIED_IP)
                .or_insert_with(|| create_unknown_node(next_id, ttl))
                .id(),
        }
    }

    fn process_flow_entries(
        nodes: &mut HashMap<IpAddr, Node>,
        edges: &mut HashMap<(usize, usize), Edge>,
        flow: &Flow,
        flow_id: FlowId,
        next_id: &mut usize,
        resolver: &DnsResolver,
    ) {
        for window in flow.entries.windows(2) {
            if let [fst, snd] = *window {
                let fst_id = create_or_get_node_id(nodes, fst, next_id, resolver);
                let snd_id = create_or_get_node_id(nodes, snd, next_id, resolver);
                edges
                    .entry((fst_id, snd_id))
                    .or_insert_with(|| Edge::new(fst_id, snd_id))
                    .value
                    .insert(flow_id);
            }
        }
    }

    fn generate_dot_graph(nodes: &HashMap<IpAddr, Node>, edges: &HashMap<(usize, usize), Edge>) {
        println!("digraph {{");
        println!("    node [shape=plaintext]");
        for node in nodes.values() {
            println!("    {} [ label = {} ]", node.id, node.to_label_string());
        }
        for edge in edges.values() {
            println!(
                "    {} -> {} [ label = \"[{}]\" ]",
                edge.from,
                edge.to,
                edge.to_label_string()
            );
        }
        println!("}}");
    }

    const UNSPECIFIED_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    #[derive(Debug, Clone)]
    struct Node {
        id: usize,
        addr: IpAddr,
        _ttl: Ttl,
        names: Vec<String>,
        as_info: AsInfo,
    }

    impl Node {
        fn id(&self) -> &usize {
            &self.id
        }

        fn to_label_string(&self) -> String {
            let as_label = if self.as_info.asn.is_empty() {
                "n/a".to_string()
            } else {
                format!("AS{}", self.as_info.asn)
            };

            format!(
                r#"<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4"><tr><td>{}</td><td>{}</td></tr><tr><td COLSPAN="2">{}</td></tr></TABLE>>"#,
                self.addr,
                as_label,
                self.names.join(", ")
            )
        }
    }

    #[derive(Debug, Clone)]
    struct Edge {
        from: usize,
        to: usize,
        value: HashSet<FlowId>,
    }

    impl Edge {
        fn new(from: usize, to: usize) -> Self {
            Self {
                from,
                to,
                value: HashSet::new(),
            }
        }

        fn to_label_string(&self) -> String {
            self.value
                .iter()
                .map(|flow_id| flow_id.0.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    }

    // Utility functions to create nodes
    fn create_node(next_id: &mut usize, ttl: Ttl, addr: IpAddr, resolver: &DnsResolver) -> Node {
        let id = *next_id;
        *next_id += 1;

        let entry = resolver.reverse_lookup_with_asinfo(addr);
        let (addr, names, as_info) = match entry {
            DnsEntry::Resolved(Resolved::WithAsInfo(addr, names, as_info)) => {
                (addr, names, as_info)
            }
            DnsEntry::Resolved(Resolved::Normal(addr, names)) => (addr, names, AsInfo::default()),
            DnsEntry::NotFound(Unresolved::WithAsInfo(addr, as_info)) => {
                (addr, vec![String::from("unknown")], as_info)
            }
            _ => (addr, vec![String::from("unknown")], AsInfo::default()),
        };

        Node {
            id,
            addr,
            _ttl: ttl,
            names,
            as_info,
        }
    }

    fn create_unknown_node(next_id: &mut usize, ttl: Ttl) -> Node {
        let id = *next_id;
        *next_id += 1;

        Node {
            id,
            addr: UNSPECIFIED_IP,
            _ttl: ttl,
            names: vec![String::from("unknown")],
            as_info: AsInfo::default(),
        }
    }
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
