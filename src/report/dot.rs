use crate::backend::flows::{Flow, FlowEntry, FlowId};
use crate::TraceInfo;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr};
use trippy::dns::{AsInfo, DnsEntry, DnsResolver, Resolved, Resolver, Unresolved};

/// Run a trace and generate a dot file.
pub fn report(
    info: &TraceInfo,
    report_cycles: usize,
    resolver: &DnsResolver,
) -> anyhow::Result<()> {
    let mut next_id = 0;
    let mut nodes: HashMap<IpAddr, Node> = HashMap::new();
    let mut edges: HashMap<(usize, usize), Edge> = HashMap::new();
    super::wait_for_round(&info.data, report_cycles)?;
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
        FlowEntry::Known(addr) => *nodes
            .entry(addr)
            .or_insert_with(|| create_node(next_id, addr, resolver))
            .id(),
        FlowEntry::Unknown => *nodes
            .entry(UNSPECIFIED_IP)
            .or_insert_with(|| create_unknown_node(next_id))
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
fn create_node(next_id: &mut usize, addr: IpAddr, resolver: &DnsResolver) -> Node {
    let id = *next_id;
    *next_id += 1;

    let entry = resolver.reverse_lookup_with_asinfo(addr);
    let (addr, names, as_info) = match entry {
        DnsEntry::Resolved(Resolved::WithAsInfo(addr, names, as_info)) => (addr, names, as_info),
        DnsEntry::Resolved(Resolved::Normal(addr, names)) => (addr, names, AsInfo::default()),
        DnsEntry::NotFound(Unresolved::WithAsInfo(addr, as_info)) => {
            (addr, vec![String::from("unknown")], as_info)
        }
        _ => (addr, vec![String::from("unknown")], AsInfo::default()),
    };

    Node {
        id,
        addr,
        names,
        as_info,
    }
}

fn create_unknown_node(next_id: &mut usize) -> Node {
    let id = *next_id;
    *next_id += 1;

    Node {
        id,
        addr: UNSPECIFIED_IP,
        names: vec![String::from("unknown")],
        as_info: AsInfo::default(),
    }
}
