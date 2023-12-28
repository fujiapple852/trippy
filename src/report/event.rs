use crate::backend::flows::FlowId;
use crate::backend::trace::{Hop, Trace};
use crate::TraceInfo;
use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::thread::sleep;
use trippy::dns::Resolver;
use uuid::Uuid;

/// Display a continuous stream of trace events.
pub fn report<R: Resolver>(info: &TraceInfo, resolver: &R) -> anyhow::Result<()> {
    let mut producer = EventProducer::new(resolver);
    loop {
        let trace_data = &info.data.read().clone();
        let events = producer.produce(trace_data, info);
        for event in &events {
            emit_event(event);
        }
        if producer.state.failed {
            return Err(anyhow!("failed"));
        }
        sleep(info.min_round_duration);
    }
}

/// The state of the world.
#[derive(Debug)]
struct EventProducer<'a, R> {
    /// Dns resolver.
    resolver: &'a R,
    /// Tracing state.
    state: State,
}

impl<'a, R: Resolver> EventProducer<'a, R> {
    pub fn new(resolver: &'a R) -> Self {
        Self {
            resolver,
            state: State::new(),
        }
    }

    /// Update state from latest trace and return events.
    pub fn produce(&mut self, trace: &Trace, info: &TraceInfo) -> Vec<Event> {
        let mut events = vec![];
        events.extend(self.started_event(info));
        events.extend(self.failed_event(trace));
        events.extend(self.round_completed_event(trace));
        events.extend(self.flow_discovered_event(trace));
        events.extend(self.host_discovered_event(trace));
        events
    }

    /// TODO
    fn started_event(&mut self, info: &TraceInfo) -> Vec<Event> {
        if self.state.started {
            vec![]
        } else {
            self.state.started = true;
            vec![Event::new(EventData::Started(Started::new(
                info.target_hostname.clone(),
                info.target_addr,
            )))]
        }
    }

    /// TODO
    fn failed_event(&mut self, trace: &Trace) -> Vec<Event> {
        if let Some(err) = trace.error() {
            self.state.failed = true;
            vec![Event::new(EventData::Failed(Failed::new(err.to_string())))]
        } else {
            vec![]
        }
    }

    #[allow(clippy::unused_self)]
    fn round_completed_event(&mut self, trace: &Trace) -> Vec<Event> {
        vec![Event::new(EventData::RoundCompleted(RoundCompleted::new(
            trace.round_count(Trace::default_flow_id()),
        )))]
    }

    fn flow_discovered_event(&mut self, trace: &Trace) -> Vec<Event> {
        let all_flow_ids = trace
            .flows()
            .iter()
            .map(|(_, flow_id)| flow_id)
            .copied()
            .collect::<HashSet<FlowId>>();
        let events = self
            .state
            .flow_ids
            .symmetric_difference(&all_flow_ids)
            .map(|flow_id| Event::new(EventData::FlowDiscovered(FlowDiscovered::new(flow_id.0))))
            .collect();
        self.state.flow_ids = all_flow_ids;
        events
    }

    fn host_discovered_event(&mut self, trace: &Trace) -> Vec<Event> {
        let all_hosts = trace
            .hops(Trace::default_flow_id())
            .iter()
            .flat_map(Hop::addrs)
            .map(ToOwned::to_owned)
            .collect::<HashSet<IpAddr>>();
        let events = self
            .state
            .hosts
            .symmetric_difference(&all_hosts)
            .map(|addr| {
                Event::new(EventData::HostDiscovered(HostDiscovered::new(
                    *addr,
                    self.resolver.reverse_lookup(*addr).to_string(),
                )))
            })
            .collect();
        self.state.hosts = all_hosts;
        events
    }
}

#[derive(Debug)]
struct State {
    pub started: bool,
    pub failed: bool,
    pub flow_ids: HashSet<FlowId>,
    pub hosts: HashSet<IpAddr>,
}

impl State {
    pub fn new() -> Self {
        Self {
            started: false,
            failed: false,
            flow_ids: HashSet::new(),
            hosts: HashSet::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct Event {
    id: Uuid,
    timestamp: DateTime<Utc>,
    #[serde(flatten)]
    data: EventData,
}

impl Event {
    fn new(data: EventData) -> Self {
        Self {
            id: Self::make_id(),
            timestamp: Self::make_timestamp(),
            data,
        }
    }

    fn make_id() -> Uuid {
        Uuid::now_v7()
    }

    fn make_timestamp() -> DateTime<Utc> {
        chrono::Utc::now()
    }
}

#[derive(Debug, Serialize)]
enum EventData {
    /// Tracing has started.
    ///
    /// Emitted exactly once on startup.
    Started(Started),

    /// A tracing round has finished.
    ///
    /// Emitted once per round of tracing.
    RoundCompleted(RoundCompleted),

    /// A host has been discovered.
    ///
    /// Emitted once for every host discovered during tracing.
    HostDiscovered(HostDiscovered),

    /// A flow has been discovered.
    ///
    /// Emitted once for every flow discovered during tracing.
    FlowDiscovered(FlowDiscovered),

    /// Tracing has failed.
    ///
    /// Emitted at most once if tracing fails.
    Failed(Failed),
}

/// TODO would include all tracing parameters
#[derive(Debug, Serialize)]
struct Started {
    target_hostname: String,
    target_addr: IpAddr,
}

impl Started {
    pub fn new(target_hostname: String, target_addr: IpAddr) -> Self {
        Self {
            target_hostname,
            target_addr,
        }
    }
}

#[derive(Debug, Serialize)]
struct Failed {
    err: String,
}

impl Failed {
    pub fn new(err: String) -> Self {
        Self { err }
    }
}

/// TODO all the usual per-round info
#[derive(Debug, Serialize)]
struct RoundCompleted {
    round_count: usize,
}

impl RoundCompleted {
    pub fn new(round_count: usize) -> Self {
        Self { round_count }
    }
}

#[derive(Debug, Serialize)]
struct HostDiscovered {
    addr: IpAddr,
    hostname: String,
}

impl HostDiscovered {
    pub fn new(addr: IpAddr, hostname: String) -> Self {
        Self { addr, hostname }
    }
}

#[derive(Debug, Serialize)]
struct FlowDiscovered {
    flow_id: u64,
}

impl FlowDiscovered {
    pub fn new(flow_id: u64) -> Self {
        Self { flow_id }
    }
}

fn emit_event(event: &Event) {
    println!("{}", serde_json::to_string(event).unwrap());
}
