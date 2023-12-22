use crate::backend::flows::{Flow, FlowId, FlowRegistry};
use crate::config::MAX_HOPS;
use indexmap::IndexMap;
use std::collections::HashMap;
use std::iter::once;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use trippy::tracing::{Extensions, Probe, ProbeStatus, TracerRound};

/// The state of all hops in a trace.
#[derive(Debug, Clone)]
pub struct Trace {
    max_samples: usize,
    /// The flow id for the current round.
    round_flow_id: FlowId,
    /// Tracing data per registered flow id.
    trace_data: HashMap<FlowId, TraceData>,
    /// Flow registry.
    registry: FlowRegistry,
    /// Tracing error message.
    error: Option<String>,
}

impl Trace {
    /// Create a new `Trace`.
    pub fn new(max_samples: usize) -> Self {
        Self {
            trace_data: once((Self::default_flow_id(), TraceData::new(max_samples)))
                .collect::<HashMap<FlowId, TraceData>>(),
            round_flow_id: Self::default_flow_id(),
            max_samples,
            registry: FlowRegistry::new(),
            error: None,
        }
    }

    /// Return the id of the default flow.
    pub fn default_flow_id() -> FlowId {
        FlowId(0)
    }

    /// Information about each hop for a given flow.
    pub fn hops(&self, flow_id: FlowId) -> &[Hop] {
        self.trace_data[&flow_id].hops()
    }

    /// Is a given `Hop` the target hop for a given flow?
    ///
    /// A `Hop` is considered to be the target if it has the highest `ttl` value observed.
    ///
    /// Note that if the target host does not respond to probes then the the highest `ttl` observed
    /// will be one greater than the `ttl` of the last host which did respond.
    pub fn is_target(&self, hop: &Hop, flow_id: FlowId) -> bool {
        self.trace_data[&flow_id].is_target(hop)
    }

    /// Is a given `Hop` in the current round for a given flow?
    pub fn is_in_round(&self, hop: &Hop, flow_id: FlowId) -> bool {
        self.trace_data[&flow_id].is_in_round(hop)
    }

    /// Return the target `Hop` for a given flow.
    pub fn target_hop(&self, flow_id: FlowId) -> &Hop {
        self.trace_data[&flow_id].target_hop()
    }

    /// The current round of tracing for a given flow.
    pub fn round(&self, flow_id: FlowId) -> Option<usize> {
        self.trace_data[&flow_id].round()
    }

    /// The total rounds of tracing for a given flow.
    pub fn round_count(&self, flow_id: FlowId) -> usize {
        self.trace_data[&flow_id].round_count()
    }

    /// The `FlowId` for the current round.
    pub fn round_flow_id(&self) -> FlowId {
        self.round_flow_id
    }

    /// The registry of flows in the trace.
    pub fn flows(&self) -> &[(Flow, FlowId)] {
        self.registry.flows()
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn set_error(&mut self, error: Option<String>) {
        self.error = error;
    }

    /// Update the tracing state from a `TracerRound`.
    pub(super) fn update_from_round(&mut self, round: &TracerRound<'_>) {
        let flow = Flow::from_hops(
            round
                .probes
                .iter()
                .filter(|probe| {
                    matches!(probe.status, ProbeStatus::Complete | ProbeStatus::Awaited)
                })
                .take(usize::from(round.largest_ttl.0))
                .map(|p| p.host),
        );
        let flow_id = self.registry.register(flow);
        self.round_flow_id = flow_id;
        self.update_trace_flow(Self::default_flow_id(), round);
        self.update_trace_flow(flow_id, round);
    }

    fn update_trace_flow(&mut self, flow_id: FlowId, round: &TracerRound<'_>) {
        let flow_trace = self
            .trace_data
            .entry(flow_id)
            .or_insert_with(|| TraceData::new(self.max_samples));
        flow_trace.update_from_round(round);
    }
}

/// Information about a single `Hop` within a `Trace`.
#[derive(Debug, Clone)]
pub struct Hop {
    /// The ttl of this hop.
    ttl: u8,
    /// The addrs of this hop and associated counts.
    addrs: IndexMap<IpAddr, usize>,
    /// The total probes sent for this hop.
    total_sent: usize,
    /// The total probes received for this hop.
    total_recv: usize,
    /// The total round trip time for this hop across all rounds.
    total_time: Duration,
    /// The round trip time for this hop in the current round.
    last: Option<Duration>,
    /// The best round trip time for this hop across all rounds.
    best: Option<Duration>,
    /// The worst round trip time for this hop across all rounds.
    worst: Option<Duration>,
    /// The history of round trip times across the last N rounds.
    samples: Vec<Duration>,
    /// The ICMP extensions for this hop.
    extensions: Option<Extensions>,
    mean: f64,
    m2: f64,
    /// The ABS(RTTx - RTTx-n)
    jitter: Option<Duration>,
    /// The Sequential jitter average calculated for each
    javg: Option<f64>,
    /// The worst jitter reading recorded
    jmax: Option<Duration>,
    /// The interval calculation i.e smooth
    jinta: f64,
}

impl Hop {
    /// The time-to-live of this hop.
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    /// The set of addresses that have responded for this time-to-live.
    pub fn addrs(&self) -> impl Iterator<Item = &IpAddr> {
        self.addrs.keys()
    }

    pub fn addrs_with_counts(&self) -> impl Iterator<Item = (&IpAddr, &usize)> {
        self.addrs.iter()
    }

    /// The number of unique address observed for this time-to-live.
    pub fn addr_count(&self) -> usize {
        self.addrs.len()
    }

    /// The total number of probes sent.
    pub fn total_sent(&self) -> usize {
        self.total_sent
    }

    /// The total number of probes responses received.
    pub fn total_recv(&self) -> usize {
        self.total_recv
    }

    /// The % of packets that are lost.
    pub fn loss_pct(&self) -> f64 {
        if self.total_sent > 0 {
            let lost = self.total_sent - self.total_recv;
            lost as f64 / self.total_sent as f64 * 100f64
        } else {
            0_f64
        }
    }

    /// The duration of the last probe.
    pub fn last_ms(&self) -> Option<f64> {
        self.last.map(|last| last.as_secs_f64() * 1000_f64)
    }

    /// The duration of the best probe observed.
    pub fn best_ms(&self) -> Option<f64> {
        self.best.map(|last| last.as_secs_f64() * 1000_f64)
    }

    /// The duration of the worst probe observed.
    pub fn worst_ms(&self) -> Option<f64> {
        self.worst.map(|last| last.as_secs_f64() * 1000_f64)
    }

    /// The average duration of all probes.
    pub fn avg_ms(&self) -> f64 {
        if self.total_recv() > 0 {
            (self.total_time.as_secs_f64() * 1000_f64) / self.total_recv as f64
        } else {
            0_f64
        }
    }

    /// The standard deviation of all probes.
    pub fn stddev_ms(&self) -> f64 {
        if self.total_recv > 1 {
            (self.m2 / (self.total_recv - 1) as f64).sqrt()
        } else {
            0_f64
        }
    }

    /// The duration of the jitter probe observed.
    pub fn jitter_ms(&self) -> Option<f64> {
        self.jitter.map(|j| j.as_secs_f64() * 1000_f64)
    }
    /// The duration of the jworst probe observed.
    pub fn jmax_ms(&self) -> Option<f64> {
        self.jmax.map(|x| x.as_secs_f64() * 1000_f64)
    }
    /// The jitter average duration of all probes.
    pub fn javg_ms(&self) -> Option<f64> {
        if self.total_recv() > 0 {
            self.javg
        } else {
            None
        }
    }
    /// The jitter interval of all probes.
    pub fn jinta(&self) -> Option<f64> {
        if self.total_recv() > 0 {
            Some(self.jinta)
        } else {
            None
        }
    }

    /// The last N samples.
    pub fn samples(&self) -> &[Duration] {
        &self.samples
    }

    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }
}

impl Default for Hop {
    fn default() -> Self {
        Self {
            ttl: 0,
            addrs: IndexMap::default(),
            total_sent: 0,
            total_recv: 0,
            total_time: Duration::default(),
            last: None,
            best: None,
            worst: None,
            mean: 0f64,
            m2: 0f64,
            samples: Vec::default(),
            extensions: None,
            jitter: None,
            javg: None,
            jmax: None,
            jinta: 0f64,
        }
    }
}

/// Data for a trace.
#[derive(Debug, Clone)]
struct TraceData {
    /// The maximum number of samples to record.
    max_samples: usize,
    /// The lowest ttl observed across all rounds.
    lowest_ttl: u8,
    /// The highest ttl observed across all rounds.
    highest_ttl: u8,
    /// The highest ttl observed for the latest round.
    highest_ttl_for_round: u8,
    /// The latest round received.
    round: Option<usize>,
    /// The total number of rounds received.
    round_count: usize,
    /// The hops in this trace.
    hops: Vec<Hop>,
}

impl TraceData {
    fn new(max_samples: usize) -> Self {
        Self {
            max_samples,
            lowest_ttl: 0,
            highest_ttl: 0,
            highest_ttl_for_round: 0,
            round: None,
            round_count: 0,
            hops: (0..MAX_HOPS).map(|_| Hop::default()).collect(),
        }
    }

    fn hops(&self) -> &[Hop] {
        if self.lowest_ttl == 0 || self.highest_ttl == 0 {
            &[]
        } else {
            let start = (self.lowest_ttl as usize) - 1;
            let end = self.highest_ttl as usize;
            &self.hops[start..end]
        }
    }

    fn is_target(&self, hop: &Hop) -> bool {
        self.highest_ttl == hop.ttl
    }

    fn is_in_round(&self, hop: &Hop) -> bool {
        hop.ttl <= self.highest_ttl_for_round
    }

    fn target_hop(&self) -> &Hop {
        if self.highest_ttl > 0 {
            &self.hops[usize::from(self.highest_ttl) - 1]
        } else {
            &self.hops[0]
        }
    }

    fn round(&self) -> Option<usize> {
        self.round
    }

    fn round_count(&self) -> usize {
        self.round_count
    }

    fn update_from_round(&mut self, round: &TracerRound<'_>) {
        self.round_count += 1;
        self.highest_ttl = std::cmp::max(self.highest_ttl, round.largest_ttl.0);
        self.highest_ttl_for_round = round.largest_ttl.0;
        for probe in round.probes {
            self.update_from_probe(probe);
        }
    }

    fn update_from_probe(&mut self, probe: &Probe) {
        self.update_lowest_ttl(probe);
        self.update_round(probe);
        match probe.status {
            ProbeStatus::Complete => {
                let index = usize::from(probe.ttl.0) - 1;
                let hop = &mut self.hops[index];
                hop.ttl = probe.ttl.0;
                hop.total_sent += 1;
                hop.total_recv += 1;
                let dur = probe.duration();
                let dur_ms = dur.as_secs_f64() * 1000_f64;
                hop.total_time += dur;
                //Before last is set use it to calc jitter
                let last_ms = hop.last_ms().unwrap_or_default();
                let jitter_ms = (last_ms - dur_ms).abs();
                let jitter_dur = Duration::from_secs_f64(jitter_ms / 1000_f64);
                hop.jitter = Some(jitter_dur);
                let mut javg_ms = hop.javg_ms().unwrap_or_default();
                //Welfords online algorithm avg without dataset values.
                javg_ms += (jitter_ms - javg_ms) / hop.total_recv as f64;
                hop.javg = Some(javg_ms);
                // algorithm is from rfc1889, A.8 or rfc3550
                hop.jinta += jitter_ms - ((hop.jinta + 8.0) / 16.0);
                //Max following logic of hop.worst
                hop.jmax = hop
                    .jmax
                    .map_or(Some(jitter_dur), |d| Some(d.max(jitter_dur)));
                hop.last = Some(dur);
                hop.samples.insert(0, dur);
                hop.best = hop.best.map_or(Some(dur), |d| Some(d.min(dur)));
                hop.worst = hop.worst.map_or(Some(dur), |d| Some(d.max(dur)));
                hop.mean += (dur_ms - hop.mean) / hop.total_recv as f64;
                hop.m2 += (dur_ms - hop.mean) * (dur_ms - hop.mean);
                if hop.samples.len() > self.max_samples {
                    hop.samples.pop();
                }
                let host = probe.host.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                *hop.addrs.entry(host).or_default() += 1;
                hop.extensions = probe.extensions.clone();
            }
            ProbeStatus::Awaited => {
                let index = usize::from(probe.ttl.0) - 1;
                self.hops[index].total_sent += 1;
                self.hops[index].ttl = probe.ttl.0;
                self.hops[index].samples.insert(0, Duration::default());
                if self.hops[index].samples.len() > self.max_samples {
                    self.hops[index].samples.pop();
                }
            }
            ProbeStatus::NotSent | ProbeStatus::Skipped => {}
        }
    }

    fn update_round(&mut self, probe: &Probe) {
        if matches!(probe.status, ProbeStatus::Awaited | ProbeStatus::Complete) {
            self.round = match self.round {
                None => Some(probe.round.0),
                Some(r) => Some(r.max(probe.round.0)),
            }
        }
    }

    fn update_lowest_ttl(&mut self, probe: &Probe) {
        if matches!(probe.status, ProbeStatus::Awaited | ProbeStatus::Complete) {
            if self.lowest_ttl == 0 {
                self.lowest_ttl = probe.ttl.0;
            } else {
                self.lowest_ttl = self.lowest_ttl.min(probe.ttl.0);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::trace::{Hop, TraceData};
    use iso8601_timestamp::Timestamp;
    use serde::{Deserialize, Serialize};
    use std::fs::File;
    use std::io::Read;
    use std::str::FromStr;
    use std::time::SystemTime;
    use test_case::test_case;
    use trippy::tracing::tracer::CompletionReason;
    use trippy::tracing::types::{Port, Round, Sequence, TimeToLive, TraceId};
    use trippy::tracing::{IcmpPacketType, Probe};
    
    #[derive(Serialize, Deserialize, Debug)]
    struct ImportProbe {
        sequence: u16,
        identifier: u16,
        src_port: u16,
        dest_port: u16,
        ttl: u8,
        round: usize,
        sent: Option<Timestamp>,
        status: String,
        host: Option<String>,
        received: Option<Timestamp>,
        icmp_packet_type: Option<String>,
        extensions: Option<String>,
    }
    impl ImportProbe {
        fn sequence(&self) -> Sequence {
            Sequence(self.sequence)
        }
        fn identifier(&self) -> TraceId {
            TraceId(self.identifier)
        }
        fn src_port(&self) -> Port {
            Port(self.src_port)
        }
        fn dest_port(&self) -> Port {
            Port(self.dest_port)
        }
        fn ttl(&self) -> TimeToLive {
            TimeToLive(self.ttl)
        }
        fn round(&self) -> Round {
            Round(self.round)
        }
        fn sent(&self) -> SystemTime {
            match SystemTime::try_from(self.sent.unwrap()) {
                Ok(st) => st,
                Err(_d) => SystemTime::now(),
            }
        }
        fn received(&self) -> Option<SystemTime> {
            self.received.map(|r| SystemTime::try_from(r).ok().unwrap())
        }
        fn status(&self) -> ProbeStatus {
            match self.status.as_str() {
                "Complete" => ProbeStatus::Complete,
                "NotSent" => ProbeStatus::NotSent,
                "Awaited" => ProbeStatus::Awaited,
                _ => ProbeStatus::Skipped,
            }
        }
        fn host(&self) -> Option<IpAddr> {
            self.host
                .as_ref()
                .map(|h| IpAddr::V4(Ipv4Addr::from_str(h).unwrap()))
        }
    }
    impl From<ImportProbe> for Probe {
        fn from(value: ImportProbe) -> Self {
            Self {
                sequence: value.sequence(),
                identifier: value.identifier(),
                src_port: value.src_port(),
                dest_port: value.dest_port(),
                ttl: value.ttl(),
                round: value.round(),
                sent: Some(value.sent()),
                status: value.status(),
                host: value.host(),
                received: value.received(),
                icmp_packet_type: Some(IcmpPacketType::NotApplicable),
                extensions: None,
            }
        }
    }
    #[derive(Deserialize,Serialize,Debug,Clone)]
    struct HopResults {
        /// The total probes sent for this hop.
        total_sent: usize,
        /// The total probes received for this hop.
        total_recv: usize,
        /// The round trip time for this hop in the current round.
        last: Option<Duration>,
        /// The best round trip time for this hop across all rounds.
        best: Option<Duration>,
        /// The worst round trip time for this hop across all rounds.
        worst: Option<Duration>,
        /// The history of round trip times across the last N rounds.
        mean: f64,
        m2: f64,
        /// The ABS(RTTx - RTTx-n)
        jitter: Option<Duration>,
        /// The Sequential jitter average calculated for each
        javg: Option<f64>,
        /// The worst jitter reading recorded
        jmax: Option<Duration>,
        /// The interval calculation i.e smooth
        jinta: f64,
    }
    impl HopResults {
        #[allow(clippy::too_many_arguments)]
        fn new(
            total_sent: usize,
            total_recv: usize,
            last: u64,
            best: u64,
            worst: u64,
            mean: f64,
            m2: f64,
            jitter: u64,
            javg: f64,
            jmax: u64,
            jinta: f64,
        ) -> Self {
                Self {total_sent,
                total_recv,
                last: Some(Duration::from_millis(last)),
                best: Some(Duration::from_millis(best)),
                worst: Some(Duration::from_millis(worst)),
                mean,
                m2,
                jitter: Some(Duration::from_millis(jitter)),
                javg: Some(javg),
                jmax: Some(Duration::from_millis(jmax)),
                jinta,
            }
        }
        //TODO: Create combined struct ImportProbe Vec<ImportProbe> & HopResults.
        //JSON will define the test and expected results.
    }
    impl PartialEq<&Hop> for HopResults {
        fn eq(&self, other: &&Hop) -> bool {
            self.last == other.last
            && self.jitter == other.jitter
            && self.jmax == other.jmax
            && self.javg == other.javg
            && format!("{:.2}",self.jinta) == format!("{:.2}", other.jinta)
            }
    }    
    #[test_case("base_line.json", &HopResults::new(2,2,700,300,700,0.0,0.0,400,350.0,400,680.28))]
    fn test_probe_file(json_file: &str, expected: &HopResults) {
        let mut json = String::new();
        let mut dir_json_file = "./tests/data/".to_owned();
        dir_json_file.push_str(json_file);
        let mut file = File::open(dir_json_file).expect("Failed to open input file");
        // Read the network inputs into a string
        file.read_to_string(&mut json).expect("Failed to read file");

        let mut trace = Trace::new(100);
        let import_probes: Vec<ImportProbe> = serde_json::from_str(&json).unwrap();
        let probes: Vec<Probe> = import_probes.into_iter().map(Probe::from).collect();
        let round = TracerRound::new(&probes, TimeToLive(1), CompletionReason::TargetFound);
        trace.update_from_round(&round);
        println!("Hop = {:#?}", trace.hops(Trace::default_flow_id())[0]);
        let hop: &Hop = &trace.hops(Trace::default_flow_id())[0];
        ///Check if expected matches results
        assert_eq!(expected, &hop );
    }
    #[test]
    //#[ignore = "WIP"]
    fn test_probe_raw_list() {
        let json = r#"[{
            "sequence": 1,
            "identifier": 1,
            "src_port": 80,
            "dest_port": 80,
            "ttl": 1,
            "round": 1,
            "sent": "2023-01-01T12:01:55.100",
            "status": "Complete",
            "host": "10.1.0.2",
            "received": "2023-01-01T12:01:55.400",
            "icmp_packet_type": null,
            "extensions": null
          },{
            "sequence": 2,
            "identifier": 1,
            "src_port": 80,
            "dest_port": 80,
            "ttl": 1,
            "round": 1,
            "sent": "2023-01-01T12:01:56.100",
            "status": "Complete",
            "host": "10.1.0.2",
            "received": "2023-01-01T12:01:56.800",
            "icmp_packet_type": null,
            "extensions": null
          }]"#;
        let mut trace = Trace::new(100);
        let import_probes: Vec<ImportProbe> = serde_json::from_str(json).unwrap();
        let probes: Vec<Probe> = import_probes.into_iter().map(Probe::from).collect();
        let round = TracerRound::new(&probes, TimeToLive(1), CompletionReason::TargetFound);
        trace.update_from_round(&round);
        println!("Hop = {:#?}", trace.hops(Trace::default_flow_id())[0]);
        assert_eq!(2, trace.hops(Trace::default_flow_id())[0].total_recv);
    }

    #[test]
    fn test_probe_raw_single() {
        let json = r#"{
            "sequence": 2,
            "identifier": 2,
            "src_port": 80,
            "dest_port": 80,
            "ttl": 63,
            "round": 2,
            "sent": "2022-01-01T12:02:00Z",
            "status": "Complete",
            "host": "10.1.0.1",
            "received": "2022-01-01T12:02:01Z",
            "icmp_packet_type": null,
            "extensions": null
          }"#;

        let import_probe: ImportProbe = serde_json::from_str(json).expect("Failed to deserialize JSON");
        let probe = Probe::from(import_probe);
        let mut td = TraceData::new(2);
        td.update_from_probe(&probe);
        assert_eq!(probe.sequence.0, 2);
        println!("Host: {:?}, Age: {:?}", probe.host, probe.sequence);
    }
}
