use crate::backend::flow::FlowId;
use crate::config::MAX_HOPS;
use crate::platform::Platform;
use indexmap::IndexMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;
use trippy::tracing::{
    Probe, ProbeStatus, SocketImpl, Tracer, TracerChannel, TracerChannelConfig, TracerConfig,
    TracerRound,
};

/// The state of all hops in a trace.
#[derive(Debug, Clone)]
pub struct Trace {
    max_samples: usize,
    round: Option<usize>,
    flows: HashMap<FlowId, Flow>,
    error: Option<String>,
}

impl Trace {
    pub fn new(max_samples: usize) -> Self {
        let mut flows = HashMap::new();
        flows.insert(FlowId(0), Flow::new());
        Self {
            max_samples,
            round: None,
            flows,
            error: None,
        }
    }

    /// The current round of tracing.
    pub fn round(&self) -> Option<usize> {
        self.round
    }

    /// Return the number of hops.
    pub fn hop_count(&self) -> usize {
        let flow = self.flows.get(&FlowId(0)).unwrap();
        if flow.lowest_ttl == 0 || flow.highest_ttl == 0 {
            0
        } else {
            usize::from(flow.highest_ttl - flow.lowest_ttl) + 1
        }
    }

    /// Return the range of hops in tui indexes
    ///
    /// These will always be in the range 0..x even when the `lowest_ttl` is not 1
    pub fn hop_range(&self) -> Range<usize> {
        let flow = self.flows.get(&FlowId(0)).unwrap();
        #[allow(clippy::range_plus_one)]
        if flow.lowest_ttl == 0 || flow.highest_ttl == 0 {
            0..0
        } else {
            0..usize::from(flow.highest_ttl - flow.lowest_ttl) + 1
        }
    }

    /// The maximum number of hosts per hop.
    pub fn max_addr_count(&self) -> u8 {
        self.hops()
            .iter()
            .map(|h| h.addrs.len())
            .max()
            .and_then(|i| u8::try_from(i).ok())
            .unwrap_or_default()
    }

    /// Is a given `Hop` the target hop?
    ///
    /// A `Hop` is considered to be the target if it has the highest `ttl` value observed.
    ///
    /// Note that if the target host does not respond to probes then the the highest `ttl` observed
    /// will be one greater than the `ttl` of the last host which did respond.
    pub fn is_target(&self, index: usize) -> bool {
        let flow = self.flows.get(&FlowId(0)).unwrap();
        let hop = &self.hops()[index];
        flow.highest_ttl == hop.ttl
    }

    /// Is a given `Hop` in the current round?
    pub fn is_in_round(&self, index: usize) -> bool {
        let flow = self.flows.get(&FlowId(0)).unwrap();
        let hop = &self.hops()[index];
        hop.ttl <= flow.highest_ttl_for_round
    }

    /// The time-to-live of this hop.
    ///
    /// The index here is the Tui index, so 0 may be ttl 4
    pub fn ttl(&self, index: usize) -> u8 {
        let hop = &self.hops()[index];
        hop.ttl
    }

    /// The set of addresses that have responded for this time-to-live.
    pub fn addrs(&self, index: usize) -> impl Iterator<Item = &IpAddr> {
        let hop = &self.hops()[index];
        hop.addrs.keys()
    }

    pub fn addrs_with_counts(&self, index: usize) -> impl Iterator<Item = (&IpAddr, &usize)> {
        let hop = &self.hops()[index];
        hop.addrs.iter()
    }

    /// The number of unique address observed for this time-to-live.
    pub fn addr_count(&self, index: usize) -> usize {
        let hop = &self.hops()[index];
        hop.addrs.len()
    }

    /// The total number of probes sent.
    pub fn total_sent(&self, index: usize) -> usize {
        let hop = &self.hops()[index];
        hop.total_sent
    }

    /// The total number of probes responses received.
    pub fn total_recv(&self, index: usize) -> usize {
        let hop = &self.hops()[index];
        hop.total_recv
    }

    /// The % of packets that are lost.
    pub fn loss_pct(&self, index: usize) -> f64 {
        let hop = &self.hops()[index];
        if hop.total_sent > 0 {
            let lost = hop.total_sent - hop.total_recv;
            lost as f64 / hop.total_sent as f64 * 100f64
        } else {
            0_f64
        }
    }

    /// The duration of the last probe.
    pub fn last_ms(&self, index: usize) -> Option<f64> {
        let hop = &self.hops()[index];
        hop.last.map(|last| last.as_secs_f64() * 1000_f64)
    }

    /// The duration of the best probe observed.
    pub fn best_ms(&self, index: usize) -> Option<f64> {
        let hop = &self.hops()[index];
        hop.best.map(|last| last.as_secs_f64() * 1000_f64)
    }

    /// The duration of the worst probe observed.
    pub fn worst_ms(&self, index: usize) -> Option<f64> {
        let hop = &self.hops()[index];
        hop.worst.map(|last| last.as_secs_f64() * 1000_f64)
    }

    /// The average duration of all probes.
    pub fn avg_ms(&self, index: usize) -> f64 {
        let hop = &self.hops()[index];
        if hop.total_recv > 0 {
            (hop.total_time.as_secs_f64() * 1000_f64) / hop.total_recv as f64
        } else {
            0_f64
        }
    }

    /// The standard deviation of all probes.
    pub fn stddev_ms(&self, index: usize) -> f64 {
        let hop = &self.hops()[index];
        if hop.total_recv > 1 {
            (hop.m2 / (hop.total_recv - 1) as f64).sqrt()
        } else {
            0_f64
        }
    }

    /// The last N samples.
    pub fn samples(&self, index: usize) -> &[Duration] {
        let hop = &self.hops()[index];
        &hop.samples
    }

    /// Return a slice of `Hop`.
    ///
    /// If there are no hops then the `hops[0..1]` is returned as a sentinel
    /// value which will have default values for all fields.
    fn hops(&self) -> &[Hop] {
        let flow = self.flows.get(&FlowId(0)).unwrap();
        if flow.lowest_ttl == 0 || flow.highest_ttl == 0 {
            &flow.hops[0..1]
        } else {
            let start = (flow.lowest_ttl as usize) - 1;
            let end = flow.highest_ttl as usize;
            &flow.hops[start..end]
        }
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Update the tracing state from a `TracerRound`.
    pub fn update_from_round(&mut self, round: &TracerRound<'_>) {
        let _flow_id = FlowId::from_addrs(round.probes.iter().map(|p| (p.ttl.0, p.host))).flow_id();
        // println!("flow_id: {}", flow_id.flow_id());
        // let flow = self.flows.entry(flow_id).or_insert_with(|| Flow::new());

        let flow = self.flows.get_mut(&FlowId(0)).unwrap();
        flow.highest_ttl = std::cmp::max(flow.highest_ttl, round.largest_ttl.0);
        flow.highest_ttl_for_round = round.largest_ttl.0;
        for probe in round.probes {
            self.update_from_probe(probe);
        }
    }

    fn update_from_probe(&mut self, probe: &Probe) {
        self.update_lowest_ttl(probe);
        self.update_round(probe);
        let flow = self.flows.get_mut(&FlowId(0)).unwrap();
        match probe.status {
            ProbeStatus::Complete => {
                let index = usize::from(probe.ttl.0) - 1;
                let hop = &mut flow.hops[index];
                hop.ttl = probe.ttl.0;
                hop.total_sent += 1;
                hop.total_recv += 1;
                let dur = probe.duration();
                let dur_ms = dur.as_secs_f64() * 1000_f64;
                hop.total_time += dur;
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
            }
            ProbeStatus::Awaited => {
                let index = usize::from(probe.ttl.0) - 1;
                flow.hops[index].total_sent += 1;
                flow.hops[index].ttl = probe.ttl.0;
                flow.hops[index].samples.insert(0, Duration::default());
                if flow.hops[index].samples.len() > self.max_samples {
                    flow.hops[index].samples.pop();
                }
            }
            ProbeStatus::NotSent => {}
        }
    }

    /// Update `lowest_ttl` for valid probes.
    fn update_lowest_ttl(&mut self, probe: &Probe) {
        let flow = self.flows.get_mut(&FlowId(0)).unwrap();
        if matches!(probe.status, ProbeStatus::Awaited | ProbeStatus::Complete) {
            if flow.lowest_ttl == 0 {
                flow.lowest_ttl = probe.ttl.0;
            } else {
                flow.lowest_ttl = flow.lowest_ttl.min(probe.ttl.0);
            }
        }
    }

    /// Update `round` for valid probes.
    fn update_round(&mut self, probe: &Probe) {
        if matches!(probe.status, ProbeStatus::Awaited | ProbeStatus::Complete) {
            self.round = match self.round {
                None => Some(probe.round.0),
                Some(r) => Some(r.max(probe.round.0)),
            }
        }
    }
}

// /// An identifier for a flow.
// pub type FlowId = u64;

/// A Flow holds data a unique tracing flow.
#[derive(Debug, Clone)]
struct Flow {
    lowest_ttl: u8,
    highest_ttl: u8,
    highest_ttl_for_round: u8,
    hops: Vec<Hop>,
}

impl Flow {
    pub fn new() -> Self {
        Self {
            lowest_ttl: 0,
            highest_ttl: 0,
            highest_ttl_for_round: 0,
            hops: (0..MAX_HOPS).map(|_| Hop::default()).collect(),
        }
    }
}

/// Information about a single `Hop` within a `Flow`.
#[derive(Debug, Clone)]
struct Hop {
    ttl: u8,
    addrs: IndexMap<IpAddr, usize>,
    total_sent: usize,
    total_recv: usize,
    total_time: Duration,
    last: Option<Duration>,
    best: Option<Duration>,
    worst: Option<Duration>,
    mean: f64,
    m2: f64,
    samples: Vec<Duration>,
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
        }
    }
}

mod flow {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::net::IpAddr;

    /// TODO
    #[derive(Debug, Clone, Eq, PartialEq, Hash)]
    pub struct FlowId(pub(super) u64);

    impl FlowId {
        /// TODO
        pub fn from_addrs(addrs: impl Iterator<Item = (u8, Option<IpAddr>)>) -> Self {
            let hasher = addrs.fold(DefaultHasher::new(), |mut hasher, hop| {
                hop.hash(&mut hasher);
                hasher
            });
            Self(hasher.finish())
        }

        /// TODO
        pub fn flow_id(&self) -> u64 {
            self.0
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::Ipv4Addr;
        use std::str::FromStr;

        #[test]
        fn test_flow_id() {
            let hops = [
                (1, Some(addr("192.168.1.1"))),
                (2, Some(addr("10.193.232.14"))),
                (3, Some(addr("10.193.232.21"))),
                (4, Some(addr("218.102.40.26"))),
                (5, Some(addr("10.195.41.17"))),
                (6, Some(addr("63.218.1.105"))),
                (7, Some(addr("63.223.60.126"))),
                (8, Some(addr("213.248.97.220"))),
                (9, Some(addr("62.115.118.110"))),
                (10, None),
                (11, Some(addr("62.115.140.43"))),
                (12, Some(addr("62.115.115.173"))),
                (13, Some(addr("62.115.45.195"))),
                (14, Some(addr("185.74.76.23"))),
                (15, Some(addr("89.18.162.17"))),
                (16, Some(addr("213.189.4.73"))),
            ];
            assert_eq!(
                2_435_116_302_937_406_375,
                FlowId::from_addrs(hops.into_iter()).flow_id()
            );
        }

        fn addr(addr: &str) -> IpAddr {
            IpAddr::V4(Ipv4Addr::from_str(addr).unwrap())
        }
    }
}

/// Run the tracing backend.
///
/// Note that this implementation blocks the tracer on the `RwLock` and so any delays in the the TUI
/// will delay the next round of the started.
#[instrument(skip_all)]
pub fn run_backend(
    tracer_config: &TracerConfig,
    channel_config: &TracerChannelConfig,
    trace_data: Arc<RwLock<Trace>>,
) -> anyhow::Result<()> {
    let td = trace_data.clone();
    let channel = TracerChannel::<SocketImpl>::connect(channel_config).map_err(|err| {
        td.write().error = Some(err.to_string());
        err
    })?;
    Platform::drop_privileges()?;
    let tracer = Tracer::new(tracer_config, move |round| {
        trace_data.write().update_from_round(round);
    });
    match tracer.trace(channel) {
        Ok(()) => {}
        Err(err) => {
            td.write().error = Some(err.to_string());
        }
    };
    Ok(())
}
