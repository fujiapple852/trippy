use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use crate::caps::drop_caps;
use crate::config::MAX_HOPS;
use indexmap::IndexMap;
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;
use trippy::tracing::{
    Probe, ProbeStatus, Tracer, TracerChannel, TracerChannelConfig, TracerConfig, TracerRound
};

/// run dublin/paris mode, fix the src/dst ports for each round, currently we do this <- DONE
/// for each round result, we'll have a single ipaddr per hop, we can compute fingerprint for the trace in that round
/// we need to store stats per-hop-per-host (currently per hop)?  currently per hop

// what does a trace fingerprint look like?

fn fingerprint(addrs: impl Iterator<Item = (u8, Option<IpAddr>)>) -> u64 {
    let hasher = addrs.fold(DefaultHasher::new(), |mut hasher, hop| {
        hop.hash(&mut hasher);
        hasher
    });
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::*;

    #[test]
    fn test_fingerprint_1() {
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
        assert_eq!(2435116302937406375, fingerprint(hops.into_iter()));
    }

    fn addr(addr: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(addr).unwrap())
    }
}

// rather than a fingerprint, maybe we need to store Vec<(hop, ipaddr)>

// for each round, we search for a previous round that contains the same hop/host
// cases:
//      round has hop/host not in round history
//      round does not have hop/host in history <- so a subset,

// option 3: we use src/dest addr/port quad to derive a hash
// we store trace per hash, could be multiple hosts per hop

/// The state of all hops in a trace.
#[derive(Debug, Clone)]
pub struct Trace {
    max_samples: usize,
    lowest_ttl: u8,
    highest_ttl: u8,
    highest_ttl_for_round: u8,
    round: Option<usize>,
    hops: Vec<Hop>,
    error: Option<String>,
}

impl Trace {
    pub fn new(max_samples: usize) -> Self {
        Self {
            max_samples,
            lowest_ttl: 0,
            highest_ttl: 0,
            highest_ttl_for_round: 0,
            round: None,
            hops: (0..MAX_HOPS).map(|_| Hop::default()).collect(),
            error: None,
        }
    }

    /// The current round of tracing.
    pub fn round(&self) -> Option<usize> {
        self.round
    }

    /// Information about each hop in the trace.
    pub fn hops(&self) -> &[Hop] {
        if self.lowest_ttl == 0 || self.highest_ttl == 0 {
            &[]
        } else {
            let start = (self.lowest_ttl as usize) - 1;
            let end = self.highest_ttl as usize;
            &self.hops[start..end]
        }
    }

    /// Is a given `Hop` the target hop?
    ///
    /// A `Hop` is considered to be the target if it has the highest `ttl` value observed.
    ///
    /// Note that if the target host does not respond to probes then the the highest `ttl` observed
    /// will be one greater than the `ttl` of the last host which did respond.
    pub fn is_target(&self, hop: &Hop) -> bool {
        self.highest_ttl == hop.ttl
    }

    /// Is a given `Hop` in the current round?
    pub fn is_in_round(&self, hop: &Hop) -> bool {
        hop.ttl <= self.highest_ttl_for_round
    }

    /// Return the target `Hop`.
    ///
    /// TODO Do we guarantee there is always a target hop?
    pub fn target_hop(&self) -> &Hop {
        if self.highest_ttl > 0 {
            &self.hops[usize::from(self.highest_ttl) - 1]
        } else {
            &self.hops[0]
        }
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Update the tracing state from a `TracerRound`.
    pub fn update_from_round(&mut self, round: &TracerRound<'_>) {

        let hash = fingerprint(round.probes.iter().map(|p| (p.ttl.0, p.host)));
        println!("hash: {}", hash);


        self.highest_ttl = std::cmp::max(self.highest_ttl, round.largest_ttl.0);
        self.highest_ttl_for_round = round.largest_ttl.0;
        for probe in round.probes {
            self.update_from_probe(probe, hash);
        }
    }

    fn update_from_probe(&mut self, probe: &Probe, _hash: u64) {
        self.update_lowest_ttl(probe);
        self.update_round(probe);
        match probe.status {
            ProbeStatus::Complete => {
                let index = usize::from(probe.ttl.0) - 1;

                let hop_outer = &mut self.hops[index];
                let hop = &mut hop_outer.inners.entry(0).or_insert_with( || HopInner::new());

                hop_outer.ttl = probe.ttl.0;
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

                // TODO duplicated init code
                let hop_outer = &mut self.hops[index];
                let hop = &mut hop_outer.inners.entry(0).or_insert_with( || HopInner::new());

                hop.total_sent += 1;
                hop_outer.ttl = probe.ttl.0;
                hop.samples.insert(0, Duration::default());
                if hop.samples.len() > self.max_samples {
                    hop.samples.pop();
                }
            }
            ProbeStatus::NotSent => {}
        }
    }

    /// Update `lowest_ttl` for valid probes.
    fn update_lowest_ttl(&mut self, probe: &Probe) {
        if matches!(probe.status, ProbeStatus::Awaited | ProbeStatus::Complete) {
            if self.lowest_ttl == 0 {
                self.lowest_ttl = probe.ttl.0;
            } else {
                self.lowest_ttl = self.lowest_ttl.min(probe.ttl.0);
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

/// Data about a single hop (single ttl)
#[derive(Debug, Clone)]
pub struct HopInner {
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

impl HopInner {
    pub fn new() -> Self {
        Self {
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

/// Information about a single `Hop` for within a `Trace`.
///
/// 
#[derive(Debug, Clone)]
pub struct Hop {
    ttl: u8,
    inners: IndexMap<u64, HopInner>
}

impl Hop {
    /// The time-to-live of this hop.
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    /// The set of addresses that have responded for this time-to-live.
    pub fn addrs(&self) -> impl Iterator<Item = &IpAddr> {
        self.inners.values().map(|inner| inner.addrs.keys()).flatten()
    }

    pub fn addrs_with_counts(&self) -> impl Iterator<Item = (&IpAddr, &usize)> {
        self.inners.values().map(|inner| inner.addrs.iter()).flatten()
    }

    /// The number of unique address observed for this time-to-live.
    pub fn addr_count(&self) -> usize {
        self.inners.values().len()
    }

    /// The total number of probes sent.
    pub fn total_sent(&self) -> usize {
        self.inners[0].total_sent
    }

    /// The total number of probes responses received.
    pub fn total_recv(&self) -> usize {
        self.inners[0].total_recv
    }

    /// The % of packets that are lost.
    pub fn loss_pct(&self) -> f64 {
        if self.inners[0].total_sent > 0 {
            let lost = self.inners[0].total_sent - self.inners[0].total_recv;
            lost as f64 / self.inners[0].total_sent as f64 * 100f64
        } else {
            0_f64
        }
    }

    /// The duration of the last probe.
    pub fn last_ms(&self) -> Option<f64> {
        self.inners[0].last.map(|last| last.as_secs_f64() * 1000_f64)
    }

    /// The duration of the best probe observed.
    pub fn best_ms(&self) -> Option<f64> {
        self.inners[0].best.map(|last| last.as_secs_f64() * 1000_f64)
    }

    /// The duration of the worst probe observed.
    pub fn worst_ms(&self) -> Option<f64> {
        self.inners[0].worst.map(|last| last.as_secs_f64() * 1000_f64)
    }

    /// The average duration of all probes.
    pub fn avg_ms(&self) -> f64 {
        if self.total_recv() > 0 {
            (self.inners[0].total_time.as_secs_f64() * 1000_f64) / self.inners[0].total_recv as f64
        } else {
            0_f64
        }
    }

    /// The standard deviation of all probes.
    pub fn stddev_ms(&self) -> f64 {
        if self.inners[0].total_recv > 1 {
            (self.inners[0].m2 / (self.inners[0].total_recv - 1) as f64).sqrt()
        } else {
            0_f64
        }
    }

    /// The last N samples.
    pub fn samples(&self) -> &[Duration] {
        &self.inners[0].samples
    }
}

impl Default for Hop {
    fn default() -> Self {
        Self {
            ttl: 0,
            inners: IndexMap::default(),
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
    let channel = TracerChannel::connect(channel_config)?;
    drop_caps()?;
    let tracer = Tracer::new(tracer_config, move |round| {
        trace_data.write().update_from_round(round);
    });
    match tracer.trace(channel) {
        Ok(_) => {}
        Err(err) => {
            td.write().error = Some(err.to_string());
        }
    };
    Ok(())
}
