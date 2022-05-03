use crate::config::MAX_HOPS;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use trippy::tracing::{Probe, ProbeStatus, Tracer, TracerChannel, TracerConfig, TracerRound};

/// The maximum number of historic samples to keep per hop.
const MAX_SAMPLES: usize = 256;

/// The state of all hops in a trace.
#[derive(Debug, Clone)]
pub struct Trace {
    lowest_ttl: u8,
    highest_ttl: u8,
    round: usize,
    hops: Vec<Hop>,
}

impl Trace {
    /// The current round of tracing.
    pub fn round(&self) -> usize {
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
    /// Note that if the target host does not respond to probes then the the highest `ttl` observed will be one greater
    /// than the `ttl` of the last host which did respond.
    pub fn is_target(&self, hop: &Hop) -> bool {
        self.highest_ttl == hop.ttl
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

    /// Update the tracing state from a `TracerRound`.
    pub fn update_from_round(&mut self, round: &TracerRound<'_>) {
        self.highest_ttl = self.highest_ttl.max(round.largest_ttl.0);
        for probe in round.probes {
            self.update_from_probe(probe);
        }
    }

    fn update_from_probe(&mut self, probe: &Probe) {
        let index = usize::from(probe.ttl.0) - 1;
        if self.lowest_ttl == 0 {
            self.lowest_ttl = probe.ttl.0;
        } else {
            self.lowest_ttl = self.lowest_ttl.min(probe.ttl.0);
        }
        self.round = self.round.max(probe.round.0);
        match probe.status {
            ProbeStatus::Complete => {
                let hop = &mut self.hops[index];
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
                if hop.samples.len() > MAX_SAMPLES {
                    hop.samples.pop();
                }
                let host = probe.host.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                *hop.addrs.entry(host).or_default() += 1;
            }
            ProbeStatus::Awaited => {
                self.hops[index].total_sent += 1;
                self.hops[index].ttl = probe.ttl.0;
                self.hops[index].samples.insert(0, Duration::default());
                if self.hops[index].samples.len() > MAX_SAMPLES {
                    self.hops[index].samples.pop();
                }
            }
            ProbeStatus::NotSent => {}
        }
    }
}

impl Default for Trace {
    fn default() -> Self {
        Self {
            lowest_ttl: 0,
            highest_ttl: 0,
            round: 0,
            hops: (0..MAX_HOPS).map(|_| Hop::default()).collect(),
        }
    }
}

/// Information about a single `Hop` within a `Trace`.
#[derive(Debug, Clone)]
pub struct Hop {
    ttl: u8,
    addrs: HashMap<IpAddr, usize>,
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

    /// The last N samples.
    pub fn samples(&self) -> &[Duration] {
        &self.samples
    }
}

impl Default for Hop {
    fn default() -> Self {
        Self {
            ttl: 0,
            addrs: HashMap::default(),
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

/// Run the tracing backend.
///
/// Note that this implementation blocks the tracer on the `RwLock` and so any delays in the the TUI will delay the
/// next round of the started.
///
/// Note that currently each `Probe` is published individually at the end of a round and so the lock is taken multiple
/// times per round.
pub fn run_backend(
    config: &TracerConfig,
    channel: TracerChannel,
    trace_data: Arc<RwLock<Trace>>,
) -> anyhow::Result<()> {
    let tracer = Tracer::new(config, move |round| {
        trace_data.write().update_from_round(round);
    });
    Ok(tracer.trace(channel)?)
}
