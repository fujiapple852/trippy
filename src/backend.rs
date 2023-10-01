use crate::config::MAX_HOPS;
use crate::platform::Platform;
use indexmap::IndexMap;
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;
use trippy::tracing::{
    Extensions, Probe, ProbeStatus, SocketImpl, Tracer, TracerChannel, TracerChannelConfig,
    TracerConfig, TracerRound,
};

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
                // TODO should we combine extensions across rounds?
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

/// Information about a single `Hop` within a `Trace`.
#[derive(Debug, Clone)]
pub struct Hop {
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
    extensions: Option<Extensions>,
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

    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
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
