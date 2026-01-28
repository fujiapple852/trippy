use serde::Deserialize;
use std::net::IpAddr;
use trippy_core::Port;

/// A simulated trace.
#[derive(Debug, Clone, Deserialize)]
pub struct Simulation {
    pub name: String,
    pub rounds: Option<usize>,
    #[serde(default)]
    pub privilege_mode: PrivilegeMode,
    pub target: IpAddr,
    pub protocol: Protocol,
    #[serde(default)]
    pub port_direction: PortDirection,
    #[serde(default)]
    pub multipath_strategy: MultipathStrategy,
    #[serde(default)]
    pub icmp_identifier: u16,
    pub initial_sequence: Option<u16>,
    pub packet_size: Option<u16>,
    pub payload_pattern: Option<u8>,
    pub tos: Option<u8>,
    pub min_round_duration: Option<u64>,
    pub max_round_duration: Option<u64>,
    pub grace_duration: Option<u64>,
    pub hops: Vec<Hop>,
}

impl Simulation {
    #[must_use]
    pub(crate) fn latest_ttl(&self) -> u8 {
        if self.hops.is_empty() {
            0
        } else {
            self.hops[self.hops.len() - 1].ttl
        }
    }
}

/// A simulated hop.
#[derive(Debug, Clone, Deserialize)]
pub struct Hop {
    /// The simulated time-to-live (TTL).
    pub ttl: u8,
    /// The simulated probe response.
    pub resp: Response,
}

/// A simulated probe response.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "tag")]
pub enum Response {
    /// Simulate a hop which does not response to probes.
    NoResponse,
    /// Simulate a hop which responds to probes from a single host.
    SingleHost(SingleHost),
}

/// A simulated probe response with a single addr and fixed ttl.
#[derive(Debug, Clone, Deserialize)]
pub struct SingleHost {
    /// The simulated host responding to the probe.
    pub addr: IpAddr,
    /// The simulated round trim time (RTT) in ms.
    pub rtt_ms: u16,
}

#[derive(Copy, Clone, Debug, Default, Deserialize)]
pub enum PrivilegeMode {
    #[default]
    Privileged,
    Unprivileged,
}

impl From<PrivilegeMode> for trippy_core::PrivilegeMode {
    fn from(value: PrivilegeMode) -> Self {
        match value {
            PrivilegeMode::Privileged => Self::Privileged,
            PrivilegeMode::Unprivileged => Self::Unprivileged,
        }
    }
}

#[derive(Copy, Clone, Debug, Deserialize)]
pub enum Protocol {
    Icmp,
    Udp,
    Tcp,
}

impl From<Protocol> for trippy_core::Protocol {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::Icmp => Self::Icmp,
            Protocol::Udp => Self::Udp,
            Protocol::Tcp => Self::Tcp,
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub enum PortDirection {
    #[default]
    None,
    FixedSrc(u16),
    FixedDest(u16),
    FixedBoth(FixedBoth),
}

#[derive(Copy, Clone, Debug, Default, Deserialize)]
pub struct FixedBoth {
    pub src: u16,
    pub dest: u16,
}

impl From<PortDirection> for trippy_core::PortDirection {
    fn from(value: PortDirection) -> Self {
        match value {
            PortDirection::None => Self::None,
            PortDirection::FixedSrc(src) => Self::FixedSrc(Port(src)),
            PortDirection::FixedDest(dest) => Self::FixedDest(Port(dest)),
            PortDirection::FixedBoth(FixedBoth { src, dest }) => {
                Self::FixedBoth(Port(src), Port(dest))
            }
        }
    }
}

#[derive(Copy, Clone, Debug, Default, Deserialize)]
pub enum MultipathStrategy {
    #[default]
    Classic,
    Paris,
    Dublin,
}

impl From<MultipathStrategy> for trippy_core::MultipathStrategy {
    fn from(value: MultipathStrategy) -> Self {
        match value {
            MultipathStrategy::Classic => Self::Classic,
            MultipathStrategy::Paris => Self::Paris,
            MultipathStrategy::Dublin => Self::Dublin,
        }
    }
}
