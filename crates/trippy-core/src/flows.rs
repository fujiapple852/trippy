use derive_more::{Add, AddAssign, Sub, SubAssign};
use itertools::{EitherOrBoth, Itertools};
use std::fmt::{Debug, Display, Formatter};
use std::net::IpAddr;
use tracing::instrument;

/// Identifies a tracing `Flow`.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Add,
    AddAssign,
    Sub,
    SubAssign,
)]
pub struct FlowId(pub u64);

impl Display for FlowId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A register of tracing `Flows`.
#[derive(Debug, Clone, Default)]
pub struct FlowRegistry {
    /// The id to assign to the next flow registered.
    next_flow_id: FlowId,
    /// The registry of flows observed.
    flows: Vec<(Flow, FlowId)>,
}

impl FlowRegistry {
    /// Create a new `FlowRegistry`.
    pub const fn new() -> Self {
        Self {
            flows: Vec::new(),
            next_flow_id: FlowId(1),
        }
    }

    /// Register a `Flow` with the `FlowRegistry`.
    ///
    /// If the flow matches a flow that has previously been observed by the registry then
    /// the id of that flow is return.  Otherwise, a new flow id is created and
    /// returned and the corresponding flow is stored in the registry.
    ///
    /// If the flow matches but also contains additional data not previously
    /// observed for that flow then the existing flow will be updated to
    /// merge the data.  In this case the existing flow id will be reused.
    ///
    /// If a flow matches more than one existing flow then only the first
    /// matching flow will be updated.
    #[instrument(skip(self), level = "trace")]
    pub fn register(&mut self, flow: Flow) -> FlowId {
        for (entry, id) in &mut self.flows {
            let status = entry.check(&flow);
            match status {
                CheckStatus::Match => {
                    return *id;
                }
                CheckStatus::NoMatch => {}
                CheckStatus::MatchMerge => {
                    entry.merge(&flow);
                    return *id;
                }
            }
        }
        let flow_id = self.next_flow_id;
        self.flows.push((flow, flow_id));
        self.next_flow_id.0 += 1;
        flow_id
    }

    /// All recorded flows.
    pub fn flows(&self) -> &[(Flow, FlowId)] {
        &self.flows
    }
}

/// Represents a single tracing path over a number of (possibly unknown) hops.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Flow {
    pub entries: Vec<FlowEntry>,
}

impl Flow {
    /// Create a new Flow from a slice of hops.
    ///
    /// Note that each entry is implicitly associated with a `ttl`.  For
    /// example `hops[0]` would have a `ttl` of 1, `hops[1]` would have a
    /// `ttl` of 2 and so on.
    pub fn from_hops(hops: impl IntoIterator<Item = Option<IpAddr>>) -> Self {
        let entries = hops
            .into_iter()
            .map(|addr| {
                if let Some(addr) = addr {
                    FlowEntry::Known(addr)
                } else {
                    FlowEntry::Unknown
                }
            })
            .collect();
        Self { entries }
    }

    /// Check if a given `Flow` matches this `Flow`.
    ///
    /// Two flows are said to match _unless_ they contain different IP
    /// addresses for the _same_ position (i.e. the same `ttl`).
    ///
    /// This is true even for flows of differing lengths.
    ///
    /// In the even of a match, if the flow being checked contains
    /// `FlowEntry::Known` entries which are `FlowEntry::Unknown` in the
    /// current flow then `CheckStatus::MatchMerge` is returned to indicate
    /// the two flows should be merged.
    ///
    /// This will also be the case if the flow being checked matches and is
    /// longer than the existing flow.
    #[instrument(skip(self), level = "trace")]
    pub fn check(&self, flow: &Self) -> CheckStatus {
        let mut additions = 0;
        for (old, new) in self.entries.iter().zip(&flow.entries) {
            match (old, new) {
                (FlowEntry::Known(fst), FlowEntry::Known(snd)) if fst != snd => {
                    return CheckStatus::NoMatch;
                }
                (FlowEntry::Unknown, FlowEntry::Known(_)) => additions += 1,
                _ => {}
            }
        }
        if flow.entries.len() > self.entries.len() || additions > 0 {
            CheckStatus::MatchMerge
        } else {
            CheckStatus::Match
        }
    }

    /// Marge the entries from the given `Flow` into our `Flow`.
    #[instrument(skip(self), level = "trace")]
    fn merge(&mut self, flow: &Self) {
        self.entries = self
            .entries
            .iter()
            .zip_longest(flow.entries.iter())
            .map(|eob| match eob {
                EitherOrBoth::Both(left, right) => match (left, right) {
                    (FlowEntry::Unknown, FlowEntry::Known(_)) => *right,
                    _ => *left,
                },
                EitherOrBoth::Left(left) => *left,
                EitherOrBoth::Right(right) => *right,
            })
            .collect::<Vec<_>>();
    }
}

impl Display for Flow {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.entries.iter().format(", "))
    }
}

/// The result of a `Flow` comparison check.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CheckStatus {
    /// The flows match.
    Match,
    /// The flows do not match.
    NoMatch,
    /// The flows match but should be merged.
    MatchMerge,
}

/// An entry in a `Flow`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum FlowEntry {
    /// An unknown flow entry.
    Unknown,
    /// A known flow entry with an `IpAddr`.
    Known(IpAddr),
}

impl Display for FlowEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => f.write_str("*"),
            Self::Known(addr) => {
                write!(f, "{addr}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_single_flow() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([addr("1.1.1.1")]);
        let flow_id = registry.register(flow1);
        assert_eq!(FlowId(1), flow_id);
        assert_eq!(
            &[(Flow::from_hops([addr("1.1.1.1")]), FlowId(1))],
            registry.flows()
        );
    }

    #[test]
    fn test_two_different_flows() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([addr("1.1.1.1")]);
        let flow1_id = registry.register(flow1.clone());
        let flow2 = Flow::from_hops([addr("2.2.2.2")]);
        let flow2_id = registry.register(flow2.clone());
        assert_eq!(FlowId(1), flow1_id);
        assert_eq!(FlowId(2), flow2_id);
        assert_eq!(&[(flow1, flow1_id), (flow2, flow2_id)], registry.flows());
    }

    #[test]
    fn test_two_same_flows() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([addr("1.1.1.1")]);
        let flow1_id = registry.register(flow1.clone());
        let flow2 = Flow::from_hops([addr("1.1.1.1")]);
        let flow2_id = registry.register(flow2);
        assert_eq!(FlowId(1), flow1_id);
        assert_eq!(FlowId(1), flow2_id);
        assert_eq!(&[(flow1, flow1_id)], registry.flows());
    }

    #[test]
    fn test_two_same_one_different_flows() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([addr("1.1.1.1")]);
        let flow1_id = registry.register(flow1.clone());
        let flow2 = Flow::from_hops([addr("2.2.2.2")]);
        let flow2_id = registry.register(flow2.clone());
        let flow3 = Flow::from_hops([addr("1.1.1.1")]);
        let flow3_id = registry.register(flow3);
        assert_eq!(FlowId(1), flow1_id);
        assert_eq!(FlowId(2), flow2_id);
        assert_eq!(FlowId(1), flow3_id);
        assert_eq!(&[(flow1, flow1_id), (flow2, flow2_id)], registry.flows());
    }

    #[test]
    fn test_merge_flow1() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([addr("1.1.1.1")]);
        let flow1_id = registry.register(flow1);
        let flow2 = Flow::from_hops([addr("1.1.1.1"), addr("2.2.2.2")]);
        let flow2_id = registry.register(flow2);
        let flow3 = Flow::from_hops([addr("1.1.1.1"), addr("2.2.2.2")]);
        let flow3_id = registry.register(flow3);
        let flow4 = Flow::from_hops([addr("1.1.1.1"), addr("3.3.3.3")]);
        let flow4_id = registry.register(flow4);
        let flow5 = Flow::from_hops([addr("1.1.1.1")]);
        let flow5_id = registry.register(flow5);
        assert_eq!(FlowId(1), flow1_id);
        assert_eq!(FlowId(1), flow2_id);
        assert_eq!(FlowId(1), flow3_id);
        assert_eq!(FlowId(2), flow4_id);
        assert_eq!(FlowId(1), flow5_id);
    }

    #[test]
    fn test_merge_flow2() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([addr("1.1.1.1"), addr("2.2.2.2"), addr("3.3.3.3")]);
        let flow1_id = registry.register(flow1);
        let flow2 = Flow::from_hops([addr("1.1.1.1"), addr("2.2.2.2")]);
        let flow2_id = registry.register(flow2);
        let flow3 = Flow::from_hops([addr("1.1.1.1"), addr("2.2.2.2")]);
        let flow3_id = registry.register(flow3);
        let flow4 = Flow::from_hops([addr("1.1.1.1"), addr("2.2.2.2"), addr("3.3.3.3")]);
        let flow4_id = registry.register(flow4);
        assert_eq!(FlowId(1), flow1_id);
        assert_eq!(FlowId(1), flow2_id);
        assert_eq!(FlowId(1), flow3_id);
        assert_eq!(FlowId(1), flow4_id);
    }

    #[test]
    fn test_merge_flow3() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([addr("1.1.1.1"), None, addr("3.3.3.3")]);
        let flow1_id = registry.register(flow1);
        // doesn't match so new flow
        let flow2 = Flow::from_hops([addr("2.2.2.2")]);
        let flow2_id = registry.register(flow2);
        // matches and replaces flow 0
        let flow3 = Flow::from_hops([
            None,
            addr("2.2.2.2"),
            None,
            addr("4.4.4.4"),
            addr("5.5.5.5"),
        ]);
        let flow3_id = registry.register(flow3);
        // still matches flow 1
        let flow4 = Flow::from_hops([addr("2.2.2.2")]);
        let flow4_id = registry.register(flow4);
        assert_eq!(FlowId(1), flow1_id);
        assert_eq!(FlowId(2), flow2_id);
        assert_eq!(FlowId(1), flow3_id);
        assert_eq!(FlowId(2), flow4_id);
    }

    #[test]
    fn test_subset() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([addr("1.1.1.1"), addr("2.2.2.2")]);
        let flow1_id = registry.register(flow1);
        let flow2 = Flow::from_hops([addr("1.1.1.1")]);
        let flow2_id = registry.register(flow2);
        assert_eq!(FlowId(1), flow1_id);
        assert_eq!(FlowId(1), flow2_id);
    }

    #[test]
    fn test_subset_any() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([addr("1.1.1.1"), addr("2.2.2.2")]);
        let flow1_id = registry.register(flow1);
        let flow2 = Flow::from_hops([addr("1.1.1.1"), None]);
        let flow2_id = registry.register(flow2);
        assert_eq!(FlowId(1), flow1_id);
        assert_eq!(FlowId(1), flow2_id);
    }

    #[test]
    fn test_superset() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([addr("1.1.1.1")]);
        let flow1_id = registry.register(flow1);
        let flow2 = Flow::from_hops([addr("1.1.1.1"), addr("2.2.2.2")]);
        let flow2_id = registry.register(flow2);
        assert_eq!(FlowId(1), flow1_id);
        assert_eq!(FlowId(1), flow2_id);
    }

    #[test]
    fn test_superset_any() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([addr("1.1.1.1"), None]);
        let flow1_id = registry.register(flow1);
        let flow2 = Flow::from_hops([addr("1.1.1.1"), addr("2.2.2.2")]);
        let flow2_id = registry.register(flow2);
        assert_eq!(FlowId(1), flow1_id);
        assert_eq!(FlowId(1), flow2_id);
    }

    #[test]
    fn test_start_any_then_same_flows() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([None, addr("1.1.1.1")]);
        let flow1_id = registry.register(flow1);
        let flow2 = Flow::from_hops([None, addr("1.1.1.1")]);
        let flow2_id = registry.register(flow2);
        assert_eq!(FlowId(1), flow1_id);
        assert_eq!(FlowId(1), flow2_id);
    }

    #[test]
    fn test_start_any_then_diff_flows() {
        let mut registry = FlowRegistry::new();
        let flow1 = Flow::from_hops([None, addr("1.1.1.1")]);
        let flow1_id = registry.register(flow1);
        let flow2 = Flow::from_hops([None, addr("2.2.2.2")]);
        let flow2_id = registry.register(flow2);
        assert_eq!(FlowId(1), flow1_id);
        assert_eq!(FlowId(2), flow2_id);
    }

    #[expect(clippy::unnecessary_wraps)]
    fn addr(addr: &str) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::from_str(addr).unwrap()))
    }
}
