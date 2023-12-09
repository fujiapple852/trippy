use anyhow::anyhow;
use itertools::Itertools;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};

/// The columns to display in the hops table of the TUI.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TuiColumns(pub Vec<TuiColumn>);

impl TryFrom<&str> for TuiColumns {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Self(
            value
                .chars()
                .map(TuiColumn::try_from)
                .collect::<Result<Vec<_>, Self::Error>>()?,
        ))
    }
}

impl Default for TuiColumns {
    fn default() -> Self {
        Self::try_from(super::constants::DEFAULT_CUSTOM_COLUMNS).expect("custom columns")
    }
}

impl TuiColumns {
    /// Validate the columns.
    ///
    /// Returns any duplicate columns.
    pub fn find_duplicates(&self) -> Vec<String> {
        let (_, duplicates) = self.0.iter().fold(
            (HashSet::<TuiColumn>::new(), Vec::new()),
            |(mut all, mut dups), column| {
                if all.iter().contains(column) {
                    dups.push(column.to_string());
                } else {
                    all.insert(*column);
                }
                (all, dups)
            },
        );
        duplicates
    }
}

/// A TUI hops table column.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum TuiColumn {
    /// The ttl for a hop.
    Ttl,
    /// The hostname for a hostname.
    Host,
    /// The packet loss % for a hop.
    LossPct,
    /// The number of probes sent for a hop.
    Sent,
    /// The number of responses received for a hop.
    Received,
    /// The last RTT for a hop.
    Last,
    /// The rolling average RTT for a hop.
    Average,
    /// The best RTT for a hop.
    Best,
    /// The worst RTT for a hop.
    Worst,
    /// The stddev of RTT for a hop.
    StdDev,
    /// The status of a hop.
    Status,
}

impl TryFrom<char> for TuiColumn {
    type Error = anyhow::Error;

    fn try_from(value: char) -> Result<Self, Self::Error> {
        match value.to_ascii_lowercase() {
            'h' => Ok(Self::Ttl),
            'o' => Ok(Self::Host),
            'l' => Ok(Self::LossPct),
            's' => Ok(Self::Sent),
            'r' => Ok(Self::Received),
            'a' => Ok(Self::Last),
            'v' => Ok(Self::Average),
            'b' => Ok(Self::Best),
            'w' => Ok(Self::Worst),
            'd' => Ok(Self::StdDev),
            't' => Ok(Self::Status),
            c => Err(anyhow!(format!("unknown column code: {c}"))),
        }
    }
}

impl Display for TuiColumn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ttl => write!(f, "h"),
            Self::Host => write!(f, "o"),
            Self::LossPct => write!(f, "l"),
            Self::Sent => write!(f, "s"),
            Self::Received => write!(f, "r"),
            Self::Last => write!(f, "a"),
            Self::Average => write!(f, "v"),
            Self::Best => write!(f, "b"),
            Self::Worst => write!(f, "w"),
            Self::StdDev => write!(f, "d"),
            Self::Status => write!(f, "t"),
        }
    }
}
