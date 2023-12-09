use crate::config::{TuiColumn, TuiColumns};
use std::fmt::{Display, Formatter};

/// The columns to display in the hops table of the TUI.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Columns(pub Vec<Column>);

impl From<TuiColumns> for Columns {
    fn from(value: TuiColumns) -> Self {
        Self(value.0.into_iter().map(Column::from).collect())
    }
}

/// A TUI hops table column.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Column {
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

impl From<TuiColumn> for Column {
    fn from(value: TuiColumn) -> Self {
        match value {
            TuiColumn::Ttl => Self::Ttl,
            TuiColumn::Host => Self::Host,
            TuiColumn::LossPct => Self::LossPct,
            TuiColumn::Sent => Self::Sent,
            TuiColumn::Received => Self::Received,
            TuiColumn::Last => Self::Last,
            TuiColumn::Average => Self::Average,
            TuiColumn::Best => Self::Best,
            TuiColumn::Worst => Self::Worst,
            TuiColumn::StdDev => Self::StdDev,
            TuiColumn::Status => Self::Status,
        }
    }
}

impl Display for Column {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ttl => write!(f, "#"),
            Self::Host => write!(f, "Host"),
            Self::LossPct => write!(f, "Loss%"),
            Self::Sent => write!(f, "Snd"),
            Self::Received => write!(f, "Recv"),
            Self::Last => write!(f, "Last"),
            Self::Average => write!(f, "Avg"),
            Self::Best => write!(f, "Best"),
            Self::Worst => write!(f, "Wrst"),
            Self::StdDev => write!(f, "StDev"),
            Self::Status => write!(f, "Sts"),
        }
    }
}

impl Column {
    /// TODO we should calculate width % based on which columns are preset
    pub fn width_pct(self) -> u16 {
        #[allow(clippy::match_same_arms)]
        match self {
            Self::Ttl => 3,
            Self::Host => 42,
            Self::LossPct => 5,
            Self::Sent => 5,
            Self::Received => 5,
            Self::Last => 5,
            Self::Average => 5,
            Self::Best => 5,
            Self::Worst => 5,
            Self::StdDev => 5,
            Self::Status => 5,
        }
    }
}
