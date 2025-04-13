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
    /// The current jitter i.e. round-trip difference with the last round-trip.
    Jitter,
    /// The average jitter time for all probes at this hop.
    Javg,
    /// The worst round-trip jitter time for all probes at this hop.
    Jmax,
    /// The smoothed jitter value for all probes at this hop.
    Jinta,
    /// The source port for last probe for this hop.
    LastSrcPort,
    /// The destination port for last probe for this hop.
    LastDestPort,
    /// The sequence number for the last probe for this hop.
    LastSeq,
    /// The icmp packet type for the last probe for this hop.
    LastIcmpPacketType,
    /// The icmp packet code for the last probe for this hop.
    LastIcmpPacketCode,
    /// The NAT detection status for the last probe for this hop.
    LastNatStatus,
    /// The number of probes that failed for a hop.
    Failed,
    /// The number of probes with forward loss for a hop.
    Floss,
    /// The number of probes with backward loss for a hop.
    Bloss,
    /// The forward loss % for a hop.
    FlossPct,
    /// The Differentiated Services Code Point of the Original Datagram for a hop.
    Dscp,
    /// The Explicit Congestion Notification of the Original Datagram for a hop.
    Ecn,
}

impl TryFrom<char> for TuiColumn {
    type Error = anyhow::Error;

    fn try_from(value: char) -> Result<Self, Self::Error> {
        match value {
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
            'j' => Ok(Self::Jitter),
            'g' => Ok(Self::Javg),
            'x' => Ok(Self::Jmax),
            'i' => Ok(Self::Jinta),
            'S' => Ok(Self::LastSrcPort),
            'P' => Ok(Self::LastDestPort),
            'Q' => Ok(Self::LastSeq),
            'T' => Ok(Self::LastIcmpPacketType),
            'C' => Ok(Self::LastIcmpPacketCode),
            'N' => Ok(Self::LastNatStatus),
            'f' => Ok(Self::Failed),
            'F' => Ok(Self::Floss),
            'B' => Ok(Self::Bloss),
            'D' => Ok(Self::FlossPct),
            'K' => Ok(Self::Dscp),
            'M' => Ok(Self::Ecn),
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
            Self::Jitter => write!(f, "j"),
            Self::Javg => write!(f, "g"),
            Self::Jmax => write!(f, "x"),
            Self::Jinta => write!(f, "i"),
            Self::LastSrcPort => write!(f, "S"),
            Self::LastDestPort => write!(f, "P"),
            Self::LastSeq => write!(f, "Q"),
            Self::LastIcmpPacketType => write!(f, "T"),
            Self::LastIcmpPacketCode => write!(f, "C"),
            Self::LastNatStatus => write!(f, "N"),
            Self::Failed => write!(f, "f"),
            Self::Floss => write!(f, "F"),
            Self::Bloss => write!(f, "B"),
            Self::FlossPct => write!(f, "D"),
            Self::Dscp => write!(f, "K"),
            Self::Ecn => write!(f, "M"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    ///Test for expected column matches to characters
    #[test_case('h', TuiColumn::Ttl)]
    #[test_case('o', TuiColumn::Host)]
    #[test_case('l', TuiColumn::LossPct)]
    #[test_case('s', TuiColumn::Sent)]
    #[test_case('r', TuiColumn::Received)]
    #[test_case('a', TuiColumn::Last)]
    #[test_case('v', TuiColumn::Average)]
    #[test_case('b', TuiColumn::Best)]
    #[test_case('w', TuiColumn::Worst)]
    #[test_case('d', TuiColumn::StdDev)]
    #[test_case('t', TuiColumn::Status)]
    fn test_try_from_char_for_tui_column(c: char, t: TuiColumn) {
        assert_eq!(TuiColumn::try_from(c).unwrap(), t);
    }

    ///Negative test for invalid characters
    #[test_case('k' ; "invalid k")]
    #[test_case('z' ; "invalid z")]
    fn test_try_invalid_char_for_tui_column(c: char) {
        // Negative test for an unknown character
        assert!(TuiColumn::try_from(c).is_err());
    }

    ///Test for `TuiColumn` type match of Display
    #[test_case(TuiColumn::Ttl, "h")]
    #[test_case(TuiColumn::Host, "o")]
    #[test_case(TuiColumn::LossPct, "l")]
    #[test_case(TuiColumn::Sent, "s")]
    #[test_case(TuiColumn::Received, "r")]
    #[test_case(TuiColumn::Last, "a")]
    #[test_case(TuiColumn::Average, "v")]
    #[test_case(TuiColumn::Best, "b")]
    #[test_case(TuiColumn::Worst, "w")]
    #[test_case(TuiColumn::StdDev, "d")]
    #[test_case(TuiColumn::Status, "t")]
    fn test_display_formatting_for_tui_column(t: TuiColumn, letter: &'static str) {
        assert_eq!(format!("{t}"), letter);
    }

    #[test]
    fn test_try_from_str_for_tui_columns() {
        let valid_input = "hol";
        let tui_columns = TuiColumns::try_from(valid_input).unwrap();
        assert_eq!(
            tui_columns,
            TuiColumns(vec![TuiColumn::Ttl, TuiColumn::Host, TuiColumn::LossPct])
        );

        // Test for invalid characters in the input
        let invalid_input = "xyz";
        assert!(TuiColumns::try_from(invalid_input).is_err());
    }

    #[test]
    fn test_default_for_tui_columns() {
        let default_columns = TuiColumns::default();
        assert_eq!(
            default_columns,
            TuiColumns(vec![
                TuiColumn::Ttl,
                TuiColumn::Host,
                TuiColumn::LossPct,
                TuiColumn::Sent,
                TuiColumn::Received,
                TuiColumn::Last,
                TuiColumn::Average,
                TuiColumn::Best,
                TuiColumn::Worst,
                TuiColumn::StdDev,
                TuiColumn::Status
            ])
        );
    }

    #[test]
    fn test_find_duplicates_for_tui_columns() {
        let columns_with_duplicates = TuiColumns(vec![
            TuiColumn::Ttl,
            TuiColumn::Host,
            TuiColumn::LossPct,
            TuiColumn::Host, // Duplicate
        ]);

        let duplicates = columns_with_duplicates.find_duplicates();
        assert_eq!(duplicates, vec!["o".to_string()]);
    }
}
