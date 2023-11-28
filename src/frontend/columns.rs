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

///Settings pop-up depends on format macro
impl Display for Columns {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let output: Vec<char> = self.0.clone().into_iter().map(Column::into).collect();
        write!(f, "{}", String::from_iter(output))
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

//Output a char for each column type
impl From<Column> for char {
    fn from(col_type: Column) -> Self {
        match col_type {
            Column::Ttl => 'h',
            Column::Host => 'o',
            Column::LossPct => 'l',
            Column::Sent => 's',
            Column::Received => 'r',
            Column::Last => 'a',
            Column::Average => 'v',
            Column::Best => 'b',
            Column::Worst => 'w',
            Column::StdDev => 'd',
            Column::Status => 't',
        }
    }
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

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use crate::{
        config::{TuiColumn, TuiColumns},
        frontend::columns::{Column, Columns},
    };

    #[test]
    fn test_columns_conversion_from_tui_columns() {
        let tui_columns = TuiColumns(vec![
            TuiColumn::Ttl,
            TuiColumn::Host,
            TuiColumn::LossPct,
            TuiColumn::Sent,
        ]);

        let columns = Columns::from(tui_columns);

        assert_eq!(
            columns,
            Columns(vec![
                Column::Ttl,
                Column::Host,
                Column::LossPct,
                Column::Sent,
            ])
        );
    }

    #[test]
    fn test_column_conversion_from_tui_column() {
        let tui_column = TuiColumn::Received;
        let column = Column::from(tui_column);

        assert_eq!(column, Column::Received);
    }

    #[test_case(Column::Ttl, "#")]
    #[test_case(Column::Host, "Host")]
    #[test_case(Column::LossPct, "Loss%")]
    #[test_case(Column::Sent, "Snd")]
    #[test_case(Column::Received, "Recv")]
    #[test_case(Column::Last, "Last")]
    #[test_case(Column::Average, "Avg")]
    #[test_case(Column::Best, "Best")]
    #[test_case(Column::Worst, "Wrst")]
    #[test_case(Column::StdDev, "StDev")]
    #[test_case(Column::Status, "Sts")]
    fn test_column_display_formatting(c: Column, heading: &'static str) {
        assert_eq!(format!("{c}"), heading);
    }

    #[test_case(Column::Ttl, 3)]
    #[test_case(Column::Host, 42)]
    #[test_case(Column::LossPct, 5)]
    fn test_column_width_percentage(column_type: Column, pct: u16) {
        assert_eq!(column_type.width_pct(), pct);
    }

    ///Expect to test the Column Into <char> flow
    #[test]
    fn test_columns_into_string_short() {
        let cols = Columns(vec![
            Column::Ttl,
            Column::Host,
            Column::LossPct,
            Column::Sent,
        ]);
        assert_eq!("hols", format!("{cols}"));
    }

    ///Happy path test for full set of colummns
    #[test]
    fn test_columns_into_string_happy_path() {
        let cols = Columns(vec![
            Column::Ttl,
            Column::Host,
            Column::LossPct,
            Column::Sent,
            Column::Received,
            Column::Last,
            Column::Average,
            Column::Best,
            Column::Worst,
            Column::StdDev,
            Column::Status,
        ]);
        assert_eq!("holsravbwdt", format!("{cols}"));
    }

    ///Reverse subset test for subset of colummns
    #[test]
    fn test_columns_into_string_reverse_str() {
        let cols = Columns(vec![
            Column::Status,
            Column::Last,
            Column::StdDev,
            Column::Worst,
            Column::Best,
            Column::Average,
            Column::Received,
        ]);
        assert_eq!("tadwbvr", format!("{cols}"));
    }
}
