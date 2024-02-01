use crate::config::{TuiColumn, TuiColumns};
use ratatui::layout::{Constraint, Rect};
use std::fmt::{Display, Formatter};

/// The columns to display in the hops table of the TUI.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Columns(pub Vec<Column>);

impl Columns {
    /// Column width constraints.
    ///
    /// All columns are returned as `Constraint::Min(width)`.
    ///
    /// For `Fixed(n)` columns the width is as specified in `n`.
    /// For `Variable` columns the width is calculated by subtracting the total
    /// size of all `Fixed` columns from the width of the containing `Rect` and
    /// dividing by the number of `Variable` columns.
    pub fn constraints(&self, rect: Rect) -> Vec<Constraint> {
        let total_fixed_width = self
            .0
            .iter()
            .map(|c| match c.width() {
                ColumnWidth::Fixed(width) => width,
                ColumnWidth::Variable => 0,
            })
            .sum();
        let variable_width_count = self
            .0
            .iter()
            .filter(|c| matches!(c.width(), ColumnWidth::Variable))
            .count() as u16;
        let variable_width =
            rect.width.saturating_sub(total_fixed_width) / variable_width_count.max(1);
        self.0
            .iter()
            .map(|c| match c.width() {
                ColumnWidth::Fixed(width) => Constraint::Min(width),
                ColumnWidth::Variable => Constraint::Min(variable_width),
            })
            .collect()
    }
}

impl From<TuiColumns> for Columns {
    fn from(value: TuiColumns) -> Self {
        Self(value.0.into_iter().map(Column::from).collect())
    }
}

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
}

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
            Column::Jitter => 'j',
            Column::Javg => 'g',
            Column::Jmax => 'x',
            Column::Jinta => 'i',
            Column::LastSrcPort => 'S',
            Column::LastDestPort => 'P',
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
            TuiColumn::Jitter => Self::Jitter,
            TuiColumn::Javg => Self::Javg,
            TuiColumn::Jmax => Self::Jmax,
            TuiColumn::Jinta => Self::Jinta,
            TuiColumn::LastSrcPort => Self::LastSrcPort,
            TuiColumn::LastDestPort => Self::LastDestPort,
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
            Self::Jitter => write!(f, "Jttr"),
            Self::Javg => write!(f, "Javg"),
            Self::Jmax => write!(f, "Jmax"),
            Self::Jinta => write!(f, "Jint"),
            Self::LastSrcPort => write!(f, "Sprt"),
            Self::LastDestPort => write!(f, "Dprt"),
        }
    }
}

impl Column {
    /// The width of the column.
    pub(self) fn width(self) -> ColumnWidth {
        #[allow(clippy::match_same_arms)]
        match self {
            Self::Ttl => ColumnWidth::Fixed(4),
            Self::Host => ColumnWidth::Variable,
            Self::LossPct => ColumnWidth::Fixed(8),
            Self::Sent => ColumnWidth::Fixed(7),
            Self::Received => ColumnWidth::Fixed(7),
            Self::Last => ColumnWidth::Fixed(7),
            Self::Average => ColumnWidth::Fixed(7),
            Self::Best => ColumnWidth::Fixed(7),
            Self::Worst => ColumnWidth::Fixed(7),
            Self::StdDev => ColumnWidth::Fixed(8),
            Self::Status => ColumnWidth::Fixed(7),
            Self::Jitter => ColumnWidth::Fixed(7),
            Self::Javg => ColumnWidth::Fixed(7),
            Self::Jmax => ColumnWidth::Fixed(7),
            Self::Jinta => ColumnWidth::Fixed(8),
            Self::LastSrcPort => ColumnWidth::Fixed(7),
            Self::LastDestPort => ColumnWidth::Fixed(7),
        }
    }
}

/// Table column layout constraints.
#[derive(Debug, PartialEq)]
enum ColumnWidth {
    /// A fixed size column.
    Fixed(u16),
    /// A column that will use the remaining space.
    Variable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::layout::Constraint::Min;
    use test_case::test_case;

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

    #[test_case(Column::Ttl, & ColumnWidth::Fixed(4))]
    #[test_case(Column::Host, & ColumnWidth::Variable)]
    #[test_case(Column::LossPct, & ColumnWidth::Fixed(8))]
    fn test_column_width(column_type: Column, width: &ColumnWidth) {
        assert_eq!(column_type.width(), *width);
    }

    #[test]
    fn test_column_constraints() {
        let columns = Columns::from(TuiColumns::default());
        let constraints = columns.constraints(Rect::new(0, 0, 80, 0));
        assert_eq!(
            vec![
                Min(4),
                Min(11),
                Min(8),
                Min(7),
                Min(7),
                Min(7),
                Min(7),
                Min(7),
                Min(7),
                Min(8),
                Min(7)
            ],
            constraints
        );
    }

    /// Expect to test the Column Into <char> flow.
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

    /// Happy path test for full set of columns.
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

    /// Reverse subset test for subset of columns.
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
