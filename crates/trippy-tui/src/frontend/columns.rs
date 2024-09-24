use crate::config::{TuiColumn, TuiColumns};
use ratatui::layout::{Constraint, Rect};
use std::fmt::{Display, Formatter};
use strum::{EnumIter, IntoEnumIterator};

/// The columns to display in the hops table of the TUI.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Columns(Vec<Column>);

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
            .columns()
            .map(|c| match c.typ.width() {
                ColumnWidth::Fixed(width) => width,
                ColumnWidth::Variable => 0,
            })
            .sum();
        let variable_width_count = self
            .columns()
            .filter(|c| matches!(c.typ.width(), ColumnWidth::Variable))
            .count() as u16;
        let variable_width =
            rect.width.saturating_sub(total_fixed_width) / variable_width_count.max(1);
        self.columns()
            .map(|c| match c.typ.width() {
                ColumnWidth::Fixed(width) => Constraint::Min(width),
                ColumnWidth::Variable => Constraint::Min(variable_width),
            })
            .collect()
    }

    pub fn columns(&self) -> impl Iterator<Item = &Column> {
        self.0
            .iter()
            .filter(|c| matches!(c.status, ColumnStatus::Shown))
    }

    pub fn all_columns(&self) -> impl Iterator<Item = &Column> {
        self.0.iter()
    }

    pub fn all_columns_count(&self) -> usize {
        self.0.len()
    }

    pub fn toggle(&mut self, index: usize) {
        self.0[index].status = match self.0[index].status {
            ColumnStatus::Shown => ColumnStatus::Hidden,
            ColumnStatus::Hidden => ColumnStatus::Shown,
        };
    }

    pub fn move_down(&mut self, index: usize) {
        if index < self.0.len() {
            let removed = self.0.remove(index);
            self.0.insert(index + 1, removed);
        }
    }

    pub fn move_up(&mut self, index: usize) {
        if index > 0 {
            let removed = self.0.remove(index);
            self.0.insert(index - 1, removed);
        }
    }
}

impl From<TuiColumns> for Columns {
    fn from(value: TuiColumns) -> Self {
        let enabled: Vec<_> = value.0.into_iter().map(Column::from).collect();
        let disabled: Vec<_> = ColumnType::iter()
            .filter(|ct| enabled.iter().all(|c| c.typ != *ct))
            .map(Column::new_hidden)
            .collect();
        let all = enabled.into_iter().chain(disabled).collect();
        Self(all)
    }
}

impl Display for Columns {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let output: Vec<char> = self
            .0
            .iter()
            .filter_map(|c| {
                if c.status == ColumnStatus::Shown {
                    Some(c.typ.into())
                } else {
                    None
                }
            })
            .collect();
        write!(f, "{}", String::from_iter(output))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Column {
    pub typ: ColumnType,
    pub status: ColumnStatus,
}

impl Column {
    pub const fn new_shown(typ: ColumnType) -> Self {
        Self {
            typ,
            status: ColumnStatus::Shown,
        }
    }
    pub const fn new_hidden(typ: ColumnType) -> Self {
        Self {
            typ,
            status: ColumnStatus::Hidden,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ColumnStatus {
    Shown,
    Hidden,
}

impl Display for ColumnStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shown => write!(f, "on"),
            Self::Hidden => write!(f, "off"),
        }
    }
}

/// A TUI hops table column.
#[derive(Debug, Copy, Clone, Eq, PartialEq, EnumIter)]
pub enum ColumnType {
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
    /// The number of probes with forward loss.
    Floss,
    /// The number of probes with backward loss.
    Bloss,
    /// The loss percentage adjusted for back and forward loss.
    AdjustedLossPct,
}

impl From<ColumnType> for char {
    fn from(col_type: ColumnType) -> Self {
        match col_type {
            ColumnType::Ttl => 'h',
            ColumnType::Host => 'o',
            ColumnType::LossPct => 'l',
            ColumnType::Sent => 's',
            ColumnType::Received => 'r',
            ColumnType::Last => 'a',
            ColumnType::Average => 'v',
            ColumnType::Best => 'b',
            ColumnType::Worst => 'w',
            ColumnType::StdDev => 'd',
            ColumnType::Status => 't',
            ColumnType::Jitter => 'j',
            ColumnType::Javg => 'g',
            ColumnType::Jmax => 'x',
            ColumnType::Jinta => 'i',
            ColumnType::LastSrcPort => 'S',
            ColumnType::LastDestPort => 'P',
            ColumnType::LastSeq => 'Q',
            ColumnType::LastIcmpPacketType => 'T',
            ColumnType::LastIcmpPacketCode => 'C',
            ColumnType::LastNatStatus => 'N',
            ColumnType::Failed => 'f',
            ColumnType::Floss => 'F',
            ColumnType::Bloss => 'B',
            ColumnType::AdjustedLossPct => 'A',
        }
    }
}

impl From<TuiColumn> for Column {
    fn from(value: TuiColumn) -> Self {
        match value {
            TuiColumn::Ttl => Self::new_shown(ColumnType::Ttl),
            TuiColumn::Host => Self::new_shown(ColumnType::Host),
            TuiColumn::LossPct => Self::new_shown(ColumnType::LossPct),
            TuiColumn::Sent => Self::new_shown(ColumnType::Sent),
            TuiColumn::Received => Self::new_shown(ColumnType::Received),
            TuiColumn::Last => Self::new_shown(ColumnType::Last),
            TuiColumn::Average => Self::new_shown(ColumnType::Average),
            TuiColumn::Best => Self::new_shown(ColumnType::Best),
            TuiColumn::Worst => Self::new_shown(ColumnType::Worst),
            TuiColumn::StdDev => Self::new_shown(ColumnType::StdDev),
            TuiColumn::Status => Self::new_shown(ColumnType::Status),
            TuiColumn::Jitter => Self::new_shown(ColumnType::Jitter),
            TuiColumn::Javg => Self::new_shown(ColumnType::Javg),
            TuiColumn::Jmax => Self::new_shown(ColumnType::Jmax),
            TuiColumn::Jinta => Self::new_shown(ColumnType::Jinta),
            TuiColumn::LastSrcPort => Self::new_shown(ColumnType::LastSrcPort),
            TuiColumn::LastDestPort => Self::new_shown(ColumnType::LastDestPort),
            TuiColumn::LastSeq => Self::new_shown(ColumnType::LastSeq),
            TuiColumn::LastIcmpPacketType => Self::new_shown(ColumnType::LastIcmpPacketType),
            TuiColumn::LastIcmpPacketCode => Self::new_shown(ColumnType::LastIcmpPacketCode),
            TuiColumn::LastNatStatus => Self::new_shown(ColumnType::LastNatStatus),
            TuiColumn::Failed => Self::new_shown(ColumnType::Failed),
            TuiColumn::Floss => Self::new_shown(ColumnType::Floss),
            TuiColumn::Bloss => Self::new_shown(ColumnType::Bloss),
            TuiColumn::AdjustedLossPct => Self::new_shown(ColumnType::AdjustedLossPct),
        }
    }
}

impl Display for ColumnType {
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
            Self::LastSeq => write!(f, "Seq"),
            Self::LastIcmpPacketType => write!(f, "Type"),
            Self::LastIcmpPacketCode => write!(f, "Code"),
            Self::LastNatStatus => write!(f, "Nat"),
            Self::Failed => write!(f, "Fail"),
            Self::Floss => write!(f, "Floss"),
            Self::Bloss => write!(f, "Bloss"),
            Self::AdjustedLossPct => write!(f, "ALoss%"),
        }
    }
}

impl ColumnType {
    /// The width of the column.
    pub(self) const fn width(self) -> ColumnWidth {
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
            Self::LastSeq => ColumnWidth::Fixed(7),
            Self::LastIcmpPacketType => ColumnWidth::Fixed(7),
            Self::LastIcmpPacketCode => ColumnWidth::Fixed(7),
            Self::LastNatStatus => ColumnWidth::Fixed(7),
            Self::Failed => ColumnWidth::Fixed(7),
            Self::Floss => ColumnWidth::Fixed(7),
            Self::Bloss => ColumnWidth::Fixed(7),
            Self::AdjustedLossPct => ColumnWidth::Fixed(8),
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
            TuiColumn::Received,
            TuiColumn::Last,
            TuiColumn::Average,
            TuiColumn::Best,
            TuiColumn::Worst,
            TuiColumn::StdDev,
            TuiColumn::Status,
        ]);
        let columns = Columns::from(tui_columns);
        assert_eq!(
            columns,
            Columns(vec![
                Column::new_shown(ColumnType::Ttl),
                Column::new_shown(ColumnType::Host),
                Column::new_shown(ColumnType::LossPct),
                Column::new_shown(ColumnType::Sent),
                Column::new_shown(ColumnType::Received),
                Column::new_shown(ColumnType::Last),
                Column::new_shown(ColumnType::Average),
                Column::new_shown(ColumnType::Best),
                Column::new_shown(ColumnType::Worst),
                Column::new_shown(ColumnType::StdDev),
                Column::new_shown(ColumnType::Status),
                Column::new_hidden(ColumnType::Jitter),
                Column::new_hidden(ColumnType::Javg),
                Column::new_hidden(ColumnType::Jmax),
                Column::new_hidden(ColumnType::Jinta),
                Column::new_hidden(ColumnType::LastSrcPort),
                Column::new_hidden(ColumnType::LastDestPort),
                Column::new_hidden(ColumnType::LastSeq),
                Column::new_hidden(ColumnType::LastIcmpPacketType),
                Column::new_hidden(ColumnType::LastIcmpPacketCode),
                Column::new_hidden(ColumnType::LastNatStatus),
                Column::new_hidden(ColumnType::Failed),
                Column::new_hidden(ColumnType::Floss),
                Column::new_hidden(ColumnType::Bloss),
                Column::new_hidden(ColumnType::AdjustedLossPct),
            ])
        );
    }

    #[test]
    fn test_column_conversion_from_tui_column() {
        let tui_column = TuiColumn::Received;
        let column = Column::from(tui_column);

        assert_eq!(column.typ, ColumnType::Received);
        assert_eq!(column.status, ColumnStatus::Shown);
    }

    #[test_case(ColumnType::Ttl, "#")]
    #[test_case(ColumnType::Host, "Host")]
    #[test_case(ColumnType::LossPct, "Loss%")]
    #[test_case(ColumnType::Sent, "Snd")]
    #[test_case(ColumnType::Received, "Recv")]
    #[test_case(ColumnType::Last, "Last")]
    #[test_case(ColumnType::Average, "Avg")]
    #[test_case(ColumnType::Best, "Best")]
    #[test_case(ColumnType::Worst, "Wrst")]
    #[test_case(ColumnType::StdDev, "StDev")]
    #[test_case(ColumnType::Status, "Sts")]
    fn test_column_display_formatting(c: ColumnType, heading: &'static str) {
        assert_eq!(format!("{c}"), heading);
    }

    #[test_case(ColumnType::Ttl, & ColumnWidth::Fixed(4))]
    #[test_case(ColumnType::Host, & ColumnWidth::Variable)]
    #[test_case(ColumnType::LossPct, & ColumnWidth::Fixed(8))]
    fn test_column_width(column_type: ColumnType, width: &ColumnWidth) {
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
            Column::new_shown(ColumnType::Ttl),
            Column::new_shown(ColumnType::Host),
            Column::new_shown(ColumnType::LossPct),
            Column::new_shown(ColumnType::Sent),
        ]);
        assert_eq!("hols", format!("{cols}"));
    }

    /// Happy path test for full set of columns.
    #[test]
    fn test_columns_into_string_happy_path() {
        let cols = Columns(vec![
            Column::new_shown(ColumnType::Ttl),
            Column::new_shown(ColumnType::Host),
            Column::new_shown(ColumnType::LossPct),
            Column::new_shown(ColumnType::Sent),
            Column::new_shown(ColumnType::Received),
            Column::new_shown(ColumnType::Last),
            Column::new_shown(ColumnType::Average),
            Column::new_shown(ColumnType::Best),
            Column::new_shown(ColumnType::Worst),
            Column::new_shown(ColumnType::StdDev),
            Column::new_shown(ColumnType::Status),
        ]);
        assert_eq!("holsravbwdt", format!("{cols}"));
    }

    /// Reverse subset test for subset of columns.
    #[test]
    fn test_columns_into_string_reverse_str() {
        let cols = Columns(vec![
            Column::new_shown(ColumnType::Status),
            Column::new_shown(ColumnType::Last),
            Column::new_shown(ColumnType::StdDev),
            Column::new_shown(ColumnType::Worst),
            Column::new_shown(ColumnType::Best),
            Column::new_shown(ColumnType::Average),
            Column::new_shown(ColumnType::Received),
        ]);
        assert_eq!("tadwbvr", format!("{cols}"));
    }
}
