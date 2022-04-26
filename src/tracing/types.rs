use derive_more::{Add, AddAssign, From, Rem, Sub};

/// `Round` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From, AddAssign)]
pub struct Round(pub usize);

/// `TimeToLive` (ttl) newtype.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From, Add, Sub, AddAssign,
)]
pub struct TimeToLive(pub u8);

/// `Sequence` number newtype.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From, Add, Sub, AddAssign, Rem,
)]
pub struct Sequence(pub u16);

/// `TraceId` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From)]
pub struct TraceId(pub u16);

/// `MaxInflight` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From)]
pub struct MaxInflight(pub u8);

/// `PacketSize` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From)]
pub struct PacketSize(pub u16);

/// `PayloadPattern` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From)]
pub struct PayloadPattern(pub u8);

impl From<Sequence> for usize {
    fn from(sequence: Sequence) -> Self {
        sequence.0 as Self
    }
}

/// Source port newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From)]
pub struct SourcePort(pub u16);

impl From<Sequence> for usize {
    fn from(sequence: Sequence) -> Self {
        sequence.0 as Self
    }
}
