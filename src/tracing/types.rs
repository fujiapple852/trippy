use derive_more::{Add, AddAssign, From, Rem, Sub};

/// Round newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From, AddAssign)]
pub struct Round(pub usize);

/// Time-to-live (ttl) newtype.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From, Add, Sub, AddAssign,
)]
pub struct TimeToLive(pub u8);

/// Sequence number newtype.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From, Add, Sub, AddAssign, Rem,
)]
pub struct Sequence(pub u16);

/// Trace Identifier newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From)]
pub struct TraceId(pub u16);

/// Max Inflight newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From)]
pub struct MaxInflight(pub u8);

/// Trace Identifier newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, From)]
pub struct PacketSize(pub u16);

/// Max Inflight newtype.
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
