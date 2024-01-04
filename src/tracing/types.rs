use derive_more::{Add, AddAssign, Rem, Sub};
use std::num::NonZeroUsize;

/// `Round` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, AddAssign)]
pub struct Round(pub usize);

/// `MaxRound` newtype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct MaxRounds(pub NonZeroUsize);

/// `TimeToLive` (ttl) newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, Add, Sub, AddAssign)]
pub struct TimeToLive(pub u8);

/// `Sequence` number newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd, Add, Sub, AddAssign, Rem)]
pub struct Sequence(pub u16);

/// `TraceId` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct TraceId(pub u16);

/// `MaxInflight` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct MaxInflight(pub u8);

/// `PacketSize` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct PacketSize(pub u16);

/// `PayloadPattern` newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct PayloadPattern(pub u8);

/// `TypeOfService` (aka `DSCP` & `ECN`) newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct TypeOfService(pub u8);

/// Port newtype.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Ord, PartialOrd)]
pub struct Port(pub u16);

impl From<Sequence> for usize {
    fn from(sequence: Sequence) -> Self {
        sequence.0 as Self
    }
}
