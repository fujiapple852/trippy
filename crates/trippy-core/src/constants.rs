/// The maximum time-to-live value allowed.
///
/// The IP `ttl` is an u8 (0..255) but since a `ttl` of zero isn't useful we only allow 254 distinct
/// hops (1..255).
pub const MAX_TTL: u8 = 254;

/// The maximum number of sequence numbers allowed per round.
///
/// This is set to be far larger than the `MAX_TTL` to allow for the re-issue of probes (with the
/// next sequence number, but the same ttl) which can occur for some protocols such as TCP when it
/// cannot bind to a given port.
pub const MAX_SEQUENCE_PER_ROUND: u16 = 512;

/// The maximum _starting_ sequence number allowed.
///
/// This ensures that there are sufficient sequence numbers available for at least _two_ rounds.  We
/// require two rounds to ensure that delayed probe responses from the immediate prior round can be
/// detected and excluded.
pub const MAX_INITIAL_SEQUENCE: u16 = u16::MAX - (MAX_SEQUENCE_PER_ROUND * 2);
