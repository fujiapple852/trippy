use thiserror::Error;

/// A packet error result.
pub type PacketResult<T> = Result<T, PacketError>;

/// A packet error.
#[derive(Error, Debug)]
pub enum PacketError {
    /// Attempting to create a packet with a insufficient buffer size.
    #[error("insufficient buffer for {0} packet, minimum={1}, provided={2}")]
    InsufficientPacketBuffer(String, usize, usize),
}
