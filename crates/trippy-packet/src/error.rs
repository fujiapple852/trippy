use thiserror::Error;

/// A packet error result.
pub type Result<T> = std::result::Result<T, Error>;

/// A packet error.
#[derive(Error, Debug, Eq, PartialEq)]
pub enum Error {
    /// Attempting to create a packet with an insufficient buffer size.
    #[error("insufficient buffer for {0} packet, minimum={1}, provided={2}")]
    InsufficientPacketBuffer(String, usize, usize),
}
