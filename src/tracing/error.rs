use crate::tracing::util::RequiredError;
use std::io;
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

pub type TraceResult<T> = Result<T, TracerError>;

#[derive(Error, Debug)]
#[error("required value was not supplied")]
pub enum TracerError {
    #[error("invalid packet size: {0}")]
    InvalidPacketSize(usize),
    #[error("unknown interface: {0}")]
    UnknownInterface(String),
    #[error("invalid config: {0}")]
    BadConfig(String),
    #[error("missing required field: {0}")]
    Required(#[from] RequiredError),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("insufficient buffer capacity")]
    InsufficientCapacity,
    #[error("address not available: {0}")]
    AddressNotAvailable(SocketAddr),
    #[error("invalid source IP address: {0}")]
    InvalidSourceAddr(IpAddr),
    #[error("system error: {0}")]
    SystemError(String),
}
