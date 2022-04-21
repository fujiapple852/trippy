use crate::icmp::util::RequiredError;
use std::io;
use thiserror::Error;

pub type TraceResult<T> = Result<T, TracerError>;

#[derive(Error, Debug)]
#[error("required value was not supplied")]
pub enum TracerError {
    Generic,
    #[error("invalid packet size: {0}")]
    InvalidPacketSize(usize),
    #[error("missing required field: {0}")]
    Required(#[from] RequiredError),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
}
