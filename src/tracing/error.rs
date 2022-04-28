use crate::tracing::util::RequiredError;
use std::io;
use thiserror::Error;

pub type TraceResult<T> = Result<T, TracerError>;

#[derive(Error, Debug)]
#[error("required value was not supplied")]
pub enum TracerError {
    #[error("invalid packet size: {0}")]
    InvalidPacketSize(usize),
    #[error("invalid config: {0}")]
    BadConfig(String),
    #[error("missing required field: {0}")]
    Required(#[from] RequiredError),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
}
