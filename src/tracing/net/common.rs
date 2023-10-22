use crate::tracing::error::TracerError::AddressNotAvailable;
use crate::tracing::error::{IoResult, TraceResult, TracerError};
use crate::tracing::net::platform;
use std::io::ErrorKind;
use std::net::SocketAddr;

/// Helper function to convert an `IoResult` to a `TraceResult` with special handling for `AddressNotAvailable`.
pub fn process_result(addr: SocketAddr, res: IoResult<()>) -> TraceResult<()> {
    match res {
        Ok(()) => Ok(()),
        Err(err) => {
            if let Some(code) = err.raw_os_error() {
                if platform::is_not_in_progress_error(code) {
                    match err.kind() {
                        ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable => {
                            Err(AddressNotAvailable(addr))
                        }
                        _ => Err(TracerError::IoError(err)),
                    }
                } else {
                    Ok(())
                }
            } else {
                Err(TracerError::IoError(err))
            }
        }
    }
}
