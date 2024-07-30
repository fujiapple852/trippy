use crate::error::{Error, ErrorKind, IoResult, Result};
use std::io;
use std::net::SocketAddr;

/// Helper function to convert an `IoResult` to a `Result`.
///
/// The `AddressInUse` error is handled separately to allow for more specific
/// handling upstream.
pub fn process_result(addr: SocketAddr, res: IoResult<()>) -> Result<()> {
    match res {
        Ok(()) => Ok(()),
        Err(err) => match err.kind() {
            ErrorKind::InProgress => Ok(()),
            ErrorKind::Std(io::ErrorKind::AddrInUse) => Err(Error::AddressInUse(addr)),
            ErrorKind::Std(_) => Err(Error::IoError(err)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{IoError, IoOperation};
    use std::io;
    use std::net::{Ipv4Addr, SocketAddrV4};

    const ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

    #[test]
    fn test_ok() {
        let res = Ok(());
        let trace_res = process_result(ADDR, res);
        assert!(trace_res.is_ok());
    }

    #[test]
    fn test_err() {
        let io_error = io::Error::from(io::ErrorKind::ConnectionRefused);
        let res = Err(IoError::Connect(io_error, ADDR));
        let trace_res = process_result(ADDR, res);
        let trace_io_error = trace_res.unwrap_err();
        assert!(matches!(trace_io_error, Error::IoError(_)));
    }

    #[test]
    fn test_addr_in_use_err() {
        let io_error = io::Error::from(io::ErrorKind::AddrInUse);
        let res = Err(IoError::Other(io_error, IoOperation::Read));
        let trace_res = process_result(ADDR, res);
        let trace_err = trace_res.unwrap_err();
        assert!(matches!(trace_err, Error::AddressInUse(ADDR)));
    }

    #[test]
    fn test_addr_not_avail_err() {
        let io_error = io::Error::from(io::ErrorKind::AddrNotAvailable);
        let res = Err(IoError::Bind(io_error, ADDR));
        let trace_res = process_result(ADDR, res);
        let trace_err = trace_res.unwrap_err();
        assert!(matches!(trace_err, Error::IoError(_)));
    }

    #[test]
    fn test_in_progress_ok() {
        let io_error = io::Error::from(ErrorKind::InProgress);
        let res = Err(IoError::Other(io_error, IoOperation::Select));
        let trace_res = process_result(ADDR, res);
        assert!(trace_res.is_ok());
    }
}
