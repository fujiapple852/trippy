use crate::error::{Error, IoResult, Result};
use crate::net::platform::in_progress_error;
use std::io::ErrorKind;
use std::net::SocketAddr;

/// Helper function to convert an `IoResult` to a `TraceResult` with special handling for
/// `AddressNotAvailable`.
pub fn process_result(addr: SocketAddr, res: IoResult<()>) -> Result<()> {
    match res {
        Ok(()) => Ok(()),
        Err(err) => {
            if err.raw_os_error() == in_progress_error().raw_os_error() {
                Ok(())
            } else {
                match err.kind() {
                    ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable => {
                        Err(Error::AddressNotAvailable(addr))
                    }
                    _ => Err(Error::IoError(err)),
                }
            }
        }
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
        let io_error = io::Error::from(ErrorKind::ConnectionRefused);
        let res = Err(IoError::Connect(io_error, ADDR));
        let trace_res = process_result(ADDR, res);
        let trace_io_error = trace_res.unwrap_err();
        assert!(matches!(trace_io_error, Error::IoError(_)));
    }

    #[test]
    fn test_addr_in_use_err() {
        let res = Err(IoError::Other(
            io::Error::from(ErrorKind::AddrInUse),
            IoOperation::Read,
        ));
        let trace_res = process_result(ADDR, res);
        let trace_err = trace_res.unwrap_err();
        assert!(matches!(trace_err, Error::AddressNotAvailable(ADDR)));
    }

    #[test]
    fn test_addr_not_avail_err() {
        let res = Err(IoError::Bind(
            io::Error::from(ErrorKind::AddrNotAvailable),
            ADDR,
        ));
        let trace_res = process_result(ADDR, res);
        let trace_err = trace_res.unwrap_err();
        assert!(matches!(trace_err, Error::AddressNotAvailable(ADDR)));
    }

    #[test]
    fn test_in_progress_ok() {
        let res = Err(IoError::Other(in_progress_error(), IoOperation::Select));
        let trace_res = process_result(ADDR, res);
        assert!(trace_res.is_ok());
    }
}
