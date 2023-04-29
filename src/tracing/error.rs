use crate::tracing::util::RequiredError;
use std::fmt::{Display, Formatter};
use std::io;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

/// A tracer error result.
pub type TraceResult<T> = Result<T, TracerError>;

/// A tracer error.
#[derive(Error, Debug)]
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
    IoError(#[from] IoError),
    #[error("insufficient buffer capacity")]
    InsufficientCapacity,
    #[error("address not available: {0}")]
    AddressNotAvailable(SocketAddr),
    #[error("invalid source IP address: {0}")]
    InvalidSourceAddr(IpAddr),
}

/// Custom IO error result.
pub type IoResult<T> = Result<T, IoError>;

/// Custom IO error.
#[derive(Error, Debug)]
pub enum IoError {
    #[error("Bind error for {1}: {0}")]
    Bind(io::Error, SocketAddr),
    #[error("Connect error for {1}: {0}")]
    Connect(io::Error, SocketAddr),
    #[error("Sendto error for {1}: {0}")]
    SendTo(io::Error, SocketAddr),
    #[error("Failed to {0}: {1}")]
    Other(io::Error, IoOperation),
}

impl IoError {
    pub fn raw_os_error(&self) -> Option<i32> {
        match self {
            Self::Bind(e, _) | Self::Connect(e, _) | Self::SendTo(e, _) | Self::Other(e, _) => {
                e.raw_os_error()
            }
        }
    }
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Bind(e, _) | Self::Connect(e, _) | Self::SendTo(e, _) | Self::Other(e, _) => {
                e.kind()
            }
        }
    }
}

/// Io operation.
#[derive(Debug)]
pub enum IoOperation {
    NewSocket,
    SetNonBlocking,
    Select,
    RecvFrom,
    Read,
    Shutdown,
    LocalAddr,
    PeerAddr,
    TakeError,
    SetTos,
    SetTtl,
    SetReusePort,
    SetHeaderIncluded,
    SetUnicastHopsV6,
    Close,
    WSACreateEvent,
    WSARecvFrom,
    WSAEventSelect,
    WSAResetEvent,
    WSAGetOverlappedResult,
    WaitForSingleObject,
    SetTcpFailConnectOnIcmpError,
    TcpIcmpErrorInfo,
    ConvertSocketAddress,
    SioRoutingInterfaceQuery,
    Startup,
}

impl Display for IoOperation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewSocket => write!(f, "create new socket"),
            Self::SetNonBlocking => write!(f, "set non-blocking"),
            Self::Select => write!(f, "select"),
            Self::RecvFrom => write!(f, "recv from"),
            Self::Read => write!(f, "read"),
            Self::Shutdown => write!(f, "shutdown"),
            Self::LocalAddr => write!(f, "local addr"),
            Self::PeerAddr => write!(f, "peer addr"),
            Self::TakeError => write!(f, "take error"),
            Self::SetTos => write!(f, "set TOS"),
            Self::SetTtl => write!(f, "set TTL"),
            Self::SetReusePort => write!(f, "set reuse port"),
            Self::SetHeaderIncluded => write!(f, "set header included"),
            Self::SetUnicastHopsV6 => write!(f, "set unicast hops v6"),
            Self::Close => write!(f, "close"),
            Self::WSACreateEvent => write!(f, "WSA create event"),
            Self::WSARecvFrom => write!(f, "WSA recv from"),
            Self::WSAEventSelect => write!(f, "WSA event select"),
            Self::WSAResetEvent => write!(f, "WSA reset event"),
            Self::WSAGetOverlappedResult => write!(f, "WSA get overlapped result"),
            Self::WaitForSingleObject => write!(f, "wait for single object"),
            Self::SetTcpFailConnectOnIcmpError => write!(f, "set TCP failed connect on ICMP error"),
            Self::TcpIcmpErrorInfo => write!(f, "get TCP ICMP error info"),
            Self::ConvertSocketAddress => write!(f, "convert socket address"),
            Self::SioRoutingInterfaceQuery => write!(f, "SIO routing interface query"),
            Self::Startup => write!(f, "startup"),
        }
    }
}
