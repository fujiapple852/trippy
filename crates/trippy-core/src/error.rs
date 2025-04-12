use std::fmt::{Display, Formatter};
use std::io;
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

/// A tracer error result.
pub type Result<T> = std::result::Result<T, Error>;

/// A tracer error.
#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid packet size: {0}")]
    InvalidPacketSize(usize),
    #[error("invalid packet: {0}")]
    PacketError(#[from] trippy_packet::error::Error),
    #[error("unknown interface: {0}")]
    UnknownInterface(String),
    #[error("invalid config: {0}")]
    BadConfig(String),
    #[error("IO error: {0}")]
    IoError(#[from] IoError),
    #[error("Probe failed to send: {0}")]
    ProbeFailed(IoError),
    #[error("insufficient buffer capacity")]
    InsufficientCapacity,
    #[error("address {0} in use")]
    AddressInUse(SocketAddr),
    #[error("source IP address {0} could not be bound")]
    InvalidSourceAddr(IpAddr),
    #[error("missing address from socket call")]
    MissingAddr,
    #[error("connect callback error: {0}")]
    PrivilegeError(#[from] trippy_privilege::Error),
    #[error("tracer error: {0}")]
    Other(String),
}

/// Custom IO error result.
pub type IoResult<T> = std::result::Result<T, IoError>;

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
    /// Get the custom error kind.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Bind(e, _) | Self::Connect(e, _) | Self::SendTo(e, _) | Self::Other(e, _) => {
                ErrorKind::from(e)
            }
        }
    }
}

/// Custom error kind.
///
/// This includes additional error kinds that are not part of the standard [`io::ErrorKind`].
#[derive(Debug, Eq, PartialEq)]
pub enum ErrorKind {
    InProgress,
    HostUnreachable,
    NetUnreachable,
    Std(io::ErrorKind),
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
    SetTclassV6,
    SetTtl,
    SetReusePort,
    SetHeaderIncluded,
    SetUnicastHopsV6,
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
            Self::SetTclassV6 => write!(f, "set TCLASS v6"),
            Self::SetTtl => write!(f, "set TTL"),
            Self::SetReusePort => write!(f, "set reuse port"),
            Self::SetHeaderIncluded => write!(f, "set header included"),
            Self::SetUnicastHopsV6 => write!(f, "set unicast hops v6"),
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
