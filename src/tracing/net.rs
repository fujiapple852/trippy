use crate::tracing::error::TracerError::{AddressNotAvailable, InvalidSourceAddr};
use crate::tracing::error::{TraceResult, TracerError};
use crate::tracing::net::platform::{discover_ip_length_byte_order, Ipv4TotalLengthByteOrder};
use crate::tracing::types::{PacketSize, PayloadPattern, Port, TraceId, TypeOfService};
use crate::tracing::util::Required;
use crate::tracing::{PortDirection, Probe, TracerAddrFamily, TracerChannelConfig, TracerProtocol};
use arrayvec::ArrayVec;
use itertools::Itertools;
use nix::sys::select::FdSet;
use nix::sys::time::{TimeVal, TimeValLike};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, SystemTime};

/// IPv4 implementation.
mod ipv4;

/// IPv6 implementation.
mod ipv6;

/// Platform specific network code.
mod platform;

/// The response to a probe.
#[derive(Debug, Copy, Clone)]
pub enum ProbeResponse {
    TimeExceeded(ProbeResponseData),
    DestinationUnreachable(ProbeResponseData),
    EchoReply(ProbeResponseData),
    TcpReply(TcpProbeResponseData),
    TcpRefused(TcpProbeResponseData),
}

/// The data in the probe response.
#[derive(Debug, Copy, Clone)]
pub struct ProbeResponseData {
    pub recv: SystemTime,
    pub addr: IpAddr,
    pub identifier: u16,
    pub sequence: u16,
}

impl ProbeResponseData {
    fn new(recv: SystemTime, addr: IpAddr, identifier: u16, sequence: u16) -> Self {
        Self {
            recv,
            addr,
            identifier,
            sequence,
        }
    }
}

/// The data in the TCP probe response.
#[derive(Debug, Copy, Clone)]
pub struct TcpProbeResponseData {
    pub recv: SystemTime,
    pub addr: IpAddr,
    pub ttl: u8,
}

impl TcpProbeResponseData {
    fn new(recv: SystemTime, addr: IpAddr, ttl: u8) -> Self {
        Self { recv, addr, ttl }
    }
}

/// An abstraction over a network interface for tracing.
pub trait Network {
    /// Send a `Probe`
    fn send_probe(&mut self, probe: Probe) -> TraceResult<()>;

    /// Receive the next Icmp packet and return a `ProbeResponse`.
    ///
    /// Returns `None` if the read times out or the packet read is not one of the types expected.
    fn recv_probe(&mut self) -> TraceResult<Option<ProbeResponse>>;
}

/// The maximum number of TCP probes we allow.
const MAX_TCP_PROBES: usize = 256;

/// The maximum size of the IP packet we allow.
const MAX_PACKET_SIZE: usize = 1024;

/// The port used for local address discovery if not dest port is available.
const DISCOVERY_PORT: Port = Port(80);

/// An entry in the TCP probes array.
#[derive(Debug)]
struct TcpProbe {
    socket: Socket,
    start: SystemTime,
}

impl TcpProbe {
    pub fn new(socket: Socket, start: SystemTime) -> Self {
        Self { socket, start }
    }
}

/// A channel for sending and receiving `ICMP` packets.
pub struct TracerChannel {
    protocol: TracerProtocol,
    addr_family: TracerAddrFamily,
    src_addr: IpAddr,
    ipv4_length_order: Ipv4TotalLengthByteOrder,
    dest_addr: IpAddr,
    identifier: TraceId,
    packet_size: PacketSize,
    payload_pattern: PayloadPattern,
    tos: TypeOfService,
    port_direction: PortDirection,
    tcp_connect_timeout: Duration,
    icmp_send_socket: Socket,
    udp_send_socket: Socket,
    recv_socket: Socket,
    tcp_probes: ArrayVec<TcpProbe, MAX_TCP_PROBES>,
}

impl TracerChannel {
    /// Create an `IcmpChannel`.
    ///
    /// This operation requires the `CAP_NET_RAW` capability on Linux.
    pub fn connect(config: &TracerChannelConfig) -> TraceResult<Self> {
        if usize::from(config.packet_size.0) > MAX_PACKET_SIZE {
            return Err(TracerError::InvalidPacketSize(usize::from(
                config.packet_size.0,
            )));
        }
        let src_addr = make_src_addr(
            config.source_addr,
            config.target_addr,
            config.port_direction,
            config.interface.as_deref(),
            config.addr_family,
        )?;
        let ipv4_length_order = discover_ip_length_byte_order(src_addr)?;
        let icmp_send_socket = make_icmp_send_socket(config.addr_family)?;
        let udp_send_socket = make_udp_send_socket(config.addr_family)?;
        let recv_socket = make_recv_socket(config.addr_family)?;
        Ok(Self {
            protocol: config.protocol,
            addr_family: config.addr_family,
            src_addr,
            ipv4_length_order,
            dest_addr: config.target_addr,
            identifier: config.identifier,
            packet_size: config.packet_size,
            payload_pattern: config.payload_pattern,
            tos: config.tos,
            port_direction: config.port_direction,
            tcp_connect_timeout: config.tcp_connect_timeout,
            icmp_send_socket,
            udp_send_socket,
            recv_socket,
            tcp_probes: ArrayVec::new(),
        })
    }

    /// Get the source `IpAddr` of the channel.
    #[must_use]
    pub fn src_addr(&self) -> IpAddr {
        self.src_addr
    }
}

impl Network for TracerChannel {
    fn send_probe(&mut self, probe: Probe) -> TraceResult<()> {
        match self.protocol {
            TracerProtocol::Icmp => self.dispatch_icmp_probe(probe),
            TracerProtocol::Udp => self.dispatch_udp_probe(probe),
            TracerProtocol::Tcp => self.dispatch_tcp_probe(probe),
        }
    }

    fn recv_probe(&mut self) -> TraceResult<Option<ProbeResponse>> {
        match self.protocol {
            TracerProtocol::Icmp | TracerProtocol::Udp => self.recv_icmp_probe(),
            TracerProtocol::Tcp => Ok(self.recv_tcp_sockets()?.or(self.recv_icmp_probe()?)),
        }
    }
}

impl TracerChannel {
    fn dispatch_icmp_probe(&mut self, probe: Probe) -> TraceResult<()> {
        match (self.addr_family, self.src_addr, self.dest_addr) {
            (TracerAddrFamily::Ipv4, IpAddr::V4(src_addr), IpAddr::V4(dest_addr)) => {
                ipv4::dispatch_icmp_probe(
                    &mut self.icmp_send_socket,
                    probe,
                    src_addr,
                    dest_addr,
                    self.identifier,
                    self.packet_size,
                    self.payload_pattern,
                    self.ipv4_length_order,
                )
            }
            (TracerAddrFamily::Ipv6, IpAddr::V6(src_addr), IpAddr::V6(dest_addr)) => {
                ipv6::dispatch_icmp_probe(
                    &mut self.icmp_send_socket,
                    probe,
                    src_addr,
                    dest_addr,
                    self.identifier,
                    self.packet_size,
                    self.payload_pattern,
                )
            }
            _ => unreachable!(),
        }
    }

    /// Dispatch a UDP probe.
    ///
    /// This covers both the IPv4 and IPv6 cases.
    fn dispatch_udp_probe(&mut self, probe: Probe) -> TraceResult<()> {
        match (self.addr_family, self.src_addr, self.dest_addr) {
            (TracerAddrFamily::Ipv4, IpAddr::V4(src_addr), IpAddr::V4(dest_addr)) => {
                ipv4::dispatch_udp_probe(
                    &mut self.udp_send_socket,
                    probe,
                    src_addr,
                    dest_addr,
                    self.port_direction,
                    self.packet_size,
                    self.payload_pattern,
                    self.ipv4_length_order,
                )
            }
            (TracerAddrFamily::Ipv6, IpAddr::V6(src_addr), IpAddr::V6(dest_addr)) => {
                ipv6::dispatch_udp_probe(
                    &mut self.udp_send_socket,
                    probe,
                    src_addr,
                    dest_addr,
                    self.port_direction,
                    self.packet_size,
                    self.payload_pattern,
                )
            }
            _ => unreachable!(),
        }
    }

    /// Dispatch a TCP probe.
    ///
    /// This covers both the IPv4 and IPv6 cases.
    fn dispatch_tcp_probe(&mut self, probe: Probe) -> TraceResult<()> {
        let (src_port, dest_port) = match self.port_direction {
            PortDirection::FixedSrc(src_port) => (src_port.0, probe.sequence.0),
            PortDirection::FixedDest(dest_port) => (probe.sequence.0, dest_port.0),
            PortDirection::FixedBoth(_, _) | PortDirection::None => unimplemented!(),
        };
        let socket = match self.addr_family {
            TracerAddrFamily::Ipv4 => Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)),
            TracerAddrFamily::Ipv6 => Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)),
        }?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_port(true)?;
        let local_addr = SocketAddr::new(self.src_addr, src_port);
        socket.bind(&SockAddr::from(local_addr))?;
        socket.set_ttl(u32::from(probe.ttl.0))?;
        socket.set_tos(u32::from(self.tos.0))?;
        let remote_addr = SocketAddr::new(self.dest_addr, dest_port);
        match socket.connect(&SockAddr::from(remote_addr)) {
            Ok(_) => {}
            Err(err) => {
                if let Some(code) = err.raw_os_error() {
                    if nix::Error::from_i32(code) != nix::Error::EINPROGRESS {
                        return match err.kind() {
                            ErrorKind::AddrInUse | ErrorKind::AddrNotAvailable => {
                                Err(AddressNotAvailable(local_addr))
                            }
                            _ => Err(TracerError::IoError(err)),
                        };
                    }
                } else {
                    return Err(TracerError::IoError(err));
                }
            }
        }
        self.tcp_probes
            .push(TcpProbe::new(socket, SystemTime::now()));
        Ok(())
    }

    /// Generate a `ProbeResponse` for the next available ICMP packet, if any
    fn recv_icmp_probe(&mut self) -> TraceResult<Option<ProbeResponse>> {
        match self.addr_family {
            TracerAddrFamily::Ipv4 => {
                ipv4::recv_icmp_probe(&mut self.recv_socket, self.protocol, self.port_direction)
            }
            TracerAddrFamily::Ipv6 => {
                ipv6::recv_icmp_probe(&mut self.recv_socket, self.protocol, self.port_direction)
            }
        }
    }

    /// Generate synthetic `ProbeResponse` if a TCP socket is connected or if the connection was refused.
    ///
    /// Any TCP socket which has not connected or failed after a timeout wil be removed.
    fn recv_tcp_sockets(&mut self) -> TraceResult<Option<ProbeResponse>> {
        self.tcp_probes
            .retain(|probe| probe.start.elapsed().unwrap_or_default() < self.tcp_connect_timeout);
        let found_index = self
            .tcp_probes
            .iter()
            .find_position(|&probe| is_writable(&probe.socket))
            .map(|(i, _)| i);
        if let Some(i) = found_index {
            let probe = self.tcp_probes.remove(i);
            let ttl = probe.socket.ttl()? as u8;
            match probe.socket.take_error()? {
                None => {
                    let addr = probe.socket.peer_addr()?.as_socket().req()?.ip();
                    probe.socket.shutdown(Shutdown::Both)?;
                    return Ok(Some(ProbeResponse::TcpReply(TcpProbeResponseData::new(
                        SystemTime::now(),
                        addr,
                        ttl,
                    ))));
                }
                Some(err) => {
                    if let Some(code) = err.raw_os_error() {
                        if nix::Error::from_i32(code) == nix::Error::ECONNREFUSED {
                            return Ok(Some(ProbeResponse::TcpRefused(TcpProbeResponseData::new(
                                SystemTime::now(),
                                self.dest_addr,
                                ttl,
                            ))));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

/// Validate, Lookup or discover the source `IpAddr`.
fn make_src_addr(
    source_addr: Option<IpAddr>,
    target_addr: IpAddr,
    port_direction: PortDirection,
    interface: Option<&str>,
    addr_family: TracerAddrFamily,
) -> TraceResult<IpAddr> {
    match (source_addr, interface.as_ref()) {
        (Some(addr), None) => validate_local_addr(addr_family, addr),
        (None, Some(interface)) => lookup_interface_addr(addr_family, interface),
        (None, None) => discover_local_addr(
            addr_family,
            target_addr,
            port_direction.dest().unwrap_or(DISCOVERY_PORT).0,
        ),
        (Some(_), Some(_)) => unreachable!(),
    }
}

/// Lookup the address for a named interface.
fn lookup_interface_addr(addr_family: TracerAddrFamily, name: &str) -> TraceResult<IpAddr> {
    match addr_family {
        TracerAddrFamily::Ipv4 => ipv4::lookup_interface_addr(name),
        TracerAddrFamily::Ipv6 => ipv6::lookup_interface_addr(name),
    }
}

/// Discover the local `IpAddr` that will be used to communicate with the given target `IpAddr`.
///
/// Note that no packets are transmitted by this method.
fn discover_local_addr(
    addr_family: TracerAddrFamily,
    target: IpAddr,
    port: u16,
) -> TraceResult<IpAddr> {
    let socket = udp_socket_for_addr_family(addr_family)?;
    socket.connect(&SockAddr::from(SocketAddr::new(target, port)))?;
    Ok(socket.local_addr()?.as_socket().req()?.ip())
}

/// Validate that we can bind to the source address.
fn validate_local_addr(addr_family: TracerAddrFamily, source_addr: IpAddr) -> TraceResult<IpAddr> {
    let socket = udp_socket_for_addr_family(addr_family)?;
    let addr = SocketAddr::new(source_addr, 0);
    match socket.bind(&SockAddr::from(addr)) {
        Ok(_) => Ok(source_addr),
        Err(_) => Err(InvalidSourceAddr(addr.ip())),
    }
}

/// Create a socket suitable for a given address.
fn udp_socket_for_addr_family(addr_family: TracerAddrFamily) -> TraceResult<Socket> {
    Ok(match addr_family {
        TracerAddrFamily::Ipv4 => Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?,
        TracerAddrFamily::Ipv6 => Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?,
    })
}

/// Make a socket for sending raw `ICMP` packets.
fn make_icmp_send_socket(addr_family: TracerAddrFamily) -> TraceResult<Socket> {
    match addr_family {
        TracerAddrFamily::Ipv4 => ipv4::make_icmp_send_socket(),
        TracerAddrFamily::Ipv6 => ipv6::make_icmp_send_socket(),
    }
}

/// Make a socket for sending `UDP` packets.
fn make_udp_send_socket(addr_family: TracerAddrFamily) -> TraceResult<Socket> {
    match addr_family {
        TracerAddrFamily::Ipv4 => ipv4::make_udp_send_socket(),
        TracerAddrFamily::Ipv6 => ipv6::make_udp_send_socket(),
    }
}

/// Make a socket for receiving raw `ICMP` packets.
fn make_recv_socket(addr_family: TracerAddrFamily) -> TraceResult<Socket> {
    match addr_family {
        TracerAddrFamily::Ipv4 => ipv4::make_recv_socket(),
        TracerAddrFamily::Ipv6 => ipv6::make_recv_socket(),
    }
}

/// Is the socket writable?
fn is_writable(sock: &Socket) -> bool {
    let mut write = FdSet::new();
    write.insert(sock.as_raw_fd());
    let writable = nix::sys::select::select(
        None,
        None,
        Some(&mut write),
        None,
        Some(&mut TimeVal::zero()),
    )
    .expect("select");
    writable == 1
}

/// An extension trait to allow `recv_from` method which writes to a `&mut [u8]`.
///
/// This is required for `socket2::Socket` which [does not currently provide] this method.
///
/// [does not currently provide]: https://github.com/rust-lang/socket2/issues/223
trait RecvFrom {
    fn recv_from_into_buf(&self, buf: &mut [u8]) -> std::io::Result<(usize, SockAddr)>;
}

impl RecvFrom for Socket {
    // Safety: the `recv` implementation promises not to write uninitialised
    // bytes to the `buf`fer, so this casting is safe.
    #![allow(unsafe_code)]
    fn recv_from_into_buf(&self, buf: &mut [u8]) -> std::io::Result<(usize, SockAddr)> {
        let buf = unsafe { &mut *(buf as *mut [u8] as *mut [std::mem::MaybeUninit<u8>]) };
        self.recv_from(buf)
    }
}
