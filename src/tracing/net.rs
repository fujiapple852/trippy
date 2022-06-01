use crate::tracing::error::TracerError::{AddressNotAvailable, InvalidSourceAddr};
use crate::tracing::error::{TraceResult, TracerError};
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

/// The byte order to encode the `total length` field of the IPv4 header.
///
/// To quote directly from the `mtr` source code (from `check_length_order` in `probe_unix.c`):
///
/// "Nearly all fields in the IP header should be encoded in network byte
/// order prior to passing to send().  However, the required byte order of
/// the length field of the IP header is inconsistent between operating
/// systems and operating system versions.  FreeBSD 11 requires the length
/// field in network byte order, but some older versions of FreeBSD
/// require host byte order.  OS X requires the length field in host
/// byte order.  Linux will accept either byte order."
#[derive(Debug, Copy, Clone)]
pub enum Ipv4TotalLengthByteOrder {
    #[cfg(all(unix, not(target_os = "linux")))]
    Host,
    Network,
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
        let src_addr = Self::make_src_addr(config)?;
        let ipv4_length_order = Self::discover_ip_length_byte_order(src_addr)?;
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

    fn make_src_addr(config: &TracerChannelConfig) -> TraceResult<IpAddr> {
        match (config.source_addr, config.interface.as_ref()) {
            (Some(addr), None) => validate_local_addr(config.addr_family, addr),
            (None, Some(interface)) => lookup_interface_addr(config.addr_family, interface),
            (None, None) => discover_local_addr(
                config.addr_family,
                config.target_addr,
                config.port_direction.dest().unwrap_or(DISCOVERY_PORT).0,
            ),
            (Some(_), Some(_)) => unreachable!(),
        }
    }

    /// Discover the required byte ordering for the IPv4 header field `total_length`.
    ///
    /// This is achieved by creating a raw socket and attempting to send an `IPv4` packet to localhost with the
    /// `total_length` set in either host byte order or network byte order. The OS will return an `InvalidInput` error
    /// if the buffer provided is smaller than the `total_length` indicated, which will be the case when the byte order
    /// is set incorrectly.
    ///
    /// This is a little confusing as `Ipv4Packet::set_total_length` method will _always_ convert from host byte order
    /// to network byte order (which will be a no-op on big-endian system) and so to test the host byte order case
    /// we must ...
    ///
    /// For example, for a packet of length 4660 bytes (dec):
    ///
    /// For a little-endian architecture:
    ///
    /// Try        Host (LE)    Wire (BE)   Order (if succeeds)
    /// normal     34 12        12 34       `Ipv4TotalLengthByteOrder::Network`
    /// swapped    12 34        34 12       `Ipv4TotalLengthByteOrder::Host`
    ///
    /// For a big-endian architecture:
    ///
    /// Try        Host (BE)    Wire (BE)   Order (if succeeds)
    /// normal     12 34        12 34       `Ipv4TotalLengthByteOrder::Host`
    /// swapped    34 12        34 12       `Ipv4TotalLengthByteOrder::Network`
    ///
    /// TODO validate the latter cases on a BE system
    /// TODO what do we do for IPv6?
    #[cfg(all(unix, not(target_os = "linux")))]
    fn discover_ip_length_byte_order(src_addr: IpAddr) -> TraceResult<Ipv4TotalLengthByteOrder> {
        match Self::test_send_local_ip4_packet(src_addr, 256_u16) {
            Ok(_) => Ok(Ipv4TotalLengthByteOrder::Network),
            Err(TracerError::IoError(io)) if io.kind() == ErrorKind::InvalidInput => {
                match Self::test_send_local_ip4_packet(src_addr, 256_u16.swap_bytes()) {
                    Ok(_) => Ok(Ipv4TotalLengthByteOrder::Host),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Open a raw socket and attempt to send an `ICMP` packet to a local address.
    ///
    /// The packet is actually of length `256` bytes but we set the `total_length` based on the input provided so as to
    /// test if the OS rejects the attempt.
    #[cfg(all(unix, not(target_os = "linux")))]
    fn test_send_local_ip4_packet(src_addr: IpAddr, total_length: u16) -> TraceResult<usize> {
        let src_addr = match src_addr {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => unimplemented!(), // TODO
        };
        let mut buf = [0_u8; 256];
        let mut ipv4 = crate::tracing::packet::ipv4::Ipv4Packet::new(&mut buf).req()?;
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_protocol(crate::tracing::packet::IpProtocol::Icmp);
        ipv4.set_ttl(255);
        ipv4.set_source(src_addr);
        ipv4.set_destination(std::net::Ipv4Addr::LOCALHOST);
        ipv4.set_total_length(total_length);
        let probe_socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(nix::libc::IPPROTO_RAW)),
        )?;
        probe_socket.set_header_included(true)?;
        let remote_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
        Ok(probe_socket.send_to(ipv4.packet(), &SockAddr::from(remote_addr))?)
    }

    /// Discover the required byte ordering for the IPv4 header field `total_length`.
    ///
    /// Linux accepts either network byte order or host byte order for the `total_length` field and so we skip the
    /// check and return network bye order unconditionally.
    ///
    /// TODO move platform specifics into a separate module.
    #[cfg(target_os = "linux")]
    #[allow(clippy::unnecessary_wraps)]
    fn discover_ip_length_byte_order(_src_addr: IpAddr) -> TraceResult<Ipv4TotalLengthByteOrder> {
        Ok(Ipv4TotalLengthByteOrder::Network)
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
