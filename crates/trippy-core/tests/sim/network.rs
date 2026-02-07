mod ipv4;
mod ipv6;

use crate::simulation::Simulation;
use crate::tun_device::TunDevice;
use futures_concurrency::future::Race;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use trippy_packet::ip::{IpPacket, IpVersion};
use trippy_packet::ipv4::Ipv4Packet;
use trippy_packet::ipv6::Ipv6Packet;

const READ_TIMEOUT: Duration = Duration::from_millis(10);

pub async fn run(
    tun: Arc<Mutex<TunDevice>>,
    sim: Arc<Simulation>,
    token: CancellationToken,
) -> anyhow::Result<()> {
    let mut handles: Vec<JoinHandle<()>> = vec![];
    let expected_version = match sim.target {
        IpAddr::V4(_) => IpVersion::Ipv4,
        IpAddr::V6(_) => IpVersion::Ipv6,
    };
    loop {
        let mut buf = [0_u8; 4096];
        let Some(bytes_read) = {
            let tun = tun.clone();
            (
                async {
                    token.cancelled().await;
                    Ok::<Option<usize>, io::Error>(None)
                },
                async { read_with_timeout(&mut buf, tun.clone()).await.map(Some) },
            )
                .race()
                .await
        }?
        else {
            for h in handles {
                h.abort();
            }
            return Ok(());
        };
        if bytes_read == 0 {
            continue;
        }
        let ip = IpPacket::new_view(&buf[..bytes_read]).expect("valid IP packet");
        match ip.get_version() {
            IpVersion::Ipv4 => {
                if expected_version != IpVersion::Ipv4 {
                    debug!(
                        "skipping IPv4 packet while expecting {:?} packets",
                        expected_version
                    );
                    continue;
                }
                if let Some((reply_delay_ms, packet_buf)) =
                    ipv4::process(sim.as_ref(), ip.packet())?
                {
                    handles.push(tokio::spawn(write_packet(
                        tun.clone(),
                        reply_delay_ms,
                        packet_buf,
                        IpVersion::Ipv4,
                    )));
                }
            }
            IpVersion::Ipv6 => {
                if expected_version != IpVersion::Ipv6 {
                    debug!(
                        "skipping IPv6 packet while expecting {:?} packets",
                        expected_version
                    );
                    continue;
                }
                if let Some((reply_delay_ms, packet_buf)) =
                    ipv6::process(sim.as_ref(), ip.packet())?
                {
                    handles.push(tokio::spawn(write_packet(
                        tun.clone(),
                        reply_delay_ms,
                        packet_buf,
                        IpVersion::Ipv6,
                    )));
                }
            }
            IpVersion::Other(version) => {
                debug!("skipping unknown IP version packet: {}", version);
            }
        }
    }
}

/// Read from the tun device with a timeout.
///
/// Note that the tun device is only locked for the timeout period
async fn read_with_timeout(buf: &mut [u8], tun: Arc<Mutex<TunDevice>>) -> io::Result<usize> {
    tokio::time::timeout(READ_TIMEOUT, tun.lock().await.read(buf))
        .await
        .unwrap_or(Ok(0))
}

async fn write_packet(
    tun: Arc<Mutex<TunDevice>>,
    reply_delay_ms: u16,
    packet_buf: Vec<u8>,
    version: IpVersion,
) {
    tokio::time::sleep(Duration::from_millis(u64::from(reply_delay_ms))).await;
    match version {
        IpVersion::Ipv4 => {
            let packet = Ipv4Packet::new_view(&packet_buf).expect("valid ipv4 packet");
            debug!("write: {:?}", packet);
            tun.lock().await.write(packet.packet()).await.expect("send");
        }
        IpVersion::Ipv6 => {
            let packet = Ipv6Packet::new_view(&packet_buf).expect("valid ipv6 packet");
            debug!("write: {:?}", packet);
            tun.lock().await.write(packet.packet()).await.expect("send");
        }
        IpVersion::Other(version) => {
            panic!("unexpected packet version: {version}");
        }
    }
}
