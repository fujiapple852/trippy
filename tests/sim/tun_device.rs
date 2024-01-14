use ipnetwork::Ipv4Network;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

static TUN: OnceLock<Arc<Mutex<TunDevice>>> = OnceLock::new();

/// Get a reference to the singleton `tun` device, initializing as necessary.
pub fn tun() -> &'static Arc<Mutex<TunDevice>> {
    TUN.get_or_init(|| {
        let tun = TunDevice::start().expect("tun");
        Arc::new(Mutex::new(tun))
    })
}

/// The CIDR network range to route to the `tun` device.
///
/// The `tun` device will be assigned the 2nd ip address from the CIDR network
/// range.
///
/// For example, if this is set to `10.0.0.0/24` then the `tun` device will be
/// assigned the IP `10.0.0.1` and all packets sent to the network range
/// `10.0.0.0/24` will be routed via the `tun` device and sent from IP
/// `10.0.0.1`.
const TUN_NETWORK_CIDR: &str = "10.0.0.0/24";

/// The flags (u16) and proto (u16) packet information.
///
/// These 4 octets are prepended to incoming and outgoing packets on some
/// platforms.
const PACKET_INFO: [u8; 4] = [0x0, 0x0, 0x0, 0x2];

/// A `tun` device.
pub struct TunDevice {
    dev: tun2::AsyncDevice,
}

impl TunDevice {
    pub fn start() -> anyhow::Result<Self> {
        let net: Ipv4Network = TUN_NETWORK_CIDR.parse()?;
        let addr = net.nth(1).expect("addr");
        let mut config = tun2::Configuration::default();
        config.address(addr).netmask(net.mask()).up();
        let dev = tun2::create_as_async(&config)?;
        Self::create_route()?;
        Ok(Self { dev })
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.dev.read(buf).await?;
        if self.has_packet_information() {
            buf.rotate_left(4);
            Ok(bytes_read - 4)
        } else {
            Ok(bytes_read)
        }
    }

    pub async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.has_packet_information() {
            let mut dev_buf = [0_u8; 4096 + 4];
            dev_buf[..4].copy_from_slice(&PACKET_INFO);
            dev_buf[4..buf.len() + 4].copy_from_slice(buf);
            self.dev.write_all(&dev_buf[..buf.len() + 4]).await?;
        } else {
            self.dev.write_all(buf).await?;
        }
        Ok(buf.len())
    }

    #[cfg(target_os = "macos")]
    fn create_route() -> anyhow::Result<()> {
        // macOS requires that we explicitly add the route.
        let net: Ipv4Network = TUN_NETWORK_CIDR.parse()?;
        let addr = net.nth(1).expect("addr");
        std::process::Command::new("sudo")
            .args([
                "route",
                "-n",
                "add",
                "-net",
                &net.to_string(),
                &addr.to_string(),
            ])
            .status()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn create_route() -> anyhow::Result<()> {
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn create_route() -> anyhow::Result<()> {
        // allow time for the routing table to reflect the tun device.
        std::thread::sleep(std::time::Duration::from_millis(10000));
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn has_packet_information(&self) -> bool {
        true
    }

    #[cfg(target_os = "linux")]
    fn has_packet_information(&self) -> bool {
        false
    }

    #[cfg(target_os = "windows")]
    fn has_packet_information(&self) -> bool {
        false
    }
}
