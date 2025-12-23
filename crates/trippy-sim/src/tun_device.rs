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

/// A `tun` device.
pub struct TunDevice {
    dev: tun::AsyncDevice,
}

impl TunDevice {
    pub fn start() -> anyhow::Result<Self> {
        let net: Ipv4Network = TUN_NETWORK_CIDR.parse()?;
        let addr = net.nth(1).expect("addr");
        let mut config = tun::Configuration::default();
        config.address(addr).netmask(net.mask()).up();
        let dev = tun::create_as_async(&config)?;
        #[cfg(target_os = "windows")]
        std::thread::sleep(std::time::Duration::from_millis(10000));
        Ok(Self { dev })
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.dev.read(buf).await?;
        Ok(bytes_read)
    }

    pub async fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.dev.write_all(buf).await?;
        Ok(buf.len())
    }
}
