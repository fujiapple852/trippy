use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;

static TUN: OnceLock<Arc<Mutex<TunDevice>>> = OnceLock::new();

/// Get a reference to the singleton `tun` device, initializing as necessary.
pub fn tun() -> &'static Arc<Mutex<TunDevice>> {
    TUN.get_or_init(|| {
        let tun = TunDevice::start().expect("tun");
        Arc::new(Mutex::new(tun))
    })
}

/// IPv4 address and CIDR prefix configured on the `tun` device.
///
/// For example, if this is set to `10.0.0.1` with a prefix length of 24 then
/// the `tun` device will be assigned the IP `10.0.0.1` and packets sent to
/// the network range `10.0.0.0/24` will typically be routed via the `tun`
/// device and therefore have the source address `10.0.0.1`.
pub const TUN_NETWORK_ADDR_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const TUN_NETWORK_PREFIX_V4: u8 = 24;

/// IPv6 address and CIDR prefix configured on the `tun` device.
pub const TUN_NETWORK_ADDR_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0010, 0, 0, 0, 0, 0, 1);
const TUN_NETWORK_PREFIX_V6: u8 = 64;

/// A `tun` device.
pub struct TunDevice {
    dev: tun_rs::AsyncDevice,
}

impl TunDevice {
    pub fn start() -> anyhow::Result<Self> {
        let dev = tun_rs::DeviceBuilder::new()
            .ipv4(TUN_NETWORK_ADDR_V4, TUN_NETWORK_PREFIX_V4, None)
            .ipv6(TUN_NETWORK_ADDR_V6, TUN_NETWORK_PREFIX_V6)
            .build_async()?;
        #[cfg(target_os = "windows")]
        std::thread::sleep(std::time::Duration::from_millis(10000));
        Ok(Self { dev })
    }

    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.dev.recv(buf).await?;
        Ok(bytes_read)
    }

    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.dev.send(buf).await
    }
}
