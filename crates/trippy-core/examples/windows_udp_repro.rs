//! Standalone privileged loopback reproduction for issue #1881.
//! Run a debug build from an elevated Windows process; no listener is needed.

use std::cell::Cell;
use std::net::IpAddr;
use std::time::Duration;
use trippy_core::{Builder, MultipathStrategy, Port, PortDirection, PrivilegeMode, Protocol};

fn main() -> anyhow::Result<()> {
    anyhow::ensure!(cfg!(windows), "this reproducer requires Windows");
    let privileged = trippy_privilege::Privilege::discover()?.has_privileges();
    println!("REPRO privileged={privileged}");
    anyhow::ensure!(privileged, "run this reproducer as Administrator");

    let target: IpAddr = "127.0.0.1".parse()?;
    let tracer = Builder::new(target)
        .privilege_mode(PrivilegeMode::Privileged)
        .drop_privileges(false)
        .protocol(Protocol::Udp)
        .multipath_strategy(MultipathStrategy::Classic)
        .port_direction(PortDirection::FixedSrc(Port(43534)))
        .first_ttl(1)
        .max_ttl(3)
        .max_rounds(Some(3))
        .read_timeout(Duration::from_millis(100))
        .max_round_duration(Duration::from_secs(10))
        .build()?;
    println!("REPRO tracer_built");
    let rounds = Cell::new(0);
    match tracer.run_with(|_round| rounds.set(rounds.get() + 1)) {
        Ok(()) => println!("REPRO completed rounds={}", rounds.get()),
        Err(error) => {
            eprintln!("REPRO typed_error: {error:?}");
            return Err(error.into());
        }
    }
    Ok(())
}
