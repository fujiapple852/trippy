use crate::Trace;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

/// Dummy front end which just prints out the hop data in a loop.
pub fn run_frontend(target_addr: IpAddr, trace_data: &Arc<RwLock<Trace>>) -> anyhow::Result<()> {
    loop {
        let trace_data = trace_data.read().clone();
        let hops = trace_data.highest_ttl;
        println!("Tracing to {}", target_addr);
        for (i, hop) in trace_data.hops.iter().enumerate().take(hops as usize) {
            let ttl = i + 1;
            let addrs = hop.addrs.iter().collect::<Vec<_>>();
            let sent = hop.total_sent;
            let recv = hop.total_recv;
            let last = hop
                .last
                .as_ref()
                .map(Duration::as_millis)
                .unwrap_or_default();
            println!(
                "ttl={} addrs={:?} last={} sent={} recv={}",
                ttl, addrs, last, sent, recv
            );
        }
        sleep(Duration::from_millis(500));
    }
}
