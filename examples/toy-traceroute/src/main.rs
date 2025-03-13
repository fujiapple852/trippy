use anyhow::anyhow;
use clap::Parser;
use itertools::Itertools;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use trippy::core::{Builder, PortDirection, Protocol};
use trippy::dns::{Config, DnsResolver, Resolver};

/// A toy clone of BSD4.3 (macOS) traceroute.
///
/// *** This is for demonstration purposes only. ***
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, arg_required_else_help(true))]
struct Args {
    host: String,
    #[arg(short = 'f')]
    first_ttl: Option<u8>,
    #[arg(short = 'm')]
    max_ttl: Option<u8>,
    #[arg(short = 'i')]
    interface: Option<String>,
    #[arg(short = 'p')]
    port: Option<u16>,
    #[arg(short = 'q')]
    nqueries: Option<usize>,
    #[arg(short = 's')]
    src_addr: Option<String>,
    #[arg(short = 't')]
    tos: Option<u8>,
    #[arg(short = 'z')]
    pausemsecs: Option<u64>,
    #[arg(short = 'e')]
    evasion: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let hostname = args.host;
    let interface = args.interface;
    let src_addr = args
        .src_addr
        .as_ref()
        .map(|addr| IpAddr::from_str(addr))
        .transpose()?;
    let port = args.port.unwrap_or(33434);
    let first_ttl = args.first_ttl.unwrap_or(1);
    let max_ttl = args.max_ttl.unwrap_or(64);
    let nqueries = args.nqueries.unwrap_or(3);
    let tos = args.tos.unwrap_or(0);
    let pausemsecs = args.pausemsecs.unwrap_or(100);
    let port_direction = if args.evasion {
        PortDirection::new_fixed_dest(port)
    } else {
        PortDirection::new_fixed_src(port)
    };
    let resolver = DnsResolver::start(Config::default())?;
    let addrs: Vec<_> = resolver
        .lookup(&hostname)
        .map_err(|_| anyhow!(format!("traceroute: unknown host {}", hostname)))?
        .into_iter()
        .collect();
    let addr = match addrs.as_slice() {
        [] => return Err(anyhow!("traceroute: unknown host {}", hostname)),
        [addr] => *addr,
        [addr, ..] => {
            println!("traceroute: Warning: {hostname} has multiple addresses; using {addr}");
            *addr
        }
    };
    let tracer = Builder::new(addr)
        .interface(interface)
        .source_addr(src_addr)
        .protocol(Protocol::Udp)
        .port_direction(port_direction)
        .packet_size(52)
        .first_ttl(first_ttl)
        .max_ttl(max_ttl)
        .tos(tos)
        .max_flows(1)
        .max_rounds(Some(nqueries))
        .min_round_duration(Duration::from_millis(pausemsecs))
        .max_round_duration(Duration::from_millis(pausemsecs))
        .build()?;
    println!(
        "traceroute to {} ({}), {} hops max, {} byte packets",
        &hostname,
        tracer.target_addr(),
        tracer.max_ttl().0,
        tracer.packet_size().0
    );
    tracer.run()?;
    let snapshot = &tracer.snapshot();
    if let Some(err) = snapshot.error() {
        return Err(anyhow!("error: {}", err));
    }
    for hop in snapshot.hops() {
        let ttl = hop.ttl();
        let samples: String = hop
            .samples()
            .iter()
            .map(|s| format!("{:.3} ms", s.as_secs_f64() * 1000_f64))
            .join("  ");
        if hop.addr_count() > 0 {
            for (i, addr) in hop.addrs().enumerate() {
                let host = resolver.reverse_lookup(*addr).to_string();
                let address = format!("{host} ({addr})");
                if i != 0 {
                    println!("    {address} {samples}");
                } else {
                    println!(" {ttl}  {address} {samples}");
                }
            }
        } else {
            println!(" {ttl}  * * * {samples}");
        }
    }
    Ok(())
}
