use clap::Parser;

/// Trace a route to a host and record statistics
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// The hostname or IP to scan
    pub hostname: String,

    /// The TTL to start from
    #[clap(short, long, default_value_t = 1)]
    pub first_ttl: u8,

    /// The maximum number of hops
    #[clap(short, long, default_value_t = 64, max_values(256))]
    pub max_ttl: u8,

    /// The minimum duration of every round
    #[clap(short = 'i', long, default_value = "1s")]
    pub min_round_duration: String,

    /// The maximum duration of every round
    #[clap(short = 't', long, default_value = "1s")]
    pub max_round_duration: String,

    /// The period of time to wait for additional ICMP responses after the target has responded
    #[clap(short, long, default_value = "500ms")]
    pub grace_duration: String,

    /// The maximum number of in-flight ICMP echo requests
    #[clap(short = 'U', long, default_value_t = 10)]
    pub max_inflight: u8,

    /// The socket read timeout.
    #[clap(short, long, default_value = "10ms")]
    pub read_timeout: String,

    /// Preserve the screen on exit
    #[clap(long)]
    pub preserve_screen: bool,
}
