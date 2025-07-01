use std::str::FromStr;
use trippy::core::Builder;

fn main() -> anyhow::Result<()> {
    let addr = std::net::IpAddr::from_str("1.1.1.1")?;
    Builder::new(addr)
        .build()?
        .run_with(|round| println!("{round:?}"))?;
    Ok(())
}
