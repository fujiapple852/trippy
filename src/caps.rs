// Linux

#[cfg(target_os = "linux")]
/// Check if `CAP_NET_RAW` is in the permitted set and if so raise it to the effective set.
pub fn ensure_caps() -> anyhow::Result<()> {
    if caps::has_cap(None, caps::CapSet::Permitted, caps::Capability::CAP_NET_RAW)? {
        caps::raise(None, caps::CapSet::Effective, caps::Capability::CAP_NET_RAW)?;
    } else {
        eprintln!("capability CAP_NET_RAW is required, see https://github.com/fujiapple852/trippy#privileges");
        std::process::exit(-1);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
/// Drop all capabilities.
pub fn drop_caps() -> anyhow::Result<()> {
    caps::clear(None, caps::CapSet::Effective)?;
    Ok(())
}

// macOS, BSD etc

#[cfg(all(unix, not(target_os = "linux")))]
#[allow(clippy::unnecessary_wraps)]
/// Ensure the effective user is `root`.
pub fn ensure_caps() -> anyhow::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("root user required to use raw sockets, see https://github.com/fujiapple852/trippy#privileges");
        std::process::exit(-1);
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
#[allow(clippy::unnecessary_wraps)]
/// Drop all capabilities.
///
/// This is a no-op on non-Linux systems.
pub fn drop_caps() -> anyhow::Result<()> {
    Ok(())
}

// Windows

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
/// Ensure the effective user is `root`.
pub fn ensure_caps() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
/// Drop all capabilities.
///
/// This is a no-op on non-Linux systems.
pub fn drop_caps() -> anyhow::Result<()> {
    Ok(())
}
