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

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)]
/// Ensure the effective user is `root`.
pub fn ensure_caps() -> anyhow::Result<()> {
    macro_rules! syscall {
        ($p: path, $fn: ident ( $($arg: expr),* $(,)* ) ) => {{
            #[allow(unsafe_code)]
            unsafe { paste::paste!(windows_sys::Win32::$p::$fn) ($($arg, )*) }
        }};
    }

    /// Window elevated privilege checker.
    pub struct Privileged {
        handle: windows_sys::Win32::Foundation::HANDLE,
    }

    impl Privileged {
        /// Create a new `ElevationChecker` for the current process.
        pub fn current_process() -> anyhow::Result<Self> {
            use windows_sys::Win32::Security::TOKEN_QUERY;
            let mut handle: windows_sys::Win32::Foundation::HANDLE = 0;
            let current_process = syscall!(System::Threading, GetCurrentProcess());
            let res = syscall!(
                System::Threading,
                OpenProcessToken(current_process, TOKEN_QUERY, std::ptr::addr_of_mut!(handle))
            );
            if res == 0 {
                Err(anyhow::anyhow!("OpenProcessToken failed"))
            } else {
                Ok(Self { handle })
            }
        }

        /// Check if the current process has elevated privileged.
        pub fn is_elevated(&self) -> anyhow::Result<bool> {
            use windows_sys::Win32::Security::TokenElevation;
            use windows_sys::Win32::Security::TOKEN_ELEVATION;
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let size = std::mem::size_of::<TOKEN_ELEVATION>();
            let mut ret_size = 0u32;
            let ret = syscall!(
                Security,
                GetTokenInformation(
                    self.handle,
                    TokenElevation,
                    std::ptr::addr_of_mut!(elevation).cast(),
                    size as u32,
                    std::ptr::addr_of_mut!(ret_size),
                )
            );
            if ret == 0 {
                Err(anyhow::anyhow!("GetTokenInformation failed"))
            } else {
                Ok(elevation.TokenIsElevated != 0)
            }
        }
    }

    impl Drop for Privileged {
        fn drop(&mut self) {
            if self.handle != 0 {
                syscall!(Foundation, CloseHandle(self.handle));
            }
        }
    }

    if !Privileged::current_process()?.is_elevated()? {
        eprintln!("administrator capability is required, see https://github.com/fujiapple852/trippy#privileges");
        std::process::exit(-1);
    }
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)]
/// Drop all capabilities.
///
/// This is a no-op on non-Linux systems.
pub fn drop_caps() -> anyhow::Result<()> {
    Ok(())
}
