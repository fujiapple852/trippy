/// Runtime information about the platform and environment.
#[derive(Debug)]
pub struct Platform {
    /// The platform process id.
    pub pid: u16,
    /// Are we running with the privileges required for raw sockets?
    pub has_privileges: bool,
    /// Does our platform always need privileges for `ICMP`?
    ///
    /// Specifically, each platform requires privileges unless it supports the `IPPROTO_ICMP` socket type which _also_
    /// allows the `IP_HDRINCL` socket option to be set.
    pub needs_privileges: bool,
}

impl Platform {
    /// Discover information about the platform and environment.
    pub fn discover() -> anyhow::Result<Self> {
        let pid = u16::try_from(std::process::id() % u32::from(u16::MAX))?;
        let has_privileges = Self::has_privileges()?;
        let needs_privileges = Self::needs_privileges();
        Ok(Self {
            pid,
            has_privileges,
            needs_privileges,
        })
    }

    // Linux

    #[cfg(target_os = "linux")]
    /// Acquire privileges, if possible.
    ///
    /// Check if `CAP_NET_RAW` is in the permitted set and if so raise it to the effective set.
    pub fn acquire_privileges() -> anyhow::Result<()> {
        if caps::has_cap(None, caps::CapSet::Permitted, caps::Capability::CAP_NET_RAW)? {
            caps::raise(None, caps::CapSet::Effective, caps::Capability::CAP_NET_RAW)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    /// Do we have the required privileges?
    ///
    /// Check if `CAP_NET_RAW` is in the effective set.
    pub fn has_privileges() -> anyhow::Result<bool> {
        Ok(caps::has_cap(
            None,
            caps::CapSet::Effective,
            caps::Capability::CAP_NET_RAW,
        )?)
    }

    #[cfg(target_os = "linux")]
    /// Drop all privileges.
    ///
    /// Clears the effective set.
    pub fn drop_privileges() -> anyhow::Result<()> {
        caps::clear(None, caps::CapSet::Effective)?;
        Ok(())
    }

    // Unix (excl. Linux)

    #[cfg(all(unix, not(target_os = "linux")))]
    #[allow(clippy::unnecessary_wraps)]
    /// Acquire privileges, if possible.
    ///
    /// This is a no-op on non-Linux unix systems.
    pub fn acquire_privileges() -> anyhow::Result<()> {
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[allow(clippy::unnecessary_wraps)]
    /// Do we have the required privileges?
    ///
    /// Checks if the effective user is root.
    pub fn has_privileges() -> anyhow::Result<bool> {
        Ok(nix::unistd::Uid::effective().is_root())
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[allow(clippy::unnecessary_wraps)]
    /// Drop all privileges.
    ///
    /// This is a no-op on non-Linux unix systems.
    pub fn drop_privileges() -> anyhow::Result<()> {
        Ok(())
    }

    // Unix (excl. macOS)

    #[cfg(all(unix, not(target_os = "macos")))]
    /// Does the platform always require privileges?
    ///
    /// Whilst Linux supports the `IPPROTO_ICMP` socket type, it does not allow using it with the `IP_HDRINCL` socket
    /// option and is therefore not supported.  This may be supported in the future.
    ///
    /// `NetBSD`, `OpenBSD` and `FreeBSD` do not support `IPPROTO_ICMP`.
    fn needs_privileges() -> bool {
        true
    }

    // macOS

    #[cfg(target_os = "macos")]
    /// Does the platform always require privileges?
    ///
    /// `macOS` supports both privileged and unprivileged modes.
    fn needs_privileges() -> bool {
        false
    }

    // Windows

    #[cfg(windows)]
    #[allow(clippy::unnecessary_wraps)]
    /// Acquire privileges, if possible.
    ///
    /// This is a no-op on `Windows`.
    pub fn acquire_privileges() -> anyhow::Result<()> {
        Ok(())
    }

    #[cfg(windows)]
    #[allow(clippy::unnecessary_wraps)]
    /// Do we have the required privileges?
    ///
    /// Check if the current process has an elevated token.
    pub fn has_privileges() -> anyhow::Result<bool> {
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
        Privileged::current_process()?.is_elevated()
    }

    #[cfg(windows)]
    #[allow(clippy::unnecessary_wraps)]
    /// Drop all capabilities.
    ///
    /// This is a no-op on `Windows`.
    pub fn drop_privileges() -> anyhow::Result<()> {
        Ok(())
    }

    #[cfg(target_os = "windows")]
    /// Does the platform always require privileges?
    ///
    /// Privileges are always required on `Windows`.
    fn needs_privileges() -> bool {
        true
    }
}
