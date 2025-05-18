//! Discover platform privileges.
//!
//! A cross-platform library to discover and manage platform privileges needed
//! for sending ICMP packets via RAW and `IPPROTO_ICMP` sockets.
//!
//! [`Privilege::acquire_privileges`]:
//!
//! - On Linux we check if `CAP_NET_RAW` is in the permitted set and if so raise it to the effective
//!   set
//! - On other Unix platforms this is a no-op
//! - On Windows this is a no-op
//!
//! [`Privilege::has_privileges`] (obtained via [`Privilege::discover`]):
//!
//! - On Linux we check if `CAP_NET_RAW` is in the effective set
//! - On other Unix platforms we check that the effective user is root
//! - On Windows we check if the current process has an elevated token
//!
//! [`Privilege::needs_privileges`] (obtained via [`Privilege::discover`]):
//!
//! - On macOS we do not always need privileges to send ICMP packets as we can use `IPPROTO_ICMP`
//!   sockets with the `IP_HDRINCL` socket option.
//! - On Linux we always need privileges to send ICMP packets even though it supports the
//!   `IPPROTO_ICMP` socket type but not the `IP_HDRINCL` socket option
//! - On Windows we always need privileges to send ICMP packets
//!
//! [`Privilege::drop_privileges`]:
//!
//! - On Linux we clear the effective set
//! - On other Unix platforms this is a no-op
//! - On Windows this is a no-op
//!
//! # Examples
//!
//! Acquire the required privileges if we can:
//!
//! ```rust
//! # fn main() -> anyhow::Result<()> {
//! # use trippy_privilege::Privilege;
//! let privilege = Privilege::acquire_privileges()?;
//! if privilege.has_privileges() {
//!     println!("You have the required privileges for raw sockets");
//! } else {
//!     println!("You do not have the required privileges for raw sockets");
//! }
//! if privilege.needs_privileges() {
//!     println!("You always need privileges to send ICMP packets.");
//! } else {
//!     println!("You do not always need privileges to send ICMP packets.");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Discover the current privileges:
//!
//! ```rust
//! # fn main() -> anyhow::Result<()> {
//! # use trippy_privilege::Privilege;
//! let privilege = Privilege::discover()?;
//! if privilege.has_privileges() {
//!     println!("You have the required privileges for raw sockets");
//! } else {
//!     println!("You do not have the required privileges for raw sockets");
//! }
//! if privilege.needs_privileges() {
//!     println!("You always need privileges to send ICMP packets.");
//! } else {
//!     println!("You do not always need privileges to send ICMP packets.");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Drop all privileges:
//!
//! ```rust
//! # fn main() -> anyhow::Result<()> {
//! # use trippy_privilege::Privilege;
//! Privilege::drop_privileges()?;
//! # Ok(())
//! # }
//! ```

/// A privilege error result.
pub type Result<T> = std::result::Result<T, Error>;

/// A privilege error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[cfg(target_os = "linux")]
    #[error("caps error: {0}")]
    CapsError(#[from] caps::errors::CapsError),
    #[cfg(windows)]
    #[error("OpenProcessToken failed")]
    OpenProcessTokenError,
    #[cfg(windows)]
    #[error("GetTokenInformation failed")]
    GetTokenInformationError,
}

/// Run-time platform privilege information.
#[derive(Debug)]
pub struct Privilege {
    has_privileges: bool,
    needs_privileges: bool,
}

impl Privilege {
    /// Discover information about the platform privileges.
    pub fn discover() -> Result<Self> {
        let has_privileges = Self::check_has_privileges()?;
        let needs_privileges = Self::check_needs_privileges();
        Ok(Self {
            has_privileges,
            needs_privileges,
        })
    }

    /// Create a new Privilege instance.
    #[must_use]
    pub const fn new(has_privileges: bool, needs_privileges: bool) -> Self {
        Self {
            has_privileges,
            needs_privileges,
        }
    }

    /// Are we running with the privileges required for raw sockets?
    #[must_use]
    pub const fn has_privileges(&self) -> bool {
        self.has_privileges
    }

    /// Does our platform always need privileges for `ICMP`?
    ///
    /// Specifically, each platform requires privileges unless it supports the `IPPROTO_ICMP` socket
    /// type which _also_ allows the `IP_HDRINCL` socket option to be set.
    #[must_use]
    pub const fn needs_privileges(&self) -> bool {
        self.needs_privileges
    }

    // Linux

    #[cfg(target_os = "linux")]
    /// Acquire privileges, if possible.
    ///
    /// Check if `CAP_NET_RAW` is in the permitted set and if so raise it to the effective set.
    pub fn acquire_privileges() -> Result<Self> {
        if caps::has_cap(None, caps::CapSet::Permitted, caps::Capability::CAP_NET_RAW)? {
            caps::raise(None, caps::CapSet::Effective, caps::Capability::CAP_NET_RAW)?;
        }
        Self::discover()
    }

    #[cfg(target_os = "linux")]
    /// Do we have the required privileges?
    ///
    /// Check if `CAP_NET_RAW` is in the effective set.
    fn check_has_privileges() -> Result<bool> {
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
    pub fn drop_privileges() -> Result<()> {
        caps::clear(None, caps::CapSet::Effective)?;
        Ok(())
    }

    // Unix (excl. Linux)

    #[cfg(all(unix, not(target_os = "linux")))]
    /// Acquire privileges, if possible.
    ///
    /// This is a no-op on non-Linux unix systems.
    pub fn acquire_privileges() -> Result<Self> {
        Self::discover()
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[expect(clippy::unnecessary_wraps)]
    /// Do we have the required privileges?
    ///
    /// Checks if the effective user is root.
    fn check_has_privileges() -> Result<bool> {
        Ok(nix::unistd::Uid::effective().is_root())
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    /// Drop all privileges.
    ///
    /// This is a no-op on non-Linux unix systems.
    pub const fn drop_privileges() -> Result<()> {
        Ok(())
    }

    // Unix (excl. macOS)

    #[cfg(all(unix, not(target_os = "macos")))]
    /// Does the platform always require privileges?
    ///
    /// Whilst Linux supports the `IPPROTO_ICMP` socket type, it does not allow using it with the
    /// `IP_HDRINCL` socket option and is therefore not supported.  This may be supported in the
    /// future.
    ///
    /// `NetBSD`, `OpenBSD` and `FreeBSD` do not support `IPPROTO_ICMP`.
    const fn check_needs_privileges() -> bool {
        true
    }

    // macOS

    #[cfg(target_os = "macos")]
    /// Does the platform always require privileges?
    ///
    /// `macOS` supports both privileged and unprivileged modes.
    const fn check_needs_privileges() -> bool {
        false
    }

    // Windows

    #[cfg(windows)]
    /// Acquire privileges, if possible.
    ///
    /// This is a no-op on `Windows`.
    pub fn acquire_privileges() -> Result<Self> {
        Self::discover()
    }

    #[cfg(windows)]
    /// Do we have the required privileges?
    ///
    /// Check if the current process has an elevated token.
    fn check_has_privileges() -> Result<bool> {
        macro_rules! syscall {
            ($p: path, $fn: ident ( $($arg: expr),* $(,)* ) ) => {{
                #[expect(unsafe_code)]
                unsafe { paste::paste!(windows_sys::Win32::$p::$fn) ($($arg, )*) }
            }};
        }

        /// Window elevated privilege checker.
        pub struct Privileged {
            handle: windows_sys::Win32::Foundation::HANDLE,
        }

        impl Privileged {
            /// Create a new `ElevationChecker` for the current process.
            pub fn current_process() -> Result<Self> {
                use windows_sys::Win32::Security::TOKEN_QUERY;
                let mut handle: windows_sys::Win32::Foundation::HANDLE = 0;
                let current_process = syscall!(System::Threading, GetCurrentProcess());
                let res = syscall!(
                    System::Threading,
                    OpenProcessToken(current_process, TOKEN_QUERY, std::ptr::addr_of_mut!(handle))
                );
                if res == 0 {
                    Err(Error::OpenProcessTokenError)
                } else {
                    Ok(Self { handle })
                }
            }

            /// Check if the current process has elevated privileged.
            pub fn is_elevated(&self) -> Result<bool> {
                use windows_sys::Win32::Security::TokenElevation;
                use windows_sys::Win32::Security::TOKEN_ELEVATION;
                let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
                #[expect(clippy::cast_possible_truncation)]
                let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
                let mut ret_size = 0u32;
                let ret = syscall!(
                    Security,
                    GetTokenInformation(
                        self.handle,
                        TokenElevation,
                        std::ptr::addr_of_mut!(elevation).cast(),
                        size,
                        std::ptr::addr_of_mut!(ret_size),
                    )
                );
                if ret == 0 {
                    Err(Error::GetTokenInformationError)
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
    /// Drop all capabilities.
    ///
    /// This is a no-op on `Windows`.
    pub const fn drop_privileges() -> Result<()> {
        Ok(())
    }

    #[cfg(target_os = "windows")]
    /// Does the platform always require privileges?
    ///
    /// Privileges are always required on `Windows`.
    const fn check_needs_privileges() -> bool {
        true
    }
}
