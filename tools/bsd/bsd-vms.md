# Local BSD development VMs

The `scripts/bsd/vm` command creates persistent amd64 FreeBSD, NetBSD, and OpenBSD
VMs on an Intel Mac. It downloads the latest stable release on first creation,
verifies its checksum, installs Rust and build tools, and copies your working tree.
It does not build or run Trippy during ordinary startup.

## Requirements

Install QEMU, Python 3, and rsync (macOS's bundled rsync also works). SSH, curl, and
`hdiutil` are supplied by macOS. QEMU must support HVF and `vmnet-bridged`.

```sh
brew install qemu python rsync
./scripts/bsd/vm up freebsd --bridge en0
./scripts/bsd/vm shell freebsd
```

Replace `freebsd` with `netbsd` or `openbsd`. The first boot installs the OS and
packages and can take several minutes. Subsequent boots reuse the disk and caches.
The `vmnet` launch uses `sudo` and may prompt for your Mac administrator password
in your terminal. Python orchestration and image downloads run as your user.

By default the tool selects the physical default-route interface. If a VPN obscures
that route, specify `--bridge en0` (or the appropriate physical interface).

Defaults are HVF, two CPUs, 4096 MiB RAM, and a sparse 64 GiB disk per guest.
Override with `--accel tcg`, `--cpus`, or `--memory`. TCG is useful for diagnosing
hypervisor compatibility but is much slower.
`--cpu` overrides the CPU model. The unused Q35 SMBus is disabled because OpenBSD
can stall while probing it. Stop the guest before changing hardware options.

## Source and builds

The development account uses zsh with persistent history, arrow-key navigation,
and tab completion. Zoxide provides `z NAME` to jump to frequently visited
directories and `zi` for an interactive directory picker (fzf is installed too).
Zoxide is currently unavailable in the OpenBSD binary package repository; zsh's
history and completion still work there.
Personal shell settings can be added to `~/.zshrc`; the managed defaults live in
`~/.trippy-shell.zsh`.

To apply updated shell defaults to an existing VM after synchronizing the source,
run `sudo sh ~/src/trippy/scripts/bsd/provision.sh --shell-only` inside the guest
(use `doas` on OpenBSD), then reconnect with `vm shell`.

Startup and `sync` copy tracked and nonignored untracked files, including local
edits, into `~/src/trippy`. Local deletions remove files from this managed mirror.
Edit on the Mac: guest edits can be overwritten by the next synchronization.
Git metadata and ignored files are excluded.

```sh
./scripts/bsd/vm sync freebsd
./scripts/bsd/vm shell freebsd
# Inside the guest:
cargo build --locked -p trippy
cargo test
sudo "$CARGO_TARGET_DIR/debug/trip" example.com --icmp
sudo "$CARGO_TARGET_DIR/debug/trip" example.com --udp
sudo "$CARGO_TARGET_DIR/debug/trip" example.com --tcp -P 443
```

OpenBSD uses `doas` instead of `sudo`. Cargo downloads remain in `~/.cargo` and
build output in `~/.cache/trippy-target`, outside the source mirror. Two build jobs
limit memory use. Rust must meet the checked-out workspace's `rust-version`.
FreeBSD and NetBSD use rustup; OpenBSD uses its release's Rust package. Provisioning
fails if a required package is unavailable, and synchronization rejects a compiler
below the workspace minimum.

## Networking and IPv6 through Tailscale

Each guest has a management NIC and a separate bridged probe NIC. SSH uses only
Mac loopback ports 2222 (FreeBSD), 2223 (NetBSD), and 2224 (OpenBSD). Management
user networking is for SSH and provisioning; it is not a valid raw-probe path.
After provisioning, native default routes use the bridged NIC with DHCPv4 and IPv6
router advertisements. Wi-Fi/AP restrictions can still affect bridged guests.

Tailscale runs inside the guest with a real TUN interface. Bridging to Wi-Fi does
not inherit the Mac's Tailscale routes. Enroll each guest once using the URL printed
by this command, then select your existing IPv6-capable Linux exit node:

```sh
./scripts/bsd/vm tailscale freebsd login
./scripts/bsd/vm tailscale freebsd exit-node YOUR-LINUX-EXIT-NODE
./scripts/bsd/vm doctor freebsd
./scripts/bsd/vm shell freebsd
# Inside the guest:
sudo "$CARGO_TARGET_DIR/debug/trip" example.com -6 --icmp
sudo "$CARGO_TARGET_DIR/debug/trip" example.com -6 --udp
sudo "$CARGO_TARGET_DIR/debug/trip" example.com -6 --tcp -P 443
```

The Linux exit node must have working public IPv6, kernel forwarding, and tailnet
policy permission for Internet access. Userspace subnet/exit routers reconstruct
TCP/UDP connections and relay pings, changing trace behavior. Tunnel traces show
the overlay and exit-side path, not the encrypted underlay's intermediate hops.
See [Tailscale routing behavior](https://tailscale.com/docs/reference/kernel-vs-userspace-routers).

Tailnet identity and the selected exit node persist. Tailscale does not replace
system DNS configuration. To test native bridged traffic again:

```sh
./scripts/bsd/vm tailscale freebsd direct
```

On NetBSD, the tool preserves the native IPv4 gateway after selecting an exit
node. The packaged client otherwise routes its own IPv4 tunnel transport back
into the TUN device. IPv4 probes use the native network; public IPv6 uses the exit
node. Reapply `tailscale netbsd exit-node NODE` after manually restarting its
Tailscale daemon, or restart through `vm up`.

`up --management-only` is an explicit diagnostic mode for installing/building
without host networking privileges. Its native connection does **not** validate
raw ICMP/UDP/TCP tracing. Probes inside an enrolled Tailscale TUN tunnel can still
be tested because QEMU carries the encapsulated transport traffic.
Stop the guest before switching between management-only and bridged launches.

## Lifecycle and recovery

```sh
./scripts/bsd/vm status
./scripts/bsd/vm console freebsd    # Ctrl-] disconnects
./scripts/bsd/vm stop freebsd
./scripts/bsd/vm stop freebsd --force
```

`stop` requests graceful shutdown; `--force` permits power-off after a timeout.
Per-guest locks prevent competing lifecycle commands. `console.log` records initial
installation, and `qemu.log` records hypervisor errors. A failed installation keeps
its disk and logs for diagnosis.

State lives in `~/Library/Application Support/trippy-bsd/`. Use `TRIPPY_VM_HOME` to
place it elsewhere. Short Unix socket paths are kept in a private temporary
runtime directory. `QEMU_BIN` and `QEMU_IMG` can select specific QEMU binaries.
Images contain a key-authenticated development account with passwordless guest
administration; treat them as development machines.

Ordinary starts retain the recorded release. To discard one guest and download
the latest stable release, stop it and run:

```sh
./scripts/bsd/vm recreate freebsd --latest
./scripts/bsd/vm up freebsd --bridge en0
```

Recreation asks for the guest name before deleting its disk, caches, SSH keys, and
Tailscale identity. Downloaded installation media remain cached. Official checksums
are fetched over HTTPS; OpenBSD also verifies installation sets in its installer.

## Validation

Run host tooling tests with:

```sh
python3 -m unittest discover -s scripts/bsd -v
sh -n scripts/bsd/provision.sh
```

For each BSD, start a fresh VM using `up`, enroll Tailscale, build Trippy from the
synchronized checkout, and run the repository's check, test, and Clippy commands.
Do not pass `--all-features` to `cargo test`.

Run bounded traces using `-m json -C 3` for ICMP, UDP, and TCP over IPv4 and IPv6.
Validate bridged IPv4 and IPv6 through the Linux exit node. Inspect guest `tcpdump`
captures to establish TTL/hop-limit values and returned ICMP errors; successful
package downloads or ping alone do not establish traceroute correctness. Exercise
UDP Paris/Dublin modes where supported. Retain results and classify upstream
filtering separately from guest or VM failures.

Finally, edit source on the Mac, sync and rebuild incrementally, then stop/restart
the guest and verify its build cache and Tailscale identity persist.

See the [validation results](bsd-vms-validation.md) for the BSD releases,
toolchains, protocol checks, and retained artifacts from the local acceptance run.
