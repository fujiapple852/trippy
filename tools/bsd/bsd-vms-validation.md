# BSD VM validation — 14 November 2026

Validated on this Intel MacBook running macOS 15.7.9 and QEMU 11.1.3, using HVF,
two virtual CPUs, 4 GiB RAM, and 64 GiB sparse disks. All guests were acquired and
provisioned through `scripts/bsd/vm`; host administrator authentication and one
Tailscale enrollment per guest were performed in the user's terminal/browser.

| Guest   | Release      | Rust    | Build  | Tests  | Workspace check | Clippy |
| ------- | ------------ | ------- | ------ | ------ | --------------- | ------ |
| FreeBSD | 15.1-RELEASE | 1.100.0 | Passed | Passed | Passed          | Passed |
| NetBSD  | 11.1         | 1.100.0 | Passed | Passed | Passed          | Passed |
| OpenBSD | 8.0          | 1.98.1  | Passed | Passed | Passed          | Passed |

The commands used inside each guest were:

```sh
cargo build --locked -p trippy
cargo test
cargo check --workspace --all-features --tests
cargo clippy --workspace --all-features --tests -- -Dwarnings
```

OpenBSD requires the separate `rust-clippy` package; provisioning installs it.
NetBSD's build produces dependency linker compatibility warnings, but its check,
tests, and Clippy all passed.

## Probe networking

All three guests used `vmnet-bridged` on Wi-Fi interface `en0` for IPv4, and their
own Tailscale TUN interface through the Linux exit node `tailscale-exit-uk-tf` for
public IPv6. Native IPv6 Internet access on the Wi-Fi LAN was not tested.

The freshly built `trip` binary was run using ICMP, UDP, and TCP for both address
families, with bounded JSON reports. IPv4 targeted `1.1.1.1`; IPv6 targeted
`2606:4700:4700::1111`; TCP used port 443. Every combination received multiple-hop
responses on each BSD. ICMP and TCP reached the destination. UDP received
intermediate ICMP errors; destination response is subject to the target's policy.

IPv4 UDP Paris and Dublin modes, with fixed source/destination ports, also received
hop responses on all three BSDs.

Guest packet captures on each bridged NIC and TUN interface confirmed varying
IPv4 TTLs / IPv6 hop limits and returned ICMP time-exceeded messages. User-mode
QEMU networking was used for provisioning and management, not as evidence of native
probe support.

## Development workflow and persistence

- Source additions, modifications, and deletions were synchronized and verified
  inside all three guests.
- Guest Cargo caches and binaries survived synchronization.
- Subsequent incremental builds completed in approximately 1–2 seconds.
- Guests were stopped and restarted through the tool, retaining source, Cargo
  caches, SSH host keys, and Tailscale identities.
- Repeated network configuration completed successfully on all three guests.
- Host tooling passed ten offline behavior tests, Python lint/format checks,
  shell syntax checks, and documentation formatting checks.

Validation artifacts are retained in each VM's host state directory under
`validation/`, including trace JSON, packet-capture text, check/Clippy logs, and
incremental-build logs. VM state is retained at the normal location documented in
[Local BSD development VMs](bsd-vms.md).

The macOS workspace check and tests also passed with Rust 1.92. Host Clippy with
that older compiler failed on an existing lint expectation in `trippy-dns`;
Clippy passed inside all three BSD guests with the toolchains listed above.
