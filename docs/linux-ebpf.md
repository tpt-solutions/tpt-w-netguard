# Linux per-app enforcement (eBPF)

tpt-netguard blocks individual programs on Linux with eBPF. The panic button ("block all
internet") stays on nftables. This page covers what the eBPF path does, what it needs, and where
it stops.

## What it does

A rule such as "block `/usr/bin/curl`" is enforced in the kernel:

- **Connects and datagram sends** (IPv4 and IPv6, TCP and UDP) from a blocked program fail with
  `EPERM`. The hooks are `cgroup/connect4`, `connect6`, `sendmsg4` and `sendmsg6`, attached to
  the cgroup v2 root so they cover every process.
- **Children of a blocked program** inherit the block at `fork`, before they can connect. The
  inheritance ends when the child executes a program of its own.
- **A program started while rules exist is held until it is checked.** On `exec` the kernel
  refuses that process network access for up to 5 ms. The loader wakes on the event, checks the
  executable, and then either blocks it or releases it. Blocked programs stay blocked; other
  programs are released after the check. See the limits below.
- **Programs already running** when the rule is added are blocked at once, and a 250 ms `/proc`
  scan keeps the set current as processes start and exit.

Rules are per executable path. Only absolute paths are accepted. When a profile-scoped rule and
an unscoped rule disagree, the scoped one wins, matching the rest of the app.

Removing a rule lifts the block at once. Closing tpt-netguard detaches the programs, which also
lifts every per-app block. The panic button is separate and is unaffected by that.

## What it does not cover

- **A brand-new program can have its first connect refused.** While rules exist, a program that
  connects within the first few tens of microseconds of starting is refused, because the kernel
  cannot yet tell it apart from a blocked one. Measured with a fresh probe program, that happened
  to 3 and 4 in 1000 trials (two runs), and no blocked program got through in 2000 trials. Real
  programs connect much later than that, so the real-world rate should be far lower; that is not
  measured yet. A refused connect appears as an ordinary permission error, and most programs
  retry. Run the measurement with `NETGUARD_MEASURE=1000` (see Testing).
- **The pending window is bounded.** A program is refused for at most 5 ms after `exec`, even if
  the loader stalls, so the refusal can never last longer than that.
- Processes already running are checked on the 250 ms scan as well, so a long-running blocked
  program is always covered within that interval.
- **Raw sockets and ICMP** are not hooked, so a blocked program that opens a raw socket can
  still send. Blocking those needs a different hook.
- **Per-connection byte counters** are not provided by this path. Bandwidth on Linux is still
  shown as unavailable.
- **cgroup v1 hosts** are not supported. Per-app rules report the reason in Settings; the panic
  button still works.

## Requirements

Runtime:

- Linux 5.8 or newer, with cgroup v2 mounted at `/sys/fs/cgroup` and tracefs at
  `/sys/kernel/tracing` (most distributions mount both).
- Root, or `CAP_BPF` and `CAP_NET_ADMIN` (and `CAP_PERFMON` on kernels that need it).

Process IDs: the kernel programs translate their ids into the PID namespace the loader runs in
(`bpf_get_ns_current_pid_tgid`), so the app works on the host and inside containers alike.

Build (only needed to build the eBPF object):

- A nightly Rust toolchain with `rust-src`: `rustup toolchain install nightly --component rust-src`.
- `bpf-linker`, built against an LLVM it supports, for example:
  `LLVM_PREFIX=/usr/lib/llvm-22 cargo install bpf-linker --locked --no-default-features --features llvm-22`
  Use the LLVM major version your distribution ships.

If those are missing, the build still succeeds with a warning, and per-app rules are reported as
unavailable with the reason. `TPT_SKIP_EBPF=1` skips the object build on purpose.

## License of the kernel program

The kernel-side program (`platform-linux/ebpf/`) declares an MIT license and uses no GPL-only
kernel helpers, so the whole repository is MIT OR Apache-2.0 with no GPL component. The
kernel checks this when the program loads: a GPL-only helper in a non-GPL program is refused.

The price is the first-connect refusal described above. Matching the executable path inside the
kernel at `exec` needs `bpf_probe_read_str` or `bpf_probe_read`, and both are GPL-only, so the
kernel cannot identify a new program from its own path.

## Testing

`platform-linux/tests/enforcement.rs` runs real programs against the kernel. The test binary is
its own probe, so it needs no interpreter. It is ignored by default because it needs root, the
built object and a kernel with BPF enabled:

```text
cargo test -p tpt-netguard-platform-linux -- --include-ignored
```

It checks that a blocked copy cannot connect over TCP or send UDP, that its forked child is
blocked, that a program already running is blocked, that a control copy still connects, that
removing the rule restores access, and that relative paths are refused.

Verified on a 6.18 WSL2 kernel, both inside a privileged Debian container and in the Docker
Desktop WSL distribution. Not yet verified on a bare-metal desktop distribution or on an older
kernel; those are part of the Linux manual QA in `todo.md`.
