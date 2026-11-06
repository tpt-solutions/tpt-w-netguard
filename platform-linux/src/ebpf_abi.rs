// SPDX-License-Identifier: MIT OR Apache-2.0
//! Types shared by the kernel-side eBPF program (`platform-linux/ebpf`) and the userspace loader.
//! Keep this file `no_std`-compatible: the eBPF crate includes it directly.

/// Identity of a PID namespace: the `st_dev` and `st_ino` of `/proc/self/ns/pid`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PidNamespace {
    pub dev: u64,
    pub ino: u64,
}

/// Map names, agreed between the two sides.
pub const MAP_BLOCKED_TGIDS: &str = "BLOCKED_TGIDS";
pub const MAP_PID_NS: &str = "PID_NS";
pub const MAP_EXEC_EVENTS: &str = "EXEC_EVENTS";
pub const MAP_PENDING: &str = "PENDING";
pub const MAP_CONFIG: &str = "CONFIG";

/// Capacity limit; the loader fails loudly rather than silently dropping entries.
pub const MAX_BLOCKED_TGIDS: u32 = 65_536;
pub const MAX_PENDING: u32 = 4_096;

/// Index in `CONFIG` of the pending window, in nanoseconds.
pub const CONFIG_PENDING_WINDOW: u32 = 0;
/// Default pending window: a new program is denied until checked, but for at most this long.
pub const PENDING_WINDOW_NS: u64 = 5_000_000;

/// Program names, agreed between the two sides.
pub const PROG_CONNECT4: &str = "connect4";
pub const PROG_CONNECT6: &str = "connect6";
pub const PROG_SENDMSG4: &str = "sendmsg4";
pub const PROG_SENDMSG6: &str = "sendmsg6";
pub const PROG_SCHED_FORK: &str = "sched_fork";
pub const PROG_SCHED_EXEC: &str = "sched_exec";
