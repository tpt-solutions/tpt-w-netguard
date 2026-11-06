// SPDX-License-Identifier: MIT OR Apache-2.0
//! Kernel-side enforcement for per-app firewall rules.
//!
//! A process is denied network access when any of these holds:
//! * its id, as seen from the loader's PID namespace, is in `BLOCKED_TGIDS`. Userspace keeps
//!   that set in step with the running processes of each blocked executable;
//! * it inherited a block from a blocked parent and has not exec-ed since (`INHERITED`);
//! * it exec-ed less than `PENDING_WINDOW_NS` ago and userspace has not yet checked its
//!   executable (`PENDING`). This closes the gap between `exec` and that check. The deadline is
//!   enforced here, so a stalled loader cannot leave a process pending forever.
//!
//! `sched_process_fork` records inheritance, and `sched_process_exec` marks the process pending
//! and reports its id through `EXEC_EVENTS`.
//!
//! This object uses no GPL-only kernel helpers, so it declares an MIT license.
//!
//! Visible ids come from `bpf_get_ns_current_pid_tgid`, for the namespace the loader runs in,
//! so they match what `/proc` shows and the program works inside containers too. Kernel ids
//! (initial namespace) are used only for `INHERITED`, which is never compared with `/proc`.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_pidns_info,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, generated},
    macros::{cgroup_sock_addr, map, tracepoint},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::{SockAddrContext, TracePointContext},
    EbpfContext,
};

#[path = "../../src/ebpf_abi.rs"]
#[allow(dead_code)]
mod ebpf_abi;

use ebpf_abi::{PidNamespace, CONFIG_PENDING_WINDOW, MAX_BLOCKED_TGIDS, MAX_PENDING};

/// `(dev, ino)` of the loader's PID namespace, written by userspace before the programs attach.
#[map]
static PID_NS: Array<PidNamespace> = Array::with_max_entries(1, 0);

/// Settings written by userspace. `CONFIG_PENDING_WINDOW` is the pending window in nanoseconds;
/// zero disables pending, which userspace does while no rule is active.
#[map]
static CONFIG: Array<u64> = Array::with_max_entries(4, 0);

/// Visible ids (loader namespace) of processes that are blocked directly.
#[map]
static BLOCKED_TGIDS: HashMap<u32, u8> = HashMap::with_max_entries(MAX_BLOCKED_TGIDS, 0);

/// Kernel ids of processes that inherited a block from a blocked parent. Least-recently-used
/// eviction means an insert never fails; an evicted entry only loses the inheritance of a
/// long-idle process and never blocks anything new.
#[map]
static INHERITED: LruHashMap<u32, u8> = LruHashMap::with_max_entries(MAX_BLOCKED_TGIDS, 0);

/// Visible ids of processes that exec-ed and are not yet checked, mapped to the deadline (kernel
/// monotonic nanoseconds) after which they stop being denied.
#[map]
static PENDING: HashMap<u32, u64> = HashMap::with_max_entries(MAX_PENDING, 0);

/// Visible ids of processes that just exec-ed. Userspace drains this and checks each executable.
#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 4096, 0);

/// Offset of `child_pid` in `/sys/kernel/tracing/events/sched/sched_process_fork/format`. It is
/// part of the tracepoint ABI.
const FORK_CHILD_PID_OFFSET: usize = 20;

/// The kernel's id for the current process.
fn kernel_tgid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

/// The current process's id as seen from the loader's PID namespace, if it is visible there.
fn visible_tgid() -> Option<u32> {
    let ns = PID_NS.get(0)?;
    let mut info = bpf_pidns_info { pid: 0, tgid: 0 };
    let size = core::mem::size_of::<bpf_pidns_info>() as u32;
    let ret = unsafe { generated::bpf_get_ns_current_pid_tgid(ns.dev, ns.ino, &mut info, size) };
    if ret == 0 {
        Some(info.tgid)
    } else {
        None
    }
}

/// Whether the current process is exec-pending and its deadline has not passed.
fn is_pending_now(tgid: u32) -> bool {
    match unsafe { PENDING.get(&tgid) } {
        Some(deadline) => {
            let now = unsafe { bpf_ktime_get_ns() };
            now < *deadline
        }
        None => false,
    }
}

/// Whether the current process must be denied network access.
fn is_blocked_now() -> bool {
    if unsafe { INHERITED.get(&kernel_tgid()) }.is_some() {
        return true;
    }
    match visible_tgid() {
        Some(tgid) => unsafe { BLOCKED_TGIDS.get(&tgid) }.is_some() || is_pending_now(tgid),
        None => false,
    }
}

/// Returns 0 (reject, the caller sees EPERM) for denied processes and 1 otherwise.
fn verdict() -> i32 {
    if is_blocked_now() {
        0
    } else {
        1
    }
}

#[cgroup_sock_addr(connect4)]
pub fn connect4(_ctx: SockAddrContext) -> i32 {
    verdict()
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(_ctx: SockAddrContext) -> i32 {
    verdict()
}

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(_ctx: SockAddrContext) -> i32 {
    verdict()
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(_ctx: SockAddrContext) -> i32 {
    verdict()
}

fn try_fork(ctx: &TracePointContext) -> Result<(), i64> {
    // Runs in the parent's context. A child is blocked only if its parent is, so a recycled id
    // never keeps an old block. Reading the tracepoint record directly is allowed for tracepoint
    // programs, unlike probe-read helpers, which are GPL-only.
    let child: i32 = unsafe {
        core::ptr::read_volatile(
            ctx.as_ptr()
                .cast::<u8>()
                .add(FORK_CHILD_PID_OFFSET)
                .cast::<i32>(),
        )
    };
    let child = child as u32;
    if is_blocked_now() {
        INHERITED.insert(&child, &1, 0)?;
    } else {
        let _ = INHERITED.remove(&child);
    }
    Ok(())
}

#[tracepoint]
pub fn sched_fork(ctx: TracePointContext) -> u32 {
    // A failed record leaves one child unblocked until userspace's next sync; it never affects
    // the parent, so the error is deliberately not propagated.
    let _ = try_fork(&ctx);
    0
}

#[tracepoint]
pub fn sched_exec(_ctx: TracePointContext) -> u32 {
    // Inheritance ends at exec: the process now runs a program of its own.
    let _ = INHERITED.remove(&kernel_tgid());
    let Some(tgid) = visible_tgid() else {
        return 0;
    };
    // While rules exist, the new process is denied until userspace has checked it, but no longer
    // than the window. Dropping an event when the ring is full only delays that check, and the
    // deadline still bounds it.
    if let Some(window) = CONFIG.get(CONFIG_PENDING_WINDOW) {
        if *window > 0 {
            let deadline = unsafe { bpf_ktime_get_ns() } + *window;
            let _ = PENDING.insert(&tgid, &deadline, 0);
        }
    }
    let _ = EXEC_EVENTS.output(&tgid, 0);
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// None of the helpers above are GPL-only, so the program declares an MIT license.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"MIT\0";
