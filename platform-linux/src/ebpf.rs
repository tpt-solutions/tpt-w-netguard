// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-app enforcement through eBPF (Linux only).
//!
//! The kernel programs (`ebpf/`) block connects and datagram sends from the processes listed in
//! `BLOCKED_TGIDS`. This module loads them, attaches them to the cgroup v2 root (so they cover
//! every process), and keeps `BLOCKED_TGIDS` current in two ways:
//! * exec events: each new process id arrives on `EXEC_EVENTS`, and its executable is checked
//!   within a few milliseconds ([`EXEC_POLL`]);
//! * a full `/proc` scan every [`SYNC_EVERY`], which also catches processes that were already
//!   running when a rule was added. Rule changes sync at once.
//!
//! Without a built object (`cfg(ebpf_built)` unset) the loader is compiled but never reached, so
//! its internals are allowed to be unused in that configuration.
#![cfg_attr(not(ebpf_built), allow(dead_code, unused_imports))]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use aya::maps::{Array, HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, TracePoint};
use aya::{Ebpf, Pod};

use tpt_netguard_core::error::{Error, Result};
use tpt_netguard_core::policy::validate_rule;
use tpt_netguard_core::traits::AppRule;

use crate::app_rules::{blocked_apps, is_exec_path};
use crate::ebpf_abi::{
    PidNamespace, CONFIG_PENDING_WINDOW, MAP_BLOCKED_TGIDS, MAP_CONFIG, MAP_EXEC_EVENTS,
    MAP_PENDING, MAP_PID_NS, PENDING_WINDOW_NS, PROG_CONNECT4, PROG_CONNECT6, PROG_SCHED_EXEC,
    PROG_SCHED_FORK, PROG_SENDMSG4, PROG_SENDMSG6,
};

/// How often `/proc` is re-scanned for processes of blocked executables.
pub const SYNC_EVERY: Duration = Duration::from_millis(250);
/// How often exec events are drained. A new process is checked within about this long.
pub const EXEC_POLL: Duration = Duration::from_millis(5);
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

// The map value layout must match the kernel side byte for byte.
unsafe impl Pod for PidNamespace {}

#[cfg(ebpf_built)]
const OBJECT: &[u8] = include_bytes!(env!("TPT_EBPF_OBJECT"));

/// Userspace side of per-app eBPF enforcement. Dropping it stops the worker thread and detaches
/// the programs, which lifts every per-app block. The panic button is separate and unaffected.
pub struct EbpfEnforcer {
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

struct State {
    bpf: Ebpf,
    events: RingBuf<MapData>,
    rules: BTreeMap<i64, AppRule>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn backend(context: &str, e: impl std::fmt::Display) -> Error {
    Error::Backend(format!("eBPF {context}: {e}"))
}

impl EbpfEnforcer {
    /// Loads and attaches the programs. Needs root, or `CAP_BPF` and `CAP_NET_ADMIN`, and a
    /// kernel with cgroup v2 mounted at `/sys/fs/cgroup`.
    #[cfg(ebpf_built)]
    pub fn open() -> Result<Self> {
        if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
            return Err(Error::Unsupported(
                "per-app rules need cgroup v2 mounted at /sys/fs/cgroup",
            ));
        }
        let mut bpf = Ebpf::load(OBJECT).map_err(|e| backend("load", e))?;
        configure_pid_namespace(&mut bpf)?;
        let events = take_events(&mut bpf)?;
        set_pending_window(&mut bpf, 0)?;
        attach(&mut bpf)?;
        let state = Arc::new(Mutex::new(State {
            bpf,
            events,
            rules: BTreeMap::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("ebpf-sync".into())
                .spawn(move || run_worker(&state, &stop))
                .map_err(|e| backend("sync thread", e))?
        };
        Ok(Self {
            state,
            stop,
            worker: Some(worker),
        })
    }

    /// Without a built object there is nothing to load; the reason is reported to the UI.
    #[cfg(not(ebpf_built))]
    pub fn open() -> Result<Self> {
        Err(Error::Unsupported(
            "the eBPF object was not built (needs nightly Rust, rust-src and bpf-linker)",
        ))
    }

    pub fn list_rules(&self) -> Vec<AppRule> {
        lock(&self.state).rules.values().cloned().collect()
    }

    pub fn apply_rule(&mut self, rule: &AppRule) -> Result<()> {
        validate_rule(rule)?;
        if !is_exec_path(&rule.app) {
            return Err(Error::InvalidInput(
                "per-app rules need an absolute executable path".into(),
            ));
        }
        let mut st = lock(&self.state);
        let mut next = st.rules.clone();
        next.insert(rule.id, rule.clone());
        reconcile(&mut st, next)
    }

    pub fn remove_rule(&mut self, id: i64) -> Result<()> {
        let mut st = lock(&self.state);
        if !st.rules.contains_key(&id) {
            return Err(Error::InvalidInput(format!("no rule with id {id}")));
        }
        let mut next = st.rules.clone();
        next.remove(&id);
        reconcile(&mut st, next)
    }
}

impl Drop for EbpfEnforcer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

/// The worker: drains exec events quickly, and does a full scan on its own schedule.
#[cfg(ebpf_built)]
fn run_worker(state: &Mutex<State>, stop: &AtomicBool) {
    let mut last_scan = Instant::now();
    // The ring buffer's descriptor becomes readable as soon as the kernel records an exec, so
    // the wait below returns at once instead of sleeping for a whole poll interval.
    let fd = lock(state).events.as_raw_fd();
    while !stop.load(Ordering::Relaxed) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a valid, initialised pollfd for the duration of the call.
        unsafe { libc::poll(&mut pfd, 1, EXEC_POLL.as_millis() as libc::c_int) };
        let mut st = lock(state);
        let blocked = blocked_set(&st.rules);
        // Every new process is checked, blocked rules or not, because each one may be pending.
        let started = drain_exec_events(&mut st.events);
        // Block first, then clear pending: a process must never be unmarked before its block is
        // in place, or a connect in between would get through.
        if !blocked.is_empty() && !started.is_empty() {
            for pid in processes_running_with(&blocked, &started) {
                let _ = tgid_insert(&mut st.bpf, pid);
            }
        }
        for pid in &started {
            let _ = pending_remove(&mut st.bpf, *pid);
        }
        if last_scan.elapsed() >= SYNC_EVERY {
            last_scan = Instant::now();
            // A failed periodic sync (for example a process exiting mid-scan) is retried on the
            // next tick; the rule state itself is unaffected.
            let _ = sync_tgids(&mut st.bpf, &blocked);
        }
    }
}

/// Process ids announced by the exec hook since the last call. Each event is a `u32`.
fn drain_exec_events(events: &mut RingBuf<MapData>) -> Vec<u32> {
    let mut pids = Vec::new();
    while let Some(item) = events.next() {
        if let Ok(bytes) = <[u8; 4]>::try_from(&item[..]) {
            pids.push(u32::from_ne_bytes(bytes));
        }
    }
    pids
}

/// Installs `next` as the rule set and brings `BLOCKED_TGIDS` in line with it. If the kernel
/// refuses the update, the previous rule set is kept, so userspace never reports a rule that is
/// not enforced.
fn reconcile(st: &mut State, next: BTreeMap<i64, AppRule>) -> Result<()> {
    let before = std::mem::replace(&mut st.rules, next);
    let blocked = blocked_set(&st.rules);
    // The pending window only matters while something is blocked.
    let window = if blocked.is_empty() {
        0
    } else {
        PENDING_WINDOW_NS
    };
    let result =
        set_pending_window(&mut st.bpf, window).and_then(|()| sync_tgids(&mut st.bpf, &blocked));
    if let Err(e) = result {
        st.rules = before;
        return Err(e);
    }
    Ok(())
}

/// Executables to block, as the canonical paths `/proc` reports for them.
fn blocked_set(rules: &BTreeMap<i64, AppRule>) -> BTreeSet<String> {
    let list: Vec<AppRule> = rules.values().cloned().collect();
    blocked_apps(&list)
        .into_iter()
        .map(|app| canonical(&app))
        .collect()
}

fn canonical(app: &str) -> String {
    fs::canonicalize(app)
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .unwrap_or_else(|| app.to_owned())
}

#[cfg(ebpf_built)]
fn attach(bpf: &mut Ebpf) -> Result<()> {
    let cgroup = File::open(CGROUP_ROOT).map_err(|e| backend("cgroup", e))?;
    for name in [PROG_CONNECT4, PROG_CONNECT6, PROG_SENDMSG4, PROG_SENDMSG6] {
        let prog: &mut CgroupSockAddr = bpf
            .program_mut(name)
            .ok_or_else(|| backend("program", format!("{name} missing from object")))?
            .try_into()
            .map_err(|e| backend(name, e))?;
        prog.load().map_err(|e| backend(name, e))?;
        prog.attach(&cgroup, CgroupAttachMode::Single)
            .map_err(|e| backend(name, e))?;
    }
    for (name, event) in [
        (PROG_SCHED_FORK, "sched_process_fork"),
        (PROG_SCHED_EXEC, "sched_process_exec"),
    ] {
        let prog: &mut TracePoint = bpf
            .program_mut(name)
            .ok_or_else(|| backend("program", format!("{name} missing from object")))?
            .try_into()
            .map_err(|e| backend(name, e))?;
        prog.load().map_err(|e| backend(name, e))?;
        prog.attach("sched", event).map_err(|e| backend(name, e))?;
    }
    Ok(())
}

/// Tells the programs which PID namespace the process ids in `BLOCKED_TGIDS` belong to.
///
/// The kernel programs translate their own ids into this namespace, so the entries match what
/// `/proc` shows here, whether the loader runs on the host or inside a container.
#[cfg(ebpf_built)]
fn configure_pid_namespace(bpf: &mut Ebpf) -> Result<()> {
    let meta = fs::metadata("/proc/self/ns/pid").map_err(|e| backend("pid namespace", e))?;
    let ns = PidNamespace {
        dev: meta.dev(),
        ino: meta.ino(),
    };
    let map = bpf
        .map_mut(MAP_PID_NS)
        .ok_or_else(|| backend("map", format!("{MAP_PID_NS} missing")))?;
    let mut array: Array<_, PidNamespace> = Array::try_from(map).map_err(|e| backend("map", e))?;
    array.set(0, ns, 0).map_err(|e| backend("pid namespace", e))
}

/// Takes ownership of the exec-event ring buffer. The loader keeps it for the worker thread.
#[cfg(ebpf_built)]
fn take_events(bpf: &mut Ebpf) -> Result<RingBuf<MapData>> {
    let map = bpf
        .take_map(MAP_EXEC_EVENTS)
        .ok_or_else(|| backend("map", format!("{MAP_EXEC_EVENTS} missing")))?;
    RingBuf::try_from(map).map_err(|e| backend("exec events", e))
}

/// Sets how long a new process is denied before userspace has checked it. Zero turns it off.
fn set_pending_window(bpf: &mut Ebpf, nanos: u64) -> Result<()> {
    let map = bpf
        .map_mut(MAP_CONFIG)
        .ok_or_else(|| backend("map", format!("{MAP_CONFIG} missing")))?;
    let mut config: Array<_, u64> = Array::try_from(map).map_err(|e| backend("map", e))?;
    config
        .set(CONFIG_PENDING_WINDOW, nanos, 0)
        .map_err(|e| backend("config", e))
}

/// Clears the pending mark for `pid`, so it stops being denied. Absent entries are fine.
fn pending_remove(bpf: &mut Ebpf, pid: u32) -> Result<()> {
    let map = bpf
        .map_mut(MAP_PENDING)
        .ok_or_else(|| backend("map", format!("{MAP_PENDING} missing")))?;
    let mut pending: BpfHashMap<_, u32, u64> =
        BpfHashMap::try_from(map).map_err(|e| backend("map", e))?;
    let _ = pending.remove(&pid);
    Ok(())
}

fn tgid_map(bpf: &mut Ebpf) -> Result<BpfHashMap<&mut MapData, u32, u8>> {
    let map = bpf
        .map_mut(MAP_BLOCKED_TGIDS)
        .ok_or_else(|| backend("map", format!("{MAP_BLOCKED_TGIDS} missing")))?;
    BpfHashMap::try_from(map).map_err(|e| backend("map", e))
}

fn tgid_insert(bpf: &mut Ebpf, pid: u32) -> Result<()> {
    tgid_map(bpf)?
        .insert(pid, 1u8, 0)
        .map_err(|e| backend("map insert", e))
}

/// Makes `BLOCKED_TGIDS` hold the running processes whose executable is in `blocked`.
fn sync_tgids(bpf: &mut Ebpf, blocked: &BTreeSet<String>) -> Result<()> {
    let wanted = processes_running(blocked);
    let mut map = tgid_map(bpf)?;
    let current: Vec<u32> = map
        .keys()
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| backend("map read", e))?;
    for pid in current {
        if !wanted.contains(&pid) {
            map.remove(&pid).map_err(|e| backend("map remove", e))?;
        }
    }
    for pid in wanted {
        map.insert(pid, 1u8, 0)
            .map_err(|e| backend("map insert", e))?;
    }
    Ok(())
}

/// Process ids whose `/proc/<pid>/exe` is one of `blocked`.
///
/// The kernel programs translate their ids into the loader's PID namespace, so these are the
/// ids the programs check, host or container alike.
fn processes_running(blocked: &BTreeSet<String>) -> BTreeSet<u32> {
    if blocked.is_empty() {
        return BTreeSet::new();
    }
    let Ok(entries) = fs::read_dir("/proc") else {
        return BTreeSet::new();
    };
    let exes = entries.filter_map(|entry| {
        let entry = entry.ok()?;
        let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
        let exe = fs::read_link(entry.path().join("exe")).ok()?;
        Some((pid, exe))
    });
    matching_pids(exes, blocked)
}

/// The subset of `pids` whose `/proc/<pid>/exe` is blocked. Used for exec events, which name
/// only the processes to check.
#[cfg(ebpf_built)]
fn processes_running_with(blocked: &BTreeSet<String>, pids: &[u32]) -> BTreeSet<u32> {
    let exes = pids.iter().filter_map(|&pid| {
        let exe = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        Some((pid, exe))
    });
    matching_pids(exes, blocked)
}

/// Pure core of [`processes_running`]: picks the ids whose executable is blocked.
pub fn matching_pids(
    exes: impl IntoIterator<Item = (u32, PathBuf)>,
    blocked: &BTreeSet<String>,
) -> BTreeSet<u32> {
    exes.into_iter()
        .filter(|(_, exe)| exe.to_str().is_some_and(|s| blocked.contains(s)))
        .map(|(pid, _)| pid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_processes_of_blocked_executables_match() {
        let blocked: BTreeSet<String> = ["/usr/bin/curl".to_string()].into();
        let exes = vec![
            (10, PathBuf::from("/usr/bin/curl")),
            (11, PathBuf::from("/usr/bin/wget")),
            (12, PathBuf::from("/usr/bin/curl (deleted)")),
        ];
        assert_eq!(matching_pids(exes, &blocked), BTreeSet::from([10]));
    }

    #[test]
    fn nothing_blocked_matches_nothing() {
        let exes = vec![(1, PathBuf::from("/bin/sh"))];
        assert!(matching_pids(exes, &BTreeSet::new()).is_empty());
    }
}
