// SPDX-License-Identifier: MIT OR Apache-2.0
//! Connection enumeration from `/proc`, and per-app TCP byte counters from `sock_diag`
//! (Linux only).
//!
//! `/proc` has no byte totals. The counters come from [`crate::sockdiag`], which asks the kernel
//! for each TCP socket's `tcp_info`. If that query is refused (for example in a restricted
//! container), [`LinuxMonitor::bandwidth_available`] is `false` and [`LinuxMonitor::bandwidth_status`]
//! says why, so the UI shows a note instead of misleading zeros.
//!
//! Like the Windows backend, byte counts are TCP only. The first counter snapshot is taken as a
//! baseline and produces no samples, so traffic from before the app started is not counted.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tpt_netguard_core::error::Result;
use tpt_netguard_core::model::{ByteSample, Connection, ConnectionState, Direction, Protocol};
use tpt_netguard_core::traits::{NewConnectionHandler, TrafficMonitor};

use crate::proc_net::{map_inodes, parse_table, SocketRow};
use crate::sockdiag::{self, TcpCounters};

/// Byte totals `(sent, received)` for one socket or app.
type Totals = (u64, u64);

#[derive(Default)]
pub struct LinuxMonitor {
    handlers: Vec<NewConnectionHandler>,
    known: HashSet<(u32, SocketAddr, SocketAddr)>,
    /// Last reading per socket cookie; the basis for deltas.
    last_totals: HashMap<u64, Totals>,
    /// True once a counter snapshot has been taken. The first one only sets the baseline.
    primed: bool,
    counters_ok: bool,
    counter_error: Option<String>,
}

impl LinuxMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the last counter read succeeded.
    pub fn bandwidth_available(&self) -> bool {
        self.counters_ok
    }

    /// Plain-language counter status for the UI.
    pub fn bandwidth_status(&self) -> String {
        if self.counters_ok {
            return "available".to_string();
        }
        match &self.counter_error {
            Some(reason) => format!("unavailable: {reason}"),
            None => "unavailable: not sampled yet".to_string(),
        }
    }

    /// Reads TCP counters, recording whether the kernel answered.
    fn read_counters(&mut self) -> Vec<TcpCounters> {
        match sockdiag::query_tcp() {
            Ok(rows) => {
                self.counters_ok = true;
                self.counter_error = None;
                rows
            }
            Err(e) => {
                self.counters_ok = false;
                self.counter_error = Some(format!("sock_diag query failed ({e})"));
                Vec::new()
            }
        }
    }

    fn snapshot(&self, now_ms: u64, totals: &HashMap<u64, Totals>) -> Vec<Connection> {
        let mut rows = Vec::new();
        for (file, protocol, v6) in [
            ("tcp", Protocol::Tcp, false),
            ("tcp6", Protocol::Tcp, true),
            ("udp", Protocol::Udp, false),
            ("udp6", Protocol::Udp, true),
        ] {
            if let Ok(text) = fs::read_to_string(format!("/proc/net/{file}")) {
                rows.extend(parse_table(&text, protocol, v6));
            }
        }

        let owners = map_inodes(&list_fd_links());
        let listening: HashSet<u16> = rows
            .iter()
            .filter(|r| r.protocol == Protocol::Tcp && r.state == 0x0A)
            .map(|r| r.local.port())
            .collect();

        rows.into_iter()
            .filter_map(|row| {
                let pid = *owners.get(&row.inode)?;
                let (process_name, exe_path) = process_identity(pid);
                let (sent, received) = totals.get(&row.inode).copied().unwrap_or((0, 0));
                Some(to_connection(
                    row,
                    pid,
                    process_name,
                    exe_path,
                    &listening,
                    (sent, received),
                    now_ms,
                ))
            })
            .collect()
    }

    fn notify_new(&mut self, conns: &[Connection]) {
        let current: HashSet<(u32, SocketAddr, SocketAddr)> =
            conns.iter().map(|c| (c.pid, c.local, c.remote)).collect();
        for conn in conns {
            if self.known.insert((conn.pid, conn.local, conn.remote)) {
                for handler in &mut self.handlers {
                    handler(conn);
                }
            }
        }
        self.known.retain(|k| current.contains(k));
    }
}

/// Byte growth between two readings of one socket. A counter that went backwards means the
/// socket was recycled, so the new reading is counted from zero.
pub fn delta(previous: Totals, current: Totals) -> Totals {
    let part = |prev: u64, cur: u64| if cur >= prev { cur - prev } else { cur };
    (part(previous.0, current.0), part(previous.1, current.1))
}

fn to_connection(
    row: SocketRow,
    pid: u32,
    process_name: String,
    exe_path: Option<PathBuf>,
    listening: &HashSet<u16>,
    totals: Totals,
    now_ms: u64,
) -> Connection {
    let state = match (row.protocol, row.state) {
        (Protocol::Tcp, 0x0A) => ConnectionState::Listening,
        (Protocol::Tcp, 0x01) => ConnectionState::Established,
        (Protocol::Tcp, 0x07) => ConnectionState::Closed,
        _ => ConnectionState::Other,
    };
    let direction = match (row.protocol, state) {
        (_, ConnectionState::Listening) => Direction::Unknown,
        (Protocol::Tcp, _) if listening.contains(&row.local.port()) => Direction::Inbound,
        (Protocol::Tcp, _) => Direction::Outbound,
        (Protocol::Udp, _) => Direction::Unknown,
    };
    Connection {
        pid,
        process_name,
        exe_path,
        local: row.local,
        remote: row.remote,
        protocol: row.protocol,
        direction,
        bytes_sent: totals.0,
        bytes_received: totals.1,
        state,
        first_seen_ms: now_ms,
        last_seen_ms: now_ms,
    }
}

/// Every process's fd symlinks that point at sockets.
fn list_fd_links() -> Vec<(u32, Vec<String>)> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let pid = e.file_name().to_str()?.parse::<u32>().ok()?;
            Some((pid, e.path()))
        })
        .map(|(pid, path)| {
            let links = fs::read_dir(path.join("fd"))
                .into_iter()
                .flatten()
                .filter_map(|fd| fs::read_link(fd.ok()?.path()).ok())
                .map(|target| target.to_string_lossy().into_owned())
                .filter(|t| t.starts_with("socket:"))
                .collect();
            (pid, links)
        })
        .collect()
}

fn process_identity(pid: u32) -> (String, Option<PathBuf>) {
    let exe = fs::read_link(format!("/proc/{pid}/exe")).ok();
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| format!("pid {pid}"));
    (comm, exe)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl TrafficMonitor for LinuxMonitor {
    fn enumerate_connections(&mut self) -> Result<Vec<Connection>> {
        let totals: HashMap<u64, Totals> = self
            .read_counters()
            .into_iter()
            .map(|c| (c.inode, (c.bytes_sent, c.bytes_received)))
            .collect();
        let conns = self.snapshot(now_ms(), &totals);
        self.notify_new(&conns);
        Ok(conns)
    }

    fn sample_byte_deltas(&mut self, now_ms: u64) -> Result<Vec<ByteSample>> {
        let counters = self.read_counters();
        if !self.counters_ok {
            // Nothing read this tick; the next successful read still works from its baseline.
            return Ok(Vec::new());
        }
        // Only the first successful snapshot is a baseline. Later, a cookie we have not seen
        // belongs to a socket created since the previous tick, so all its bytes are new.
        let baseline = !self.primed;
        self.primed = true;

        let owners = map_inodes(&list_fd_links());
        let mut identities: HashMap<u32, (String, Option<PathBuf>)> = HashMap::new();
        let mut per_app: HashMap<String, Totals> = HashMap::new();
        let mut live = HashSet::new();

        for counter in &counters {
            live.insert(counter.cookie);
            let current = (counter.bytes_sent, counter.bytes_received);
            let previous = self.last_totals.insert(counter.cookie, current);
            if baseline {
                continue;
            }
            let Some(&pid) = owners.get(&counter.inode) else {
                continue;
            };
            let (sent, received) = delta(previous.unwrap_or((0, 0)), current);
            if sent == 0 && received == 0 {
                continue;
            }
            let (name, exe) = identities
                .entry(pid)
                .or_insert_with(|| process_identity(pid))
                .clone();
            let app = exe
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or(name);
            let entry = per_app.entry(app).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(sent);
            entry.1 = entry.1.saturating_add(received);
        }
        self.last_totals.retain(|cookie, _| live.contains(cookie));

        let mut samples: Vec<ByteSample> = per_app
            .into_iter()
            .map(|(app, (sent, received))| ByteSample {
                app,
                timestamp_ms: now_ms,
                bytes_sent: sent,
                bytes_received: received,
            })
            .collect();
        samples.sort_by(|a, b| a.app.cmp(&b.app));
        Ok(samples)
    }

    fn subscribe_new_connections(&mut self, handler: NewConnectionHandler) -> Result<()> {
        self.handlers.push(handler);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::delta;

    #[test]
    fn delta_counts_growth_and_recycled_sockets_from_zero() {
        assert_eq!(delta((10, 20), (15, 40)), (5, 20));
        assert_eq!(delta((0, 0), (7, 9)), (7, 9));
        // Counter went backwards: the socket was reused, count the new reading from zero.
        assert_eq!(delta((100, 100), (3, 4)), (3, 4));
        assert_eq!(delta((50, 5), (50, 5)), (0, 0));
    }
}
