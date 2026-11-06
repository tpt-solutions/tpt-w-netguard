// SPDX-License-Identifier: MIT OR Apache-2.0
//! Connection enumeration from `/proc` (Linux only).
//!
//! Byte counters are not available from `/proc`, so [`LinuxMonitor::sample_byte_deltas`]
//! returns no samples and [`LinuxMonitor::bandwidth_available`] is `false`. The UI shows
//! connections and a "bandwidth unavailable" note instead of misleading zeros.

use std::collections::HashSet;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tpt_netguard_core::error::Result;
use tpt_netguard_core::model::{ByteSample, Connection, ConnectionState, Direction, Protocol};
use tpt_netguard_core::traits::{NewConnectionHandler, TrafficMonitor};

use crate::proc_net::{map_inodes, parse_table, SocketRow};

#[derive(Default)]
pub struct LinuxMonitor {
    handlers: Vec<NewConnectionHandler>,
    known: HashSet<(u32, SocketAddr, SocketAddr)>,
}

impl LinuxMonitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Always `false` for now: see module docs.
    pub fn bandwidth_available(&self) -> bool {
        false
    }

    fn snapshot(&self, now_ms: u64) -> Vec<Connection> {
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
                Some(to_connection(
                    row,
                    pid,
                    process_name,
                    exe_path,
                    &listening,
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

fn to_connection(
    row: SocketRow,
    pid: u32,
    process_name: String,
    exe_path: Option<PathBuf>,
    listening: &HashSet<u16>,
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
        bytes_sent: 0,
        bytes_received: 0,
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
        let conns = self.snapshot(now_ms());
        self.notify_new(&conns);
        Ok(conns)
    }

    fn sample_byte_deltas(&mut self, _now_ms: u64) -> Result<Vec<ByteSample>> {
        // No byte counters from /proc; see module docs.
        Ok(Vec::new())
    }

    fn subscribe_new_connections(&mut self, handler: NewConnectionHandler) -> Result<()> {
        self.handlers.push(handler);
        Ok(())
    }
}
