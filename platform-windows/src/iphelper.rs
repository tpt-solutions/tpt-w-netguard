// SPDX-License-Identifier: MIT OR Apache-2.0
//! Connection attribution and per-app byte counters from the IP Helper API.
//!
//! * Connections and their owning PIDs come from `GetExtendedTcpTable` / `GetExtendedUdpTable`.
//! * Byte counters come from `GetPerTcpConnectionEStats` (TCP only). Collection must be enabled
//!   per connection, which works from an elevated process; counters start at the moment we
//!   enable them, so traffic from before the app started is not attributed.
//! * New connections are detected by polling the tables and diffing against the previous
//!   snapshot. ETW (Microsoft-Windows-TCPIP) is the planned event source; until it lands,
//!   `subscribe_new_connections` is served by this poll loop.
//!
//! The table buffers are `u32`-backed so the row arrays are correctly aligned.

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use tpt_netguard_core::error::{Error, Result};
use tpt_netguard_core::model::{ByteSample, Connection, ConnectionState, Direction, Protocol};
use tpt_netguard_core::traits::{NewConnectionHandler, TrafficMonitor};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, FALSE, TRUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, GetPerTcpConnectionEStats, SetPerTcpConnectionEStats,
    TCP_ESTATS_DATA_ROD_v0, TCP_ESTATS_DATA_RW_v0, TcpConnectionEstatsData, MIB_TCP6ROW_OWNER_PID,
    MIB_TCPROW_LH, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

const MIB_TCP_STATE_ESTAB: u32 = 5;
const MIB_TCP_STATE_LISTEN: u32 = 2;

/// Identity of one connection across snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConnKey {
    pid: u32,
    local: SocketAddr,
    remote: SocketAddr,
    protocol: Protocol,
}

/// Where the byte counters come from; reported so the UI can explain missing bandwidth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthSource {
    /// ESTATS counters are being read.
    EStats,
    /// ESTATS could not be enabled (usually: not elevated). Counters stay at zero.
    Unavailable,
}

pub struct IpHelperMonitor {
    process_cache: HashMap<u32, (String, Option<PathBuf>)>,
    estats_enabled: HashSet<ConnKey>,
    estats_failed: bool,
    last_totals: HashMap<ConnKey, (u64, u64)>,
    first_seen: HashMap<ConnKey, u64>,
    known: HashSet<ConnKey>,
    handlers: Vec<NewConnectionHandler>,
}

impl Default for IpHelperMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl IpHelperMonitor {
    pub fn new() -> Self {
        Self {
            process_cache: HashMap::new(),
            estats_enabled: HashSet::new(),
            estats_failed: false,
            last_totals: HashMap::new(),
            first_seen: HashMap::new(),
            known: HashSet::new(),
            handlers: Vec::new(),
        }
    }

    pub fn bandwidth_source(&self) -> BandwidthSource {
        if self.estats_failed {
            BandwidthSource::Unavailable
        } else {
            BandwidthSource::EStats
        }
    }

    /// Take one snapshot of every connection, with cumulative counters where available.
    fn snapshot(&mut self, now_ms: u64) -> Result<Vec<(Connection, ConnKey)>> {
        // SAFETY (all four calls below): `read_table` passes a buffer and its size in bytes, and
        // the IP Helper functions only write within that size. They report the required size
        // through `size` when the buffer is too small, which `read_table` handles.
        let tcp4: Vec<MIB_TCPROW_OWNER_PID> = read_table(|buf, size| unsafe {
            GetExtendedTcpTable(buf, size, FALSE, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
        })?;
        let tcp6: Vec<MIB_TCP6ROW_OWNER_PID> = read_table(|buf, size| unsafe {
            GetExtendedTcpTable(
                buf,
                size,
                FALSE,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        })?;
        let udp4: Vec<MIB_UDPROW_OWNER_PID> = read_table(|buf, size| unsafe {
            GetExtendedUdpTable(buf, size, FALSE, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
        })?;
        let udp6: Vec<MIB_UDP6ROW_OWNER_PID> = read_table(|buf, size| unsafe {
            GetExtendedUdpTable(buf, size, FALSE, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
        })?;

        // Listening ports, used to tell inbound connections from outbound ones.
        let listening: HashSet<u16> = tcp4
            .iter()
            .filter(|r| r.dwState == MIB_TCP_STATE_LISTEN)
            .map(|r| port(r.dwLocalPort))
            .chain(
                tcp6.iter()
                    .filter(|r| r.dwState == MIB_TCP_STATE_LISTEN)
                    .map(|r| port(r.dwLocalPort)),
            )
            .collect();

        let mut out = Vec::new();
        for row in &tcp4 {
            let local = SocketAddr::from((ipv4(row.dwLocalAddr), port(row.dwLocalPort)));
            let remote = SocketAddr::from((ipv4(row.dwRemoteAddr), port(row.dwRemotePort)));
            let state = tcp_state(row.dwState);
            let direction = tcp_direction(row.dwState, local.port(), &listening);
            let key = ConnKey {
                pid: row.dwOwningPid,
                local,
                remote,
                protocol: Protocol::Tcp,
            };
            let (sent, recv) = self.tcp_counters(row, key);
            out.push(self.build(key, state, direction, sent, recv, now_ms));
        }
        for row in &tcp6 {
            let local = SocketAddr::from((Ipv6Addr::from(row.ucLocalAddr), port(row.dwLocalPort)));
            let remote =
                SocketAddr::from((Ipv6Addr::from(row.ucRemoteAddr), port(row.dwRemotePort)));
            let state = tcp_state(row.dwState);
            let direction = tcp_direction(row.dwState, local.port(), &listening);
            let key = ConnKey {
                pid: row.dwOwningPid,
                local,
                remote,
                protocol: Protocol::Tcp,
            };
            out.push(self.build(key, state, direction, 0, 0, now_ms));
        }
        for row in &udp4 {
            let local = SocketAddr::from((ipv4(row.dwLocalAddr), port(row.dwLocalPort)));
            let key = ConnKey {
                pid: row.dwOwningPid,
                local,
                remote: SocketAddr::from(([0, 0, 0, 0], 0)),
                protocol: Protocol::Udp,
            };
            out.push(self.build(
                key,
                ConnectionState::Other,
                Direction::Unknown,
                0,
                0,
                now_ms,
            ));
        }
        for row in &udp6 {
            let local = SocketAddr::from((Ipv6Addr::from(row.ucLocalAddr), port(row.dwLocalPort)));
            let key = ConnKey {
                pid: row.dwOwningPid,
                local,
                remote: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
                protocol: Protocol::Udp,
            };
            out.push(self.build(
                key,
                ConnectionState::Other,
                Direction::Unknown,
                0,
                0,
                now_ms,
            ));
        }
        Ok(out)
    }

    fn build(
        &mut self,
        key: ConnKey,
        state: ConnectionState,
        direction: Direction,
        sent: u64,
        recv: u64,
        now_ms: u64,
    ) -> (Connection, ConnKey) {
        let (process_name, exe_path) = self.process_info(key.pid);
        let first_seen = *self.first_seen.entry(key).or_insert(now_ms);
        let conn = Connection {
            pid: key.pid,
            process_name,
            exe_path,
            local: key.local,
            remote: key.remote,
            protocol: key.protocol,
            direction,
            bytes_sent: sent,
            bytes_received: recv,
            state,
            first_seen_ms: first_seen,
            last_seen_ms: now_ms,
        };
        (conn, key)
    }

    /// Cumulative (sent, received) for a TCP row, enabling collection on first sight.
    fn tcp_counters(&mut self, row: &MIB_TCPROW_OWNER_PID, key: ConnKey) -> (u64, u64) {
        if self.estats_failed {
            return (0, 0);
        }
        // SAFETY: MIB_TCPROW_LH is a plain C struct; the union member is set through the
        // generated field, and the API is given buffers of exactly the sizes declared.
        unsafe {
            let mut lh: MIB_TCPROW_LH = std::mem::zeroed();
            lh.Anonymous.dwState = row.dwState;
            lh.dwLocalAddr = row.dwLocalAddr;
            lh.dwLocalPort = row.dwLocalPort;
            lh.dwRemoteAddr = row.dwRemoteAddr;
            lh.dwRemotePort = row.dwRemotePort;

            if self.estats_enabled.insert(key) {
                let rw = TCP_ESTATS_DATA_RW_v0 {
                    EnableCollection: TRUE as u8,
                };
                let rc = SetPerTcpConnectionEStats(
                    &lh,
                    TcpConnectionEstatsData,
                    &rw as *const _ as *const u8,
                    0,
                    std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>() as u32,
                    0,
                );
                if rc != 0 {
                    self.estats_failed = true;
                    return (0, 0);
                }
            }

            let mut rod: TCP_ESTATS_DATA_ROD_v0 = std::mem::zeroed();
            let rc = GetPerTcpConnectionEStats(
                &lh,
                TcpConnectionEstatsData,
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null_mut(),
                0,
                0,
                &mut rod as *mut _ as *mut u8,
                0,
                std::mem::size_of::<TCP_ESTATS_DATA_ROD_v0>() as u32,
            );
            if rc != 0 {
                return (0, 0);
            }
            (rod.DataBytesOut, rod.DataBytesIn)
        }
    }

    fn process_info(&mut self, pid: u32) -> (String, Option<PathBuf>) {
        if let Some(cached) = self.process_cache.get(&pid) {
            return cached.clone();
        }
        let info = match pid {
            0 => ("System Idle Process".to_string(), None),
            4 => ("System".to_string(), None),
            _ => query_image(pid).unwrap_or_else(|| (format!("pid {pid}"), None)),
        };
        self.process_cache.insert(pid, info.clone());
        info
    }

    /// Emit handlers for connections not seen in the previous poll; forget closed ones.
    fn notify_new(&mut self, conns: &[(Connection, ConnKey)]) {
        let current: HashSet<ConnKey> = conns.iter().map(|(_, k)| *k).collect();
        for (conn, key) in conns {
            if self.known.insert(*key) {
                for handler in &mut self.handlers {
                    handler(conn);
                }
            }
        }
        self.known.retain(|k| current.contains(k));
        self.last_totals.retain(|k, _| current.contains(k));
        self.first_seen.retain(|k, _| current.contains(k));
        self.estats_enabled.retain(|k| current.contains(k));
    }
}

/// Unix milliseconds now.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl TrafficMonitor for IpHelperMonitor {
    fn enumerate_connections(&mut self) -> Result<Vec<Connection>> {
        let snap = self.snapshot(now_unix_ms())?;
        self.notify_new(&snap);
        Ok(snap.into_iter().map(|(c, _)| c).collect())
    }

    fn sample_byte_deltas(&mut self, now_ms: u64) -> Result<Vec<ByteSample>> {
        let snap = self.snapshot(now_ms)?;
        self.notify_new(&snap);

        let mut per_app: HashMap<String, (u64, u64)> = HashMap::new();
        for (conn, key) in &snap {
            if key.protocol != Protocol::Tcp {
                continue;
            }
            let current = (conn.bytes_sent, conn.bytes_received);
            let previous = self.last_totals.insert(*key, current).unwrap_or((0, 0));
            // A counter that went backwards means the connection was reused: count from zero.
            let delta_sent = if current.0 >= previous.0 {
                current.0 - previous.0
            } else {
                current.0
            };
            let delta_recv = if current.1 >= previous.1 {
                current.1 - previous.1
            } else {
                current.1
            };
            if delta_sent == 0 && delta_recv == 0 {
                continue;
            }
            let app = conn
                .exe_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| conn.process_name.clone());
            let entry = per_app.entry(app).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(delta_sent);
            entry.1 = entry.1.saturating_add(delta_recv);
        }

        let mut samples: Vec<ByteSample> = per_app
            .into_iter()
            .map(|(app, (sent, recv))| ByteSample {
                app,
                timestamp_ms: now_ms,
                bytes_sent: sent,
                bytes_received: recv,
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

/// Call a table API twice: once to size the buffer, once to fill it.
///
/// The buffer is `u32`-backed so that the row array after the leading `dwNumEntries` field is
/// aligned for the row type.
fn read_table<R: Copy>(mut call: impl FnMut(*mut c_void, *mut u32) -> u32) -> Result<Vec<R>> {
    let mut size: u32 = 0;
    // First call reports the required size; it is expected to fail with "insufficient buffer".
    let _ = call(std::ptr::null_mut(), &mut size);
    for _ in 0..3 {
        let words = (size as usize).div_ceil(4).max(1);
        let mut buf = vec![0u32; words];
        let rc = call(buf.as_mut_ptr() as *mut c_void, &mut size);
        if rc == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if rc != 0 {
            return Err(Error::Backend(format!(
                "IP Helper table query failed: {rc}"
            )));
        }
        let count = buf[0] as usize;
        let row_size = std::mem::size_of::<R>();
        let needed = 4 + count * row_size;
        if needed > words * 4 {
            return Err(Error::Backend(
                "IP Helper returned a truncated table".into(),
            ));
        }
        // SAFETY: bounds checked above; rows are plain-old-data and copied out by value.
        let rows = unsafe {
            std::slice::from_raw_parts((buf.as_ptr() as *const u8).add(4) as *const R, count)
        };
        return Ok(rows.to_vec());
    }
    Err(Error::Backend(
        "IP Helper table kept growing; giving up".into(),
    ))
}

/// Port fields hold network byte order in the low 16 bits.
fn port(raw: u32) -> u16 {
    u16::from_be((raw & 0xFFFF) as u16)
}

/// IPv4 addresses are stored as their four octets in memory order.
fn ipv4(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(raw.to_ne_bytes())
}

fn tcp_state(raw: u32) -> ConnectionState {
    match raw {
        MIB_TCP_STATE_LISTEN => ConnectionState::Listening,
        MIB_TCP_STATE_ESTAB => ConnectionState::Established,
        1 => ConnectionState::Closed, // MIB_TCP_STATE_CLOSED
        _ => ConnectionState::Other,
    }
}

fn tcp_direction(state: u32, local_port: u16, listening: &HashSet<u16>) -> Direction {
    if state == MIB_TCP_STATE_LISTEN {
        Direction::Unknown
    } else if listening.contains(&local_port) {
        Direction::Inbound
    } else {
        Direction::Outbound
    }
}

/// Executable path and file name for a PID. Needs `PROCESS_QUERY_LIMITED_INFORMATION`, which
/// standard users get for their own processes; other processes return `None`.
fn query_image(pid: u32) -> Option<(String, Option<PathBuf>)> {
    // SAFETY: handle is closed on every path; the buffer length is passed in and updated.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if handle.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        let path = PathBuf::from(String::from_utf16_lossy(&buf[..len as usize]));
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("pid {pid}"));
        Some((name, Some(path)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only smoke test against the live tables: this machine always has listeners.
    #[test]
    fn enumerates_live_connections_with_owners() {
        let mut monitor = IpHelperMonitor::new();
        let conns = monitor.enumerate_connections().unwrap();
        assert!(
            !conns.is_empty(),
            "expected at least one socket on a running system"
        );
        assert!(conns.iter().any(|c| c.state == ConnectionState::Listening));
        assert!(conns.iter().all(|c| !c.process_name.is_empty()));
    }

    #[test]
    fn new_connection_handler_fires_once_per_connection() {
        use std::sync::{Arc, Mutex};
        let mut monitor = IpHelperMonitor::new();
        let seen = Arc::new(Mutex::new(0usize));
        let sink = Arc::clone(&seen);
        monitor
            .subscribe_new_connections(Box::new(move |_| *sink.lock().unwrap() += 1))
            .unwrap();
        monitor.enumerate_connections().unwrap();
        let first = *seen.lock().unwrap();
        monitor.enumerate_connections().unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            first,
            "unchanged sockets must not re-fire"
        );
    }

    #[test]
    fn port_and_address_decoding() {
        // 443 in network byte order stored in the low 16 bits.
        assert_eq!(port(u16::to_be(443) as u32), 443);
        assert_eq!(
            ipv4(u32::from_ne_bytes([10, 0, 0, 5])),
            Ipv4Addr::new(10, 0, 0, 5)
        );
    }
}

/// Needs an elevated process: opens the WFP engine for writing and adds then removes a rule.
#[cfg(test)]
mod wfp_tests {
    #[test]
    #[ignore = "requires an elevated (administrator) process"]
    fn wfp_block_rule_round_trip() {
        use tpt_netguard_core::traits::{AppRule, FirewallBackend, RuleAction};
        let mut enforcer = crate::wfp::WfpEnforcer::open().unwrap();
        let rule = AppRule {
            id: 1,
            app: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            action: RuleAction::Block,
            profile: None,
        };
        enforcer.apply_rule(&rule).unwrap();
        assert_eq!(enforcer.list_rules().unwrap(), vec![rule]);
        enforcer.set_block_all(true).unwrap();
        assert!(enforcer.block_all_enabled().unwrap());
        enforcer.set_block_all(false).unwrap();
        enforcer.remove_rule(1).unwrap();
    }
}
