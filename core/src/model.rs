// SPDX-License-Identifier: MIT OR Apache-2.0
//! Connection and traffic data model shared by every platform backend.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Serialize;

/// Transport protocol of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Direction relative to the local host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

/// Connection state as reported by the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    Established,
    Listening,
    Closed,
    Other,
}

/// A single observed connection, attributed to the owning process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Connection {
    pub pid: u32,
    pub process_name: String,
    pub exe_path: Option<PathBuf>,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub protocol: Protocol,
    pub direction: Direction,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub state: ConnectionState,
    /// Unix milliseconds when the connection was first observed.
    pub first_seen_ms: u64,
    /// Unix milliseconds when the connection was last observed.
    pub last_seen_ms: u64,
}

/// Byte counters for one application over one sampling interval.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ByteSample {
    /// Stable application key (executable path when known, else process name).
    pub app: String,
    /// Unix milliseconds at which the sample was taken.
    pub timestamp_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Byte totals used by rolling aggregates and rollups.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl Totals {
    pub fn add(&mut self, sent: u64, received: u64) {
        self.bytes_sent = self.bytes_sent.saturating_add(sent);
        self.bytes_received = self.bytes_received.saturating_add(received);
    }

    pub fn total(&self) -> u64 {
        self.bytes_sent.saturating_add(self.bytes_received)
    }
}

/// Milliseconds in one hour.
pub const HOUR_MS: u64 = 3_600_000;
/// Milliseconds in one day.
pub const DAY_MS: u64 = 24 * HOUR_MS;

/// Start of the hour containing `timestamp_ms`.
pub fn hour_bucket(timestamp_ms: u64) -> u64 {
    timestamp_ms - timestamp_ms % HOUR_MS
}

/// Start of the UTC day containing `timestamp_ms`.
pub fn day_bucket(timestamp_ms: u64) -> u64 {
    timestamp_ms - timestamp_ms % DAY_MS
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    /// The UI's TypeScript types depend on these exact strings.
    #[test]
    fn enums_use_lowercase_wire_names() {
        assert_eq!(serde_json::to_string(&Protocol::Tcp).unwrap(), "\"tcp\"");
        assert_eq!(
            serde_json::to_string(&Direction::Inbound).unwrap(),
            "\"inbound\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectionState::Established).unwrap(),
            "\"established\""
        );
    }
}
