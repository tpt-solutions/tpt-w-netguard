// SPDX-License-Identifier: MIT OR Apache-2.0
//! Alerts engine: turns observations into alerts, honouring mutes.
//!
//! The engine is pure: callers feed it observations and persist any alert it returns
//! (see `Store::insert_alert`). Mutes are "don't alert again for this subject" overrides.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::model::{Connection, Direction};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertKind {
    /// An application made its first network connection.
    NewApp,
    /// A device appeared on the LAN that is not yet known.
    NewDevice,
    /// An application exceeded the usage threshold within one sampling window.
    UsageSpike,
    /// An inbound connection hit a watched service port (RDP, SSH, VNC, ...).
    InboundRemote,
}

impl AlertKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertKind::NewApp => "new_app",
            AlertKind::NewDevice => "new_device",
            AlertKind::UsageSpike => "usage_spike",
            AlertKind::InboundRemote => "inbound_remote",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "new_app" => AlertKind::NewApp,
            "new_device" => AlertKind::NewDevice,
            "usage_spike" => AlertKind::UsageSpike,
            "inbound_remote" => AlertKind::InboundRemote,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "info" => Severity::Info,
            "warning" => Severity::Warning,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }
}

/// An alert with the rationale shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub kind: AlertKind,
    pub severity: Severity,
    /// What the alert is about: app key, device MAC, or service label.
    pub subject: String,
    pub message: String,
    pub ts_ms: u64,
}

/// A service port watched for inbound connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedPort {
    pub port: u16,
    pub service: &'static str,
}

/// Ports watched on Windows (remote desktop).
pub const WINDOWS_WATCHED_PORTS: &[WatchedPort] = &[WatchedPort {
    port: 3389,
    service: "RDP",
}];

/// Ports watched on Linux (SSH and VNC).
pub const LINUX_WATCHED_PORTS: &[WatchedPort] = &[
    WatchedPort {
        port: 22,
        service: "SSH",
    },
    WatchedPort {
        port: 5900,
        service: "VNC",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertConfig {
    /// Bytes within one sampling window that trigger a usage spike.
    pub usage_spike_bytes: u64,
    pub watched_ports: Vec<WatchedPort>,
}

impl AlertConfig {
    pub fn new(usage_spike_bytes: u64, watched_ports: &[WatchedPort]) -> Self {
        Self {
            usage_spike_bytes,
            watched_ports: watched_ports.to_vec(),
        }
    }
}

#[derive(Debug)]
pub struct AlertEngine {
    config: AlertConfig,
    known_apps: HashSet<String>,
    mutes: HashSet<(AlertKind, String)>,
}

impl AlertEngine {
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            known_apps: HashSet::new(),
            mutes: HashSet::new(),
        }
    }

    /// Seed apps already seen in earlier runs so they do not alert again on startup.
    pub fn with_known_apps<I, S>(mut self, apps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.known_apps.extend(apps.into_iter().map(Into::into));
        self
    }

    /// Restore mutes loaded from the store.
    pub fn with_mutes(mut self, mutes: impl IntoIterator<Item = (AlertKind, String)>) -> Self {
        self.mutes.extend(mutes);
        self
    }

    pub fn mute(&mut self, kind: AlertKind, subject: impl Into<String>) {
        self.mutes.insert((kind, subject.into()));
    }

    pub fn unmute(&mut self, kind: AlertKind, subject: &str) -> bool {
        self.mutes.remove(&(kind, subject.to_string()))
    }

    pub fn is_muted(&self, kind: AlertKind, subject: &str) -> bool {
        self.mutes.contains(&(kind, subject.to_string()))
    }

    /// Feed an app's connection. Returns a `NewApp` alert on its first ever connection.
    /// The app is marked known even when muted, so muting never re-triggers later.
    pub fn on_connection_app(&mut self, app: &str, ts_ms: u64) -> Option<Alert> {
        if !self.known_apps.insert(app.to_string()) {
            return None;
        }
        self.emit(
            AlertKind::NewApp,
            Severity::Info,
            app,
            format!("{app} made its first network connection"),
            ts_ms,
        )
    }

    /// Feed a device the registry classified as new.
    pub fn on_new_device(&mut self, mac: &str, label: &str, ts_ms: u64) -> Option<Alert> {
        self.emit(
            AlertKind::NewDevice,
            Severity::Warning,
            mac,
            format!("New device on the network: {label} ({mac})"),
            ts_ms,
        )
    }

    /// Feed one app's bytes for one sampling window.
    pub fn on_usage(&mut self, app: &str, window_bytes: u64, ts_ms: u64) -> Option<Alert> {
        if window_bytes <= self.config.usage_spike_bytes {
            return None;
        }
        self.emit(
            AlertKind::UsageSpike,
            Severity::Warning,
            app,
            format!(
                "{app} used {window_bytes} bytes in one sampling window (threshold {})",
                self.config.usage_spike_bytes
            ),
            ts_ms,
        )
    }

    /// Feed a connection; alerts when an inbound connection targets a watched port.
    pub fn on_connection_inbound(&mut self, conn: &Connection, ts_ms: u64) -> Option<Alert> {
        if conn.direction != Direction::Inbound {
            return None;
        }
        let watched = self
            .config
            .watched_ports
            .iter()
            .find(|w| w.port == conn.local.port())?
            .clone();
        let source = remote_label(conn.remote.ip());
        self.emit(
            AlertKind::InboundRemote,
            Severity::Critical,
            &conn.process_name,
            format!(
                "Inbound {} connection from {source} to {} (port {})",
                watched.service, conn.process_name, watched.port
            ),
            ts_ms,
        )
    }

    fn emit(
        &mut self,
        kind: AlertKind,
        severity: Severity,
        subject: &str,
        message: String,
        ts_ms: u64,
    ) -> Option<Alert> {
        if self.is_muted(kind, subject) {
            return None;
        }
        Some(Alert {
            kind,
            severity,
            subject: subject.to_string(),
            message,
            ts_ms,
        })
    }
}

fn remote_label(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) if v4.is_private() || v4.is_loopback() || v4.is_link_local() => {
            format!("local address {v4}")
        }
        IpAddr::V6(v6) if v6.is_loopback() => format!("local address {v6}"),
        other => format!("remote address {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConnectionState, Protocol};
    use std::net::SocketAddr;

    fn engine() -> AlertEngine {
        AlertEngine::new(AlertConfig::new(1_000, WINDOWS_WATCHED_PORTS))
    }

    fn inbound(local_port: u16, remote: &str) -> Connection {
        Connection {
            pid: 4,
            process_name: "svchost.exe".into(),
            exe_path: None,
            local: format!("0.0.0.0:{local_port}")
                .parse::<SocketAddr>()
                .unwrap(),
            remote: remote.parse::<SocketAddr>().unwrap(),
            protocol: Protocol::Tcp,
            direction: Direction::Inbound,
            bytes_sent: 0,
            bytes_received: 0,
            state: ConnectionState::Established,
            first_seen_ms: 0,
            last_seen_ms: 0,
        }
    }

    #[test]
    fn new_app_alerts_once() {
        let mut e = engine();
        assert_eq!(
            e.on_connection_app("a.exe", 1).unwrap().kind,
            AlertKind::NewApp
        );
        assert!(e.on_connection_app("a.exe", 2).is_none());
    }

    #[test]
    fn known_apps_from_history_do_not_alert() {
        let mut e = engine().with_known_apps(["a.exe"]);
        assert!(e.on_connection_app("a.exe", 1).is_none());
        assert!(e.on_connection_app("b.exe", 1).is_some());
    }

    #[test]
    fn mute_suppresses_alerts_and_survives_as_known() {
        let mut e = engine();
        e.mute(AlertKind::NewApp, "a.exe");
        assert!(e.on_connection_app("a.exe", 1).is_none());
        assert!(e.unmute(AlertKind::NewApp, "a.exe"));
        // Muted first sighting still marked the app known: unmuting does not resurrect it.
        assert!(e.on_connection_app("a.exe", 2).is_none());
    }

    #[test]
    fn usage_spike_respects_threshold() {
        let mut e = engine();
        assert!(e.on_usage("a.exe", 1_000, 1).is_none());
        let alert = e.on_usage("a.exe", 1_001, 1).unwrap();
        assert_eq!(alert.kind, AlertKind::UsageSpike);
        assert_eq!(alert.severity, Severity::Warning);
    }

    #[test]
    fn rdp_inbound_is_critical_and_other_ports_are_ignored() {
        let mut e = engine();
        let alert = e
            .on_connection_inbound(&inbound(3389, "203.0.113.5:50000"), 1)
            .unwrap();
        assert_eq!(alert.kind, AlertKind::InboundRemote);
        assert_eq!(alert.severity, Severity::Critical);
        assert!(alert.message.contains("RDP"));
        assert!(e
            .on_connection_inbound(&inbound(8080, "203.0.113.5:50000"), 1)
            .is_none());
    }

    #[test]
    fn outbound_connections_never_trigger_inbound_alerts() {
        let mut e = engine();
        let mut c = inbound(3389, "203.0.113.5:50000");
        c.direction = Direction::Outbound;
        assert!(e.on_connection_inbound(&c, 1).is_none());
    }

    #[test]
    fn severity_and_kind_strings_round_trip() {
        for k in [
            AlertKind::NewApp,
            AlertKind::NewDevice,
            AlertKind::UsageSpike,
            AlertKind::InboundRemote,
        ] {
            assert_eq!(AlertKind::parse(k.as_str()), Some(k));
        }
        for s in [Severity::Info, Severity::Warning, Severity::Critical] {
            assert_eq!(Severity::parse(s.as_str()), Some(s));
        }
        assert_eq!(AlertKind::parse("nope"), None);
    }
}
