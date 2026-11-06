// SPDX-License-Identifier: MIT OR Apache-2.0
//! Alert delivery: the pipeline that turns observations into persisted, notified alerts.
//!
//! Order of operations for every alert: persist first (the in-app Alerts tab is the source of
//! truth), then notify. A failing OS notifier never loses an alert, and a failing store is
//! reported to the caller instead of being silently dropped.

use crate::alerts::{Alert, AlertEngine};
use crate::error::Result;
use crate::model::{ByteSample, Connection};

/// Delivers an alert to the user through the OS (toast, tray balloon, ...).
pub trait Notifier: Send {
    fn notify(&mut self, alert: &Alert) -> Result<()>;
}

/// Persists an alert (the alert log).
pub trait AlertSink: Send {
    fn persist(&mut self, alert: &Alert) -> Result<()>;
}

/// Counts of what the pipeline did during one call.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryReport {
    pub raised: usize,
    pub notify_failures: usize,
}

pub struct AlertPipeline<N: Notifier, S: AlertSink> {
    engine: AlertEngine,
    notifier: N,
    sink: S,
    /// Bytes accumulated per app within the current window, flushed by `on_window_end`.
    window: Vec<(String, u64)>,
}

impl<N: Notifier, S: AlertSink> AlertPipeline<N, S> {
    pub fn new(engine: AlertEngine, notifier: N, sink: S) -> Self {
        Self {
            engine,
            notifier,
            sink,
            window: Vec::new(),
        }
    }

    pub fn engine_mut(&mut self) -> &mut AlertEngine {
        &mut self.engine
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    pub fn notifier(&self) -> &N {
        &self.notifier
    }

    /// Feed a connection: first-connection (new app) and inbound watched-port alerts.
    pub fn on_connection(&mut self, conn: &Connection, ts_ms: u64) -> Result<DeliveryReport> {
        let mut report = DeliveryReport::default();
        if let Some(alert) = self.engine.on_connection_app(&conn.process_name, ts_ms) {
            self.deliver(&alert, &mut report)?;
        }
        if let Some(alert) = self.engine.on_connection_inbound(conn, ts_ms) {
            self.deliver(&alert, &mut report)?;
        }
        Ok(report)
    }

    /// Accumulate byte samples for the current window. Call `on_window_end` to evaluate them.
    pub fn on_samples(&mut self, samples: &[ByteSample]) {
        for sample in samples {
            let bytes = sample.bytes_sent.saturating_add(sample.bytes_received);
            match self.window.iter_mut().find(|(app, _)| *app == sample.app) {
                Some((_, total)) => *total = total.saturating_add(bytes),
                None => self.window.push((sample.app.clone(), bytes)),
            }
        }
    }

    /// Evaluate usage-spike thresholds for the accumulated window and reset it.
    pub fn on_window_end(&mut self, ts_ms: u64) -> Result<DeliveryReport> {
        let mut report = DeliveryReport::default();
        let window = std::mem::take(&mut self.window);
        for (app, bytes) in window {
            if let Some(alert) = self.engine.on_usage(&app, bytes, ts_ms) {
                self.deliver(&alert, &mut report)?;
            }
        }
        Ok(report)
    }

    /// Report a device the registry classified as new.
    pub fn on_new_device(&mut self, mac: &str, label: &str, ts_ms: u64) -> Result<DeliveryReport> {
        let mut report = DeliveryReport::default();
        if let Some(alert) = self.engine.on_new_device(mac, label, ts_ms) {
            self.deliver(&alert, &mut report)?;
        }
        Ok(report)
    }

    fn deliver(&mut self, alert: &Alert, report: &mut DeliveryReport) -> Result<()> {
        self.sink.persist(alert)?;
        report.raised += 1;
        if self.notifier.notify(alert).is_err() {
            report.notify_failures += 1;
        }
        Ok(())
    }
}

/// Notifier that keeps alerts in memory. Used by tests and by headless runs.
#[derive(Debug, Default)]
pub struct RecordingNotifier {
    pub delivered: Vec<Alert>,
    pub fail: bool,
}

impl Notifier for RecordingNotifier {
    fn notify(&mut self, alert: &Alert) -> Result<()> {
        if self.fail {
            return Err(crate::error::Error::Backend("notifier unavailable".into()));
        }
        self.delivered.push(alert.clone());
        Ok(())
    }
}

/// Sink that keeps alerts in memory.
#[derive(Debug, Default)]
pub struct VecSink {
    pub stored: Vec<Alert>,
    pub fail: bool,
}

impl AlertSink for VecSink {
    fn persist(&mut self, alert: &Alert) -> Result<()> {
        if self.fail {
            return Err(crate::error::Error::Store("disk full".into()));
        }
        self.stored.push(alert.clone());
        Ok(())
    }
}

#[cfg(feature = "sqlite")]
impl AlertSink for crate::store::Store {
    fn persist(&mut self, alert: &Alert) -> Result<()> {
        self.insert_alert(alert).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::{AlertConfig, AlertKind, WINDOWS_WATCHED_PORTS};
    use crate::model::{ConnectionState, Direction, Protocol};
    use std::net::SocketAddr;

    fn engine() -> AlertEngine {
        AlertEngine::new(AlertConfig::new(1_000, WINDOWS_WATCHED_PORTS))
    }

    fn conn(name: &str, direction: Direction, local_port: u16) -> Connection {
        Connection {
            pid: 1,
            process_name: name.into(),
            exe_path: None,
            local: SocketAddr::from(([127, 0, 0, 1], local_port)),
            remote: "203.0.113.5:51000".parse().unwrap(),
            protocol: Protocol::Tcp,
            direction,
            bytes_sent: 0,
            bytes_received: 0,
            state: ConnectionState::Established,
            first_seen_ms: 0,
            last_seen_ms: 0,
        }
    }

    fn sample(app: &str, sent: u64, recv: u64) -> ByteSample {
        ByteSample {
            app: app.into(),
            timestamp_ms: 0,
            bytes_sent: sent,
            bytes_received: recv,
        }
    }

    #[test]
    fn new_app_is_persisted_and_notified_once() {
        let mut p = AlertPipeline::new(engine(), RecordingNotifier::default(), VecSink::default());
        let c = conn("chrome.exe", Direction::Outbound, 50000);
        let first = p.on_connection(&c, 1).unwrap();
        let second = p.on_connection(&c, 2).unwrap();
        assert_eq!(first.raised, 1);
        assert_eq!(second.raised, 0);
        assert_eq!(p.sink().stored.len(), 1);
        assert_eq!(p.notifier().delivered[0].kind, AlertKind::NewApp);
    }

    #[test]
    fn inbound_rdp_raises_critical_alert() {
        let mut p = AlertPipeline::new(engine(), RecordingNotifier::default(), VecSink::default());
        p.on_connection(&conn("svchost.exe", Direction::Inbound, 3389), 1)
            .unwrap();
        let kinds: Vec<AlertKind> = p.sink().stored.iter().map(|a| a.kind).collect();
        assert!(kinds.contains(&AlertKind::InboundRemote));
    }

    #[test]
    fn usage_spike_is_evaluated_per_window_across_samples() {
        let mut p = AlertPipeline::new(engine(), RecordingNotifier::default(), VecSink::default());
        // Each sample is under the 1000-byte threshold; the window total is over it.
        p.on_samples(&[sample("a.exe", 400, 0), sample("a.exe", 0, 700)]);
        let report = p.on_window_end(10).unwrap();
        assert_eq!(report.raised, 1);
        // The window resets: an empty window raises nothing.
        assert_eq!(p.on_window_end(20).unwrap().raised, 0);
    }

    #[test]
    fn notifier_failure_still_persists_alert() {
        let notifier = RecordingNotifier {
            fail: true,
            ..Default::default()
        };
        let mut p = AlertPipeline::new(engine(), notifier, VecSink::default());
        let report = p
            .on_connection(&conn("x.exe", Direction::Outbound, 1), 1)
            .unwrap();
        assert_eq!(report.raised, 1);
        assert_eq!(report.notify_failures, 1);
        assert_eq!(p.sink().stored.len(), 1);
    }

    #[test]
    fn sink_failure_is_reported_not_swallowed() {
        let sink = VecSink {
            fail: true,
            ..Default::default()
        };
        let mut p = AlertPipeline::new(engine(), RecordingNotifier::default(), sink);
        assert!(p
            .on_connection(&conn("x.exe", Direction::Outbound, 1), 1)
            .is_err());
        assert!(p.notifier().delivered.is_empty());
    }

    #[test]
    fn muted_subjects_are_not_delivered() {
        let mut e = engine();
        e.mute(AlertKind::NewApp, "quiet.exe");
        let mut p = AlertPipeline::new(e, RecordingNotifier::default(), VecSink::default());
        let report = p
            .on_connection(&conn("quiet.exe", Direction::Outbound, 1), 1)
            .unwrap();
        assert_eq!(report.raised, 0);
    }
}
