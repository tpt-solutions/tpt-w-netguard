// SPDX-License-Identifier: MIT OR Apache-2.0
//! OS-level alert notifications: a Windows toast, or a desktop notification on Linux over D-Bus.

use tpt_netguard_core::alerts::{Alert, Severity};
use tpt_netguard_core::error::{Error, Result};
use tpt_netguard_core::notify::Notifier;

/// Only alerts at or above this severity raise an OS notification. Routine events, such as a
/// program's first connection, stay in the in-app Alerts feed so the desktop is not flooded.
pub const OS_NOTIFY_MIN_SEVERITY: Severity = Severity::Warning;

/// Raises a native notification for alerts that are severe enough.
pub struct OsNotifier;

impl Notifier for OsNotifier {
    fn notify(&mut self, alert: &Alert) -> Result<()> {
        if alert.severity < OS_NOTIFY_MIN_SEVERITY {
            return Ok(());
        }
        notify_rust::Notification::new()
            .appname("tpt-netguard")
            .summary("tpt-netguard alert")
            .body(&alert.message)
            .show()
            .map(|_| ())
            .map_err(|e| Error::Backend(format!("OS notification failed: {e}")))
    }
}

/// Sends each alert to the in-app feed and then to the OS. Both are always attempted, so a
/// failing OS notifier cannot stop the UI event; the first error is still reported to the caller.
pub struct AlertNotifier<U: Notifier> {
    pub ui: U,
    pub os: OsNotifier,
}

impl<U: Notifier> Notifier for AlertNotifier<U> {
    fn notify(&mut self, alert: &Alert) -> Result<()> {
        let ui = self.ui.notify(alert);
        let os = self.os.notify(alert);
        ui.and(os)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_netguard_core::alerts::AlertKind;

    struct Recorder(Vec<String>);
    impl Notifier for Recorder {
        fn notify(&mut self, alert: &Alert) -> Result<()> {
            self.0.push(alert.message.clone());
            Ok(())
        }
    }

    fn alert(severity: Severity) -> Alert {
        Alert {
            kind: AlertKind::NewApp,
            severity,
            subject: "x.exe".into(),
            message: "msg".into(),
            ts_ms: 0,
        }
    }

    #[test]
    fn informational_alerts_skip_the_os() {
        assert!(OsNotifier.notify(&alert(Severity::Info)).is_ok());
        assert!(Severity::Info < OS_NOTIFY_MIN_SEVERITY);
        assert!(Severity::Critical >= OS_NOTIFY_MIN_SEVERITY);
    }

    #[test]
    fn ui_receives_every_alert_even_when_it_is_not_severe_enough_for_the_os() {
        let mut n = AlertNotifier {
            ui: Recorder(Vec::new()),
            os: OsNotifier,
        };
        n.notify(&alert(Severity::Info)).unwrap();
        assert_eq!(n.ui.0, vec!["msg".to_string()]);
    }
}
