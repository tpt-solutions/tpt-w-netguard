// SPDX-License-Identifier: MIT OR Apache-2.0
//! Application service: the only place UI commands turn into state changes.
//!
//! Every [`Command`] is validated first ([`validate_command`]), then applied to the firewall
//! manager, the history store, or the settings file. Nothing else in the app mutates those
//! stores, so the IPC surface stays the closed set defined in [`crate::ipc`].

use std::path::PathBuf;

use serde::Serialize;

use crate::alerts::AlertKind;
use crate::devices::{normalize_mac, Device, DeviceRegistry};
use crate::error::{Error, Result};
use crate::ipc::{validate_command, Command};
use crate::manager::FirewallManager;
use crate::settings::Settings;
use crate::store::{RetentionPolicy, RollupReport, Store};
use crate::traits::{AppRule, FirewallBackend};

/// Alerts returned to the UI in one snapshot.
pub const SNAPSHOT_ALERT_LIMIT: usize = 200;

/// An alert as the UI shows it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AlertView {
    pub id: i64,
    pub kind: &'static str,
    pub severity: &'static str,
    pub subject: String,
    pub message: String,
    pub ts_ms: u64,
    pub dismissed: bool,
}

/// Settings as the UI may see them. The GeoLite2 key is reported only as "set or not".
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SettingsView {
    pub retention_days: u32,
    pub resolver_upstreams: Vec<String>,
    pub geo_key_set: bool,
    pub geo_db_path: Option<PathBuf>,
    pub usage_spike_bytes: u64,
    pub sampling_base_ms: u64,
    pub sampling_max_ms: u64,
    pub onboarding_done: bool,
    pub crash_log_enabled: bool,
    pub panic_enabled: bool,
}

impl From<&Settings> for SettingsView {
    fn from(s: &Settings) -> Self {
        Self {
            retention_days: s.retention_days,
            resolver_upstreams: s.resolver_upstreams.clone(),
            geo_key_set: s.geo_license_key.is_some(),
            geo_db_path: s.geo_db_path.clone(),
            usage_spike_bytes: s.usage_spike_bytes,
            sampling_base_ms: s.sampling_base_ms,
            sampling_max_ms: s.sampling_max_ms,
            onboarding_done: s.onboarding_done,
            crash_log_enabled: s.crash_log_enabled,
            panic_enabled: s.panic_enabled,
        }
    }
}

/// Everything the UI needs to render, in one serialisable value.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Snapshot {
    pub block_all: bool,
    pub profile: Option<String>,
    pub rules: Vec<AppRule>,
    pub alerts: Vec<AlertView>,
    pub devices: Vec<Device>,
    pub settings: SettingsView,
}

pub struct Service<B: FirewallBackend> {
    firewall: FirewallManager<B>,
    store: Store,
    settings: Settings,
    settings_path: Option<PathBuf>,
    registry: DeviceRegistry,
}

impl<B: FirewallBackend> Service<B> {
    /// `settings_path = None` keeps settings in memory only (tests, headless runs).
    pub fn new(
        firewall: FirewallManager<B>,
        store: Store,
        settings: Settings,
        settings_path: Option<PathBuf>,
    ) -> Result<Self> {
        let registry = DeviceRegistry::from_devices(store.load_devices()?);
        Ok(Self {
            firewall,
            store,
            settings,
            settings_path,
            registry,
        })
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn firewall(&self) -> &FirewallManager<B> {
        &self.firewall
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Validate and apply one UI command.
    pub fn apply(&mut self, cmd: Command) -> Result<()> {
        validate_command(&cmd)?;
        match cmd {
            Command::SetRule {
                id,
                app,
                action,
                profile,
            } => {
                let rule = AppRule {
                    id,
                    app,
                    action,
                    profile,
                };
                self.firewall.upsert_rule(rule.clone())?;
                self.store.upsert_rule(&rule)?;
            }
            Command::RemoveRule { id } => {
                if !self.firewall.remove_rule(id)? {
                    return Err(Error::InvalidInput(format!("no rule with id {id}")));
                }
                self.store.delete_rule(id)?;
            }
            Command::SetBlockAll { enabled } => {
                self.firewall.set_block_all(enabled)?;
                self.settings.panic_enabled = enabled;
                self.persist_settings()?;
            }
            Command::DismissAlert { id } => {
                if !self.store.dismiss_alert(id)? {
                    return Err(Error::InvalidInput(format!("no alert with id {id}")));
                }
            }
            Command::SetAlertMute {
                kind,
                subject,
                muted,
            } => {
                let kind = AlertKind::parse(&kind)
                    .ok_or_else(|| Error::InvalidInput("unknown alert kind".into()))?;
                if muted {
                    self.store.add_mute(kind, &subject)?;
                } else {
                    self.store.remove_mute(kind, &subject)?;
                }
            }
            Command::LabelDevice { mac, label } => {
                let mac = normalize_mac(&mac)
                    .ok_or_else(|| Error::InvalidInput("invalid MAC address".into()))?;
                if !self.registry.set_label(&mac, label) {
                    return Err(Error::InvalidInput("unknown device".into()));
                }
                self.store_device(&mac)?;
            }
            Command::TrustDevice { mac, trusted } => {
                let mac = normalize_mac(&mac)
                    .ok_or_else(|| Error::InvalidInput("invalid MAC address".into()))?;
                if !self.registry.set_trusted(&mac, trusted) {
                    return Err(Error::InvalidInput("unknown device".into()));
                }
                self.store_device(&mac)?;
            }
            Command::SetRetentionDays { days } => {
                let previous = self.settings.retention_days;
                self.settings.retention_days = days;
                if let Err(e) = self.persist_settings() {
                    self.settings.retention_days = previous;
                    return Err(e);
                }
            }
            Command::SetResolverUpstreams { upstreams } => {
                let previous = std::mem::replace(&mut self.settings.resolver_upstreams, upstreams);
                if let Err(e) = self.persist_settings() {
                    self.settings.resolver_upstreams = previous;
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Highest-usage apps in `[from_ms, to_ms]`. Read-only.
    pub fn top_talkers(
        &self,
        from_ms: u64,
        to_ms: u64,
        limit: usize,
    ) -> Result<Vec<crate::store::AppTotals>> {
        if limit == 0 || limit > 500 {
            return Err(Error::InvalidInput("limit must be 1-500".into()));
        }
        self.store.top_talkers(from_ms, to_ms, limit)
    }

    /// Per-app bandwidth series. Read-only.
    pub fn app_history(
        &self,
        app: &str,
        from_ms: u64,
        to_ms: u64,
        granularity: crate::store::Granularity,
    ) -> Result<Vec<crate::store::HistoryPoint>> {
        if app.is_empty() || app.len() > 260 {
            return Err(Error::InvalidInput("invalid app key".into()));
        }
        self.store.history(app, from_ms, to_ms, granularity)
    }

    /// Record that the active network profile changed (home, public, ...).
    pub fn set_network_profile(&mut self, profile: Option<String>) -> Result<()> {
        self.firewall.set_profile(profile)?;
        Ok(())
    }

    /// Apply a settings change from the UI. The change is validated before anything is written.
    pub fn update_settings(&mut self, update: &crate::settings::SettingsUpdate) -> Result<()> {
        let next = update.apply_to(&self.settings);
        self.replace_settings(next)
    }

    /// Replace settings wholesale (used by the settings screen after its own validation).
    pub fn replace_settings(&mut self, settings: Settings) -> Result<()> {
        settings.validate()?;
        let previous = std::mem::replace(&mut self.settings, settings);
        if let Err(e) = self.persist_settings() {
            self.settings = previous;
            return Err(e);
        }
        Ok(())
    }

    /// Roll history up and prune it per the retention setting.
    pub fn run_retention(&mut self, now_ms: u64) -> Result<RollupReport> {
        let days = self.settings.retention_days;
        self.store.rollup(
            now_ms,
            RetentionPolicy {
                daily_days: days,
                log_days: days,
            },
        )
    }

    /// Record a device from a scan (new or refreshed) so it survives restarts.
    pub fn record_device(&mut self, device: &Device) -> Result<()> {
        self.store.upsert_device(device)
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let alerts = self
            .store
            .recent_alerts(SNAPSHOT_ALERT_LIMIT)?
            .into_iter()
            .map(|a| AlertView {
                id: a.id,
                kind: a.alert.kind.as_str(),
                severity: a.alert.severity.as_str(),
                subject: a.alert.subject,
                message: a.alert.message,
                ts_ms: a.alert.ts_ms,
                dismissed: a.dismissed,
            })
            .collect();
        Ok(Snapshot {
            block_all: self.firewall.block_all(),
            profile: self.firewall.profile().map(String::from),
            rules: self.firewall.rules().cloned().collect(),
            alerts,
            devices: self.registry.all().cloned().collect(),
            settings: SettingsView::from(&self.settings),
        })
    }

    fn store_device(&mut self, mac: &str) -> Result<()> {
        let device = self
            .registry
            .get(mac)
            .cloned()
            .ok_or_else(|| Error::InvalidInput("unknown device".into()))?;
        self.store.upsert_device(&device)
    }

    fn persist_settings(&self) -> Result<()> {
        match &self.settings_path {
            Some(path) => self.settings.save(path),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::Severity;
    use crate::mock::MockBackend;
    use crate::traits::RuleAction;

    fn service() -> Service<MockBackend> {
        let firewall = FirewallManager::new(MockBackend::new(), [], false, None).unwrap();
        Service::new(
            firewall,
            Store::open_in_memory().unwrap(),
            Settings::default(),
            None,
        )
        .unwrap()
    }

    fn device(mac: &str) -> Device {
        Device {
            mac: mac.into(),
            ip: None,
            vendor: None,
            label: None,
            first_seen_ms: 1,
            last_seen_ms: 1,
            trusted: false,
        }
    }

    #[test]
    fn set_rule_reaches_firewall_and_store() {
        let mut svc = service();
        svc.apply(Command::SetRule {
            id: 1,
            app: "chrome.exe".into(),
            action: RuleAction::Block,
            profile: None,
        })
        .unwrap();
        assert_eq!(svc.firewall().rules().count(), 1);
        assert!(svc.store().rule(1).unwrap().is_some());
        assert_eq!(svc.snapshot().unwrap().rules.len(), 1);
    }

    #[test]
    fn invalid_command_changes_nothing() {
        let mut svc = service();
        let bad = svc.apply(Command::SetRule {
            id: 1,
            app: "a\n.exe".into(),
            action: RuleAction::Block,
            profile: None,
        });
        assert!(bad.is_err());
        assert_eq!(svc.firewall().rules().count(), 0);
        assert!(svc.store().rule(1).unwrap().is_none());
    }

    #[test]
    fn panic_button_is_persisted_in_settings() {
        let dir = std::env::temp_dir().join(format!("tpt-netguard-svc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("settings.json");
        let firewall = FirewallManager::new(MockBackend::new(), [], false, None).unwrap();
        let mut svc = Service::new(
            firewall,
            Store::open_in_memory().unwrap(),
            Settings::default(),
            Some(path.clone()),
        )
        .unwrap();
        svc.apply(Command::SetBlockAll { enabled: true }).unwrap();
        assert!(svc.snapshot().unwrap().block_all);
        assert!(Settings::load(&path).unwrap().panic_enabled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_out_of_range_is_rejected_and_unchanged() {
        let mut svc = service();
        assert!(svc.apply(Command::SetRetentionDays { days: 0 }).is_err());
        assert_eq!(svc.settings().retention_days, 30);
    }

    #[test]
    fn dismiss_and_mute_round_trip() {
        let mut svc = service();
        assert!(svc.apply(Command::DismissAlert { id: 99 }).is_err());
        svc.apply(Command::SetAlertMute {
            kind: "new_app".into(),
            subject: "quiet.exe".into(),
            muted: true,
        })
        .unwrap();
        assert_eq!(
            svc.store().mutes().unwrap(),
            vec![(AlertKind::NewApp, "quiet.exe".to_string())]
        );
        svc.apply(Command::SetAlertMute {
            kind: "new_app".into(),
            subject: "quiet.exe".into(),
            muted: false,
        })
        .unwrap();
        assert!(svc.store().mutes().unwrap().is_empty());
    }

    #[test]
    fn device_labels_and_trust_are_stored() {
        let mut svc = service();
        svc.record_device(&device("aa:bb:cc:00:00:01")).unwrap();
        // Reload so the registry knows the device, as at startup.
        svc.registry = DeviceRegistry::from_devices(svc.store().load_devices().unwrap());
        svc.apply(Command::LabelDevice {
            mac: "AA-BB-CC-00-00-01".into(),
            label: Some("kitchen tablet".into()),
        })
        .unwrap();
        svc.apply(Command::TrustDevice {
            mac: "aa:bb:cc:00:00:01".into(),
            trusted: true,
        })
        .unwrap();
        let stored = svc.store().load_devices().unwrap();
        assert_eq!(stored[0].label.as_deref(), Some("kitchen tablet"));
        assert!(stored[0].trusted);
        assert!(svc
            .apply(Command::TrustDevice {
                mac: "ff:ff:ff:ff:ff:fe".into(),
                trusted: true,
            })
            .is_err());
    }

    #[test]
    fn snapshot_never_exposes_the_license_key() {
        let firewall = FirewallManager::new(MockBackend::new(), [], false, None).unwrap();
        let settings = Settings {
            geo_license_key: Some("SUPERSECRETKEY1".into()),
            ..Settings::default()
        };
        let svc = Service::new(firewall, Store::open_in_memory().unwrap(), settings, None).unwrap();
        let json = serde_json::to_string(&svc.snapshot().unwrap()).unwrap();
        assert!(!json.contains("SUPERSECRETKEY1"));
        assert!(json.contains("\"geo_key_set\":true"));
    }

    #[test]
    fn alerts_appear_in_snapshot_with_severity() {
        let mut svc = service();
        svc.store
            .insert_alert(&crate::alerts::Alert {
                kind: AlertKind::InboundRemote,
                severity: Severity::Critical,
                subject: "svchost.exe".into(),
                message: "Inbound RDP".into(),
                ts_ms: 5,
            })
            .unwrap();
        let snap = svc.snapshot().unwrap();
        assert_eq!(snap.alerts.len(), 1);
        assert_eq!(snap.alerts[0].severity, "critical");
    }
}
