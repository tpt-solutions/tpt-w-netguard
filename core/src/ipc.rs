// SPDX-License-Identifier: MIT OR Apache-2.0
//! IPC boundary: the closed set of commands the UI may send, their validation, and the
//! throttle that keeps high-volume backend events from flooding the frontend.
//!
//! The frontend can only ask for variants listed in [`Command`]. Unknown fields and unknown
//! command names are rejected by serde, and every value is checked by [`validate_command`]
//! before any backend is touched, so the UI cannot inject arbitrary rules or actions.

use std::collections::HashMap;
use std::hash::Hash;

use serde::{Deserialize, Serialize};

use crate::alerts::AlertKind;
use crate::devices::normalize_mac;
use crate::error::{Error, Result};
use crate::policy::validate_rule;
use crate::traits::{AppRule, RuleAction};

/// Longest label a user may give a device.
pub const MAX_LABEL_LEN: usize = 64;
/// Retention window bounds, in days.
pub const RETENTION_DAYS_RANGE: std::ops::RangeInclusive<u32> = 1..=365;
/// Longest DNS upstream specification accepted from the UI.
pub const MAX_UPSTREAM_LEN: usize = 256;
/// Maximum number of upstreams in one resolver configuration.
pub const MAX_UPSTREAMS: usize = 4;

/// Every request the frontend may make of the backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    SetRule {
        id: i64,
        app: String,
        action: RuleAction,
        profile: Option<String>,
    },
    RemoveRule {
        id: i64,
    },
    SetBlockAll {
        enabled: bool,
    },
    DismissAlert {
        id: i64,
    },
    SetAlertMute {
        kind: String,
        subject: String,
        muted: bool,
    },
    LabelDevice {
        mac: String,
        label: Option<String>,
    },
    TrustDevice {
        mac: String,
        trusted: bool,
    },
    SetRetentionDays {
        days: u32,
    },
    SetResolverUpstreams {
        upstreams: Vec<String>,
    },
}

/// Validate a command's values. Returns the first problem found.
pub fn validate_command(cmd: &Command) -> Result<()> {
    match cmd {
        Command::SetRule {
            id,
            app,
            action,
            profile,
        } => {
            if *id < 0 {
                return Err(Error::InvalidInput("rule id must be non-negative".into()));
            }
            validate_rule(&AppRule {
                id: *id,
                app: app.clone(),
                action: *action,
                profile: profile.clone(),
            })
        }
        Command::RemoveRule { id } | Command::DismissAlert { id } => {
            if *id < 0 {
                return Err(Error::InvalidInput("id must be non-negative".into()));
            }
            Ok(())
        }
        Command::SetBlockAll { .. } => Ok(()),
        Command::SetAlertMute { kind, subject, .. } => {
            if AlertKind::parse(kind).is_none() {
                return Err(Error::InvalidInput(format!("unknown alert kind: {kind}")));
            }
            if subject.trim().is_empty()
                || subject.len() > 260
                || subject.contains(char::is_control)
            {
                return Err(Error::InvalidInput("invalid alert subject".into()));
            }
            Ok(())
        }
        Command::LabelDevice { mac, label } => {
            require_mac(mac)?;
            if let Some(label) = label {
                if label.chars().count() > MAX_LABEL_LEN || label.contains(char::is_control) {
                    return Err(Error::InvalidInput(
                        "device label must be at most 64 printable characters".into(),
                    ));
                }
            }
            Ok(())
        }
        Command::TrustDevice { mac, .. } => require_mac(mac).map(|_| ()),
        Command::SetRetentionDays { days } => {
            if RETENTION_DAYS_RANGE.contains(days) {
                Ok(())
            } else {
                Err(Error::InvalidInput(format!(
                    "retention must be {}-{} days",
                    RETENTION_DAYS_RANGE.start(),
                    RETENTION_DAYS_RANGE.end()
                )))
            }
        }
        Command::SetResolverUpstreams { upstreams } => validate_upstreams(upstreams),
    }
}

fn require_mac(mac: &str) -> Result<String> {
    normalize_mac(mac).ok_or_else(|| Error::InvalidInput("invalid MAC address".into()))
}

/// Upstream specs are checked for shape only here; `tpt-netguard-dns` parses them fully.
pub fn validate_upstreams(upstreams: &[String]) -> Result<()> {
    if upstreams.is_empty() || upstreams.len() > MAX_UPSTREAMS {
        return Err(Error::InvalidInput(format!(
            "configure 1-{MAX_UPSTREAMS} resolver upstreams"
        )));
    }
    for up in upstreams {
        let ok_scheme = up.starts_with("https://") || up.starts_with("tls://");
        if !ok_scheme
            || up.len() > MAX_UPSTREAM_LEN
            || up.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(Error::InvalidInput(
                "upstream must be https://... (DoH) or tls://... (DoT) without spaces".into(),
            ));
        }
    }
    Ok(())
}

/// Coalesces high-frequency events per key. An event is emitted at most once per
/// `min_interval_ms` per key; events arriving in between replace each other (latest wins)
/// and are released by [`EventThrottle::flush`].
#[derive(Debug)]
pub struct EventThrottle<K: Hash + Eq + Clone, V> {
    min_interval_ms: u64,
    last_emit: HashMap<K, u64>,
    pending: HashMap<K, V>,
}

impl<K: Hash + Eq + Clone, V> EventThrottle<K, V> {
    pub fn new(min_interval_ms: u64) -> Self {
        Self {
            min_interval_ms,
            last_emit: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Offer an event. Returns it immediately when the key is due, otherwise stores it.
    pub fn push(&mut self, key: K, value: V, now_ms: u64) -> Option<V> {
        if self.is_due(&key, now_ms) {
            self.last_emit.insert(key.clone(), now_ms);
            self.pending.remove(&key);
            Some(value)
        } else {
            self.pending.insert(key, value);
            None
        }
    }

    /// Release pending events whose interval has elapsed.
    pub fn flush(&mut self, now_ms: u64) -> Vec<(K, V)> {
        let due: Vec<K> = self
            .pending
            .keys()
            .filter(|k| self.is_due(k, now_ms))
            .cloned()
            .collect();
        let mut out = Vec::with_capacity(due.len());
        for key in due {
            if let Some(value) = self.pending.remove(&key) {
                self.last_emit.insert(key.clone(), now_ms);
                out.push((key, value));
            }
        }
        out
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    fn is_due(&self, key: &K, now_ms: u64) -> bool {
        match self.last_emit.get(key) {
            None => true,
            Some(last) => now_ms.saturating_sub(*last) >= self.min_interval_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_command_and_rejects_unknown_fields() {
        let ok: Command =
            serde_json::from_str(r#"{"cmd":"set_block_all","enabled":true}"#).unwrap();
        assert_eq!(ok, Command::SetBlockAll { enabled: true });

        let extra =
            serde_json::from_str::<Command>(r#"{"cmd":"set_block_all","enabled":true,"x":1}"#);
        assert!(extra.is_err());
        let unknown = serde_json::from_str::<Command>(r#"{"cmd":"run_shell","enabled":true}"#);
        assert!(unknown.is_err());
    }

    #[test]
    fn rule_commands_are_validated() {
        let bad = Command::SetRule {
            id: 1,
            app: "a\n.exe".into(),
            action: RuleAction::Block,
            profile: None,
        };
        assert!(validate_command(&bad).is_err());
        let neg = Command::RemoveRule { id: -1 };
        assert!(validate_command(&neg).is_err());
    }

    #[test]
    fn mute_requires_known_alert_kind() {
        let ok = Command::SetAlertMute {
            kind: "new_app".into(),
            subject: "a.exe".into(),
            muted: true,
        };
        assert!(validate_command(&ok).is_ok());
        let bad = Command::SetAlertMute {
            kind: "shell".into(),
            subject: "a.exe".into(),
            muted: true,
        };
        assert!(validate_command(&bad).is_err());
    }

    #[test]
    fn device_commands_normalise_and_bound_input() {
        let ok = Command::TrustDevice {
            mac: "AA-BB-CC-DD-EE-FF".into(),
            trusted: true,
        };
        assert!(validate_command(&ok).is_ok());
        let bad_mac = Command::TrustDevice {
            mac: "not-a-mac".into(),
            trusted: true,
        };
        assert!(validate_command(&bad_mac).is_err());
        let long = Command::LabelDevice {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            label: Some("x".repeat(MAX_LABEL_LEN + 1)),
        };
        assert!(validate_command(&long).is_err());
        let ctrl = Command::LabelDevice {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            label: Some("tv\u{7}".into()),
        };
        assert!(validate_command(&ctrl).is_err());
    }

    #[test]
    fn retention_is_bounded() {
        assert!(validate_command(&Command::SetRetentionDays { days: 0 }).is_err());
        assert!(validate_command(&Command::SetRetentionDays { days: 30 }).is_ok());
        assert!(validate_command(&Command::SetRetentionDays { days: 366 }).is_err());
    }

    #[test]
    fn upstreams_must_use_encrypted_schemes() {
        assert!(validate_upstreams(&["https://dns.example/dns-query".into()]).is_ok());
        assert!(validate_upstreams(&["tls://dns.example:853".into()]).is_ok());
        assert!(validate_upstreams(&["udp://8.8.8.8:53".into()]).is_err());
        assert!(validate_upstreams(&["https://a b".into()]).is_err());
        assert!(validate_upstreams(&[]).is_err());
    }

    #[test]
    fn throttle_emits_first_then_coalesces() {
        let mut t: EventThrottle<&str, u32> = EventThrottle::new(100);
        assert_eq!(t.push("bw", 1, 0), Some(1));
        assert_eq!(t.push("bw", 2, 10), None);
        assert_eq!(t.push("bw", 3, 20), None);
        assert_eq!(t.pending_len(), 1);
        // Not yet due.
        assert!(t.flush(50).is_empty());
        // Due: the latest pending value wins.
        assert_eq!(t.flush(100), vec![("bw", 3)]);
        assert_eq!(t.push("bw", 4, 105), None);
    }

    #[test]
    fn throttle_keys_are_independent() {
        let mut t: EventThrottle<&str, u32> = EventThrottle::new(1000);
        assert_eq!(t.push("graph", 1, 0), Some(1));
        assert_eq!(t.push("alerts", 2, 1), Some(2));
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    /// Exactly the JSON the frontend sends (see src/api.ts). Changing a field name breaks the UI.
    #[test]
    fn set_rule_matches_frontend_shape() {
        let json =
            r#"{"cmd":"set_rule","id":3,"app":"C:\\Apps\\a.exe","action":"block","profile":null}"#;
        let cmd: Command = serde_json::from_str(json).unwrap();
        assert_eq!(
            cmd,
            Command::SetRule {
                id: 3,
                app: r"C:\Apps\a.exe".into(),
                action: RuleAction::Block,
                profile: None,
            }
        );
    }

    #[test]
    fn settings_update_matches_frontend_shape() {
        let json = r#"{"retention_days":30,"resolver_upstreams":["https://dns.example/dns-query"],
            "geo_db_path":null,"usage_spike_bytes":1,"sampling_base_ms":1000,"sampling_max_ms":15000,
            "onboarding_done":true,"crash_log_enabled":false}"#;
        let update: crate::settings::SettingsUpdate = serde_json::from_str(json).unwrap();
        assert_eq!(update.geo_license_key, None);
    }
}
