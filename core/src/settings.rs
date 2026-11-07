// SPDX-License-Identifier: MIT OR Apache-2.0
//! User settings, persisted as JSON in the app data directory.
//!
//! Settings are validated on load and on save. The GeoLite2 license key is a secret: it is
//! redacted from `Debug` output so it cannot leak into logs or crash reports.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::ipc::{validate_upstreams, RETENTION_DAYS_RANGE};

/// Default resolver upstreams: encrypted DNS over HTTPS.
pub const DEFAULT_UPSTREAMS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query",
];

/// Shortest sampling interval accepted. Below this the sampler would spend most of its time
/// enumerating sockets.
pub const MIN_SAMPLING_MS: u64 = 100;
/// Longest sampling interval accepted (one hour); the unfocused cap is built from the base.
pub const MAX_SAMPLING_MS: u64 = 3_600_000;
/// Longest GeoLite2 database path accepted from the UI.
pub const MAX_GEO_PATH_LEN: usize = 1024;

/// The GeoLite2 database path is written to by the updater and read by the map, and it can be
/// set from the UI. It must therefore be an absolute path to a `.mmdb` file, with no `..`
/// components and no control characters, so a setting can only name the database itself.
pub fn validate_geo_db_path(path: &Path) -> Result<()> {
    let text = path.to_string_lossy();
    if text.len() > MAX_GEO_PATH_LEN || text.chars().any(char::is_control) {
        return Err(Error::InvalidInput(
            "GeoLite2 database path is too long or malformed".into(),
        ));
    }
    if !path.is_absolute() {
        return Err(Error::InvalidInput(
            "GeoLite2 database path must be absolute".into(),
        ));
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(Error::InvalidInput(
            "GeoLite2 database path must not contain '..'".into(),
        ));
    }
    let is_mmdb = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("mmdb"));
    if !is_mmdb {
        return Err(Error::InvalidInput(
            "GeoLite2 database path must end in .mmdb".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Days of history kept before rollups are pruned (GlassWire-style ~30 days).
    pub retention_days: u32,
    /// DNS upstreams for app-scoped lookups, tried in order.
    pub resolver_upstreams: Vec<String>,
    /// MaxMind license key for GeoLite2 downloads. Secret.
    pub geo_license_key: Option<String>,
    /// Location of the GeoLite2-City database. `None` disables the Map tab.
    pub geo_db_path: Option<PathBuf>,
    /// Bytes per sampling window above which a usage-spike alert is raised.
    pub usage_spike_bytes: u64,
    /// Sampling interval while the UI is focused, in milliseconds.
    pub sampling_base_ms: u64,
    /// Longest sampling interval when unfocused, in milliseconds.
    pub sampling_max_ms: u64,
    /// Whether the first-run walkthrough has been completed or dismissed.
    pub onboarding_done: bool,
    /// Opt-in local error log. Never sent anywhere.
    pub crash_log_enabled: bool,
    /// Panic button state, restored at startup.
    pub panic_enabled: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            retention_days: 30,
            resolver_upstreams: DEFAULT_UPSTREAMS.iter().map(|s| s.to_string()).collect(),
            geo_license_key: None,
            geo_db_path: None,
            usage_spike_bytes: 500 * 1024 * 1024,
            sampling_base_ms: 1_000,
            sampling_max_ms: 15_000,
            onboarding_done: false,
            crash_log_enabled: false,
            panic_enabled: false,
        }
    }
}

impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("retention_days", &self.retention_days)
            .field("resolver_upstreams", &self.resolver_upstreams)
            .field(
                "geo_license_key",
                &self.geo_license_key.as_ref().map(|_| "<redacted>"),
            )
            .field("geo_db_path", &self.geo_db_path)
            .field("usage_spike_bytes", &self.usage_spike_bytes)
            .field("sampling_base_ms", &self.sampling_base_ms)
            .field("sampling_max_ms", &self.sampling_max_ms)
            .field("onboarding_done", &self.onboarding_done)
            .field("crash_log_enabled", &self.crash_log_enabled)
            .field("panic_enabled", &self.panic_enabled)
            .finish()
    }
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        if !RETENTION_DAYS_RANGE.contains(&self.retention_days) {
            return Err(Error::InvalidInput("retention_days out of range".into()));
        }
        validate_upstreams(&self.resolver_upstreams)?;
        if let Some(key) = &self.geo_license_key {
            let plausible = (8..=64).contains(&key.len())
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !plausible {
                return Err(Error::InvalidInput("malformed GeoLite2 license key".into()));
            }
        }
        if !(MIN_SAMPLING_MS..=MAX_SAMPLING_MS).contains(&self.sampling_base_ms)
            || self.sampling_max_ms < self.sampling_base_ms
            || self.sampling_max_ms > MAX_SAMPLING_MS
        {
            return Err(Error::InvalidInput(format!(
                "sampling interval must be {MIN_SAMPLING_MS}-{MAX_SAMPLING_MS} ms, with the maximum at least the base"
            )));
        }
        if let Some(path) = &self.geo_db_path {
            validate_geo_db_path(path)?;
        }
        Ok(())
    }

    /// Load settings from `path`. A missing file yields defaults; a corrupt or invalid file is
    /// an error so the user can see it rather than silently losing their configuration.
    pub fn load(path: &Path) -> Result<Self> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(Error::Backend(format!("cannot read settings: {e}"))),
        };
        let settings: Settings = serde_json::from_str(&text)
            .map_err(|e| Error::InvalidInput(format!("settings file is not valid JSON: {e}")))?;
        settings.validate()?;
        Ok(settings)
    }

    /// Validate, then write atomically (temp file + rename) so a crash never leaves a half-written file.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .map_err(|e| Error::Backend(format!("cannot create dir: {e}")))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| Error::Backend(format!("cannot encode settings: {e}")))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|e| Error::Backend(format!("cannot write settings: {e}")))?;
        fs::rename(&tmp, path).map_err(|e| Error::Backend(format!("cannot replace settings: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tpt-netguard-settings-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn defaults_are_valid_and_missing_file_loads_defaults() {
        let path = temp_path("missing.json");
        let _ = fs::remove_file(&path);
        let loaded = Settings::load(&path).unwrap();
        assert_eq!(loaded, Settings::default());
        loaded.validate().unwrap();
    }

    #[test]
    fn round_trips_through_disk() {
        let path = temp_path("roundtrip.json");
        let s = Settings {
            retention_days: 90,
            onboarding_done: true,
            ..Settings::default()
        };
        s.save(&path).unwrap();
        assert_eq!(Settings::load(&path).unwrap(), s);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn corrupt_file_is_an_error_not_silent_defaults() {
        let path = temp_path("corrupt.json");
        fs::write(&path, "{not json").unwrap();
        assert!(Settings::load(&path).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn invalid_values_are_rejected_on_save() {
        let path = temp_path("invalid.json");
        let s = Settings {
            retention_days: 0,
            ..Settings::default()
        };
        assert!(s.save(&path).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn license_key_is_redacted_in_debug_output() {
        let s = Settings {
            geo_license_key: Some("SECRETKEY123456".into()),
            ..Settings::default()
        };
        let dump = format!("{s:?}");
        assert!(!dump.contains("SECRETKEY123456"));
        assert!(dump.contains("<redacted>"));
    }

    #[test]
    fn malformed_license_key_is_rejected() {
        let s = Settings {
            geo_license_key: Some("short".into()),
            ..Settings::default()
        };
        assert!(s.validate().is_err());
    }
}

/// A settings change from the UI. The GeoLite2 key is tri-state so the UI never has to hold it:
/// `None` keeps the stored key, `Some("")` clears it, and `Some(key)` replaces it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct SettingsUpdate {
    pub retention_days: u32,
    pub resolver_upstreams: Vec<String>,
    #[serde(default)]
    pub geo_license_key: Option<String>,
    pub geo_db_path: Option<PathBuf>,
    pub usage_spike_bytes: u64,
    pub sampling_base_ms: u64,
    pub sampling_max_ms: u64,
    pub onboarding_done: bool,
    pub crash_log_enabled: bool,
}

impl SettingsUpdate {
    /// Apply this update on top of `current`, keeping fields the UI does not own (panic state).
    pub fn apply_to(&self, current: &Settings) -> Settings {
        let geo_license_key = match &self.geo_license_key {
            None => current.geo_license_key.clone(),
            Some(k) if k.is_empty() => None,
            Some(k) => Some(k.clone()),
        };
        Settings {
            retention_days: self.retention_days,
            resolver_upstreams: self.resolver_upstreams.clone(),
            geo_license_key,
            geo_db_path: self.geo_db_path.clone(),
            usage_spike_bytes: self.usage_spike_bytes,
            sampling_base_ms: self.sampling_base_ms,
            sampling_max_ms: self.sampling_max_ms,
            onboarding_done: self.onboarding_done,
            crash_log_enabled: self.crash_log_enabled,
            panic_enabled: current.panic_enabled,
        }
    }
}

#[cfg(test)]
mod update_tests {
    use super::*;

    fn update(key: Option<&str>) -> SettingsUpdate {
        SettingsUpdate {
            retention_days: 45,
            resolver_upstreams: vec!["https://dns.example/dns-query".into()],
            geo_license_key: key.map(String::from),
            geo_db_path: None,
            usage_spike_bytes: 1,
            sampling_base_ms: 1000,
            sampling_max_ms: 5000,
            onboarding_done: true,
            crash_log_enabled: false,
        }
    }

    #[test]
    fn missing_key_keeps_stored_key_and_panic_state() {
        let current = Settings {
            geo_license_key: Some("STOREDKEY12345678".into()),
            panic_enabled: true,
            ..Settings::default()
        };
        let next = update(None).apply_to(&current);
        assert_eq!(next.geo_license_key.as_deref(), Some("STOREDKEY12345678"));
        assert!(next.panic_enabled);
        assert_eq!(next.retention_days, 45);
    }

    #[test]
    fn geo_database_path_must_be_an_absolute_mmdb_file() {
        // An absolute path on this platform: "/x/y" on Unix, "C:\x\y" on Windows.
        let abs = |rest: &str| -> String {
            if cfg!(windows) {
                format!("C:\\{}", rest.replace('/', "\\"))
            } else {
                format!("/{rest}")
            }
        };
        let ok = |p: &str| validate_geo_db_path(Path::new(p)).is_ok();
        assert!(ok(&abs("var/lib/tpt/GeoLite2-City.mmdb")));
        assert!(
            ok(&abs("var/lib/tpt/GeoLite2-City.MMDB")),
            "extension is case-insensitive"
        );
        assert!(!ok("GeoLite2-City.mmdb"), "relative paths are refused");
        assert!(
            !ok(&abs("var/lib/../../etc/passwd.mmdb")),
            "parent components are refused"
        );
        assert!(!ok(&abs("etc/passwd")), "only .mmdb files");
        assert!(
            !ok(&abs("tmp/evil\nname.mmdb")),
            "control characters are refused"
        );
        let long = abs(&format!("{}.mmdb", "a".repeat(MAX_GEO_PATH_LEN)));
        assert!(!ok(&long));
    }

    #[test]
    fn settings_validation_rejects_bad_paths_and_sampling_bounds() {
        let root = if cfg!(windows) { "C:\\" } else { "/" };
        let bad_path = Settings {
            geo_db_path: Some(PathBuf::from(format!("{root}etc/shadow"))),
            ..Settings::default()
        };
        assert!(bad_path.validate().is_err());

        let too_fast = Settings {
            sampling_base_ms: MIN_SAMPLING_MS - 1,
            ..Settings::default()
        };
        assert!(too_fast.validate().is_err());

        let too_slow = Settings {
            sampling_max_ms: MAX_SAMPLING_MS + 1,
            ..Settings::default()
        };
        assert!(too_slow.validate().is_err());

        let ok = Settings {
            geo_db_path: Some(PathBuf::from(format!("{root}data/GeoLite2-City.mmdb"))),
            ..Settings::default()
        };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn empty_key_clears_and_new_key_replaces() {
        let current = Settings {
            geo_license_key: Some("STOREDKEY12345678".into()),
            ..Settings::default()
        };
        assert_eq!(update(Some("")).apply_to(&current).geo_license_key, None);
        assert_eq!(
            update(Some("NEWKEY0987654321"))
                .apply_to(&current)
                .geo_license_key
                .as_deref(),
            Some("NEWKEY0987654321")
        );
    }
}
