// SPDX-License-Identifier: MIT OR Apache-2.0
//! Opt-in local error log. Disabled by default, never uploaded, bounded in size, and redacted.
//!
//! When disabled, [`CrashLog::record`] does nothing and touches no file. When enabled, entries
//! are appended to a single file that is rotated to `<name>.1` once it exceeds the size cap.
//! Any registered secret (for example the GeoLite2 license key) is replaced before writing.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};

/// Rotate once the active log reaches this many bytes.
pub const MAX_LOG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

#[derive(Debug)]
pub struct CrashLog {
    path: PathBuf,
    enabled: bool,
    secrets: Vec<String>,
}

impl CrashLog {
    pub fn new(path: impl Into<PathBuf>, enabled: bool) -> Self {
        Self {
            path: path.into(),
            enabled,
            secrets: Vec::new(),
        }
    }

    /// Register a value that must never reach the log. Empty values are ignored.
    pub fn redact(&mut self, secret: impl Into<String>) {
        let secret = secret.into();
        if !secret.is_empty() {
            self.secrets.push(secret);
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one entry. A no-op when logging is disabled.
    pub fn record(&self, level: Level, message: &str) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let line = format!("{} {} {}\n", unix_ms(), level.as_str(), self.scrub(message));
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(|e| Error::Backend(format!("log dir: {e}")))?;
        }
        if fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0) >= MAX_LOG_BYTES {
            let rotated = self.path.with_extension("log.1");
            let _ = fs::remove_file(&rotated);
            fs::rename(&self.path, &rotated).map_err(|e| Error::Backend(format!("rotate: {e}")))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| Error::Backend(format!("open log: {e}")))?;
        file.write_all(line.as_bytes())
            .map_err(|e| Error::Backend(format!("write log: {e}")))
    }

    /// Replace registered secrets. Public so callers can scrub text before showing it too.
    pub fn scrub(&self, text: &str) -> String {
        let mut out = text.replace(['\n', '\r'], " ");
        for secret in &self.secrets {
            out = out.replace(secret.as_str(), "<redacted>");
        }
        out
    }
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("tpt-netguard-log-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn disabled_log_writes_nothing() {
        let d = dir("disabled");
        let log = CrashLog::new(d.join("app.log"), false);
        log.record(Level::Error, "boom").unwrap();
        assert!(!d.join("app.log").exists());
    }

    #[test]
    fn enabled_log_appends_and_redacts_secrets() {
        let d = dir("enabled");
        let mut log = CrashLog::new(d.join("app.log"), true);
        log.redact("LICENSEKEY_123456");
        log.record(Level::Warn, "download with key LICENSEKEY_123456\nfailed")
            .unwrap();
        let text = fs::read_to_string(d.join("app.log")).unwrap();
        assert!(text.contains("WARN download with key <redacted> failed"));
        assert!(!text.contains("LICENSEKEY"));
        assert_eq!(text.lines().count(), 1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn log_rotates_when_over_cap() {
        let d = dir("rotate");
        fs::create_dir_all(&d).unwrap();
        let path = d.join("app.log");
        fs::write(&path, vec![b'x'; MAX_LOG_BYTES as usize]).unwrap();
        let log = CrashLog::new(&path, true);
        log.record(Level::Info, "after rotation").unwrap();
        assert!(d.join("app.log.1").exists());
        let active = fs::read_to_string(&path).unwrap();
        assert!(active.contains("after rotation"));
        let _ = fs::remove_dir_all(&d);
    }
}
