// SPDX-License-Identifier: MIT OR Apache-2.0
//! SQLite-backed history store.
//!
//! Data flows through three tiers:
//! `samples` (raw, per sampling tick) → `hourly` → `daily`.
//! [`Store::rollup`] moves data down the tiers and prunes anything past the retention window.
//! Queries read all three tiers, which never overlap in time because each rollup moves rows
//! atomically inside one transaction.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crate::alerts::{Alert, AlertKind, Severity};
use crate::devices::Device;
use crate::error::{Error, Result};
use crate::model::{day_bucket, hour_bucket, ByteSample, Totals, DAY_MS, HOUR_MS};
use crate::traits::{AppRule, RuleAction, RulePersistence};

/// Current schema version. Bump and add a `MIGRATIONS` entry for every schema change.
pub const SCHEMA_VERSION: i64 = 2;

/// Ordered schema migrations; index `i` upgrades from version `i` to `i + 1`.
const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE samples (
    app            TEXT    NOT NULL,
    ts_ms          INTEGER NOT NULL,
    bytes_sent     INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL
);
CREATE INDEX samples_ts ON samples (ts_ms);

CREATE TABLE hourly (
    app            TEXT    NOT NULL,
    hour_start_ms  INTEGER NOT NULL,
    bytes_sent     INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL,
    PRIMARY KEY (app, hour_start_ms)
);

CREATE TABLE daily (
    app            TEXT    NOT NULL,
    day_start_ms   INTEGER NOT NULL,
    bytes_sent     INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL,
    PRIMARY KEY (app, day_start_ms)
);

CREATE TABLE connection_log (
    id            INTEGER PRIMARY KEY,
    pid           INTEGER NOT NULL,
    process_name  TEXT    NOT NULL,
    exe_path      TEXT,
    remote        TEXT    NOT NULL,
    protocol      TEXT    NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL
);
CREATE INDEX connection_log_last_seen ON connection_log (last_seen_ms);

CREATE TABLE alert_log (
    id          INTEGER PRIMARY KEY,
    ts_ms       INTEGER NOT NULL,
    kind        TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    subject     TEXT    NOT NULL,
    message     TEXT    NOT NULL,
    muted       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX alert_log_ts ON alert_log (ts_ms);

CREATE TABLE device_log (
    mac        TEXT    PRIMARY KEY,
    vendor     TEXT,
    hostname   TEXT,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms  INTEGER NOT NULL,
    trusted    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE firewall_rules (
    id      INTEGER PRIMARY KEY,
    app     TEXT    NOT NULL,
    action  TEXT    NOT NULL CHECK (action IN ('allow', 'block')),
    profile TEXT
);
"#,
    r#"
ALTER TABLE alert_log ADD COLUMN dismissed INTEGER NOT NULL DEFAULT 0;

CREATE TABLE alert_mutes (
    kind    TEXT NOT NULL,
    subject TEXT NOT NULL,
    PRIMARY KEY (kind, subject)
);
"#,
];

/// How long history is kept. Defaults match GlassWire's ~30-day window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Days of daily aggregates kept.
    pub daily_days: u32,
    /// Days of connection and alert logs kept.
    pub log_days: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            daily_days: 30,
            log_days: 30,
        }
    }
}

/// Counts of rows moved or removed by one [`Store::rollup`] call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RollupReport {
    pub samples_rolled_to_hourly: usize,
    pub hourly_rolled_to_daily: usize,
    pub rows_pruned: usize,
}

/// A row returned by a range query.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AppTotals {
    pub app: String,
    pub totals: Totals,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (or create) a store at `path` and apply pending migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_connection(Connection::open(path)?)
    }

    /// In-memory store, for tests and ephemeral runs.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", true)?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Current schema version stored in the database.
    pub fn schema_version(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    fn migrate(&mut self) -> Result<()> {
        let current = self.schema_version()?;
        if current > SCHEMA_VERSION {
            return Err(Error::Store(format!(
                "database schema v{current} is newer than supported v{SCHEMA_VERSION}"
            )));
        }
        for (idx, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", (idx + 1) as i64)?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Append raw byte samples from one sampling tick.
    pub fn insert_samples(&mut self, samples: &[ByteSample]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO samples (app, ts_ms, bytes_sent, bytes_received)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            for s in samples {
                stmt.execute(params![
                    s.app,
                    s.timestamp_ms as i64,
                    s.bytes_sent as i64,
                    s.bytes_received as i64
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Roll raw samples into hourly buckets, hourly into daily, and prune past retention.
    ///
    /// `now_ms` is the reference time. Samples in the current hour and hourly buckets in the
    /// current day stay at their finer granularity so that live views stay exact.
    pub fn rollup(&mut self, now_ms: u64, retention: RetentionPolicy) -> Result<RollupReport> {
        let current_hour = hour_bucket(now_ms) as i64;
        let current_day = day_bucket(now_ms) as i64;
        let tx = self.conn.transaction()?;
        let samples_rolled_to_hourly = tx.execute(
            "INSERT INTO hourly (app, hour_start_ms, bytes_sent, bytes_received)
             SELECT app, ts_ms - ts_ms % ?1, SUM(bytes_sent), SUM(bytes_received)
             FROM samples WHERE ts_ms < ?2
             GROUP BY app, ts_ms - ts_ms % ?1
             ON CONFLICT (app, hour_start_ms) DO UPDATE SET
                bytes_sent = bytes_sent + excluded.bytes_sent,
                bytes_received = bytes_received + excluded.bytes_received",
            params![HOUR_MS as i64, current_hour],
        )?;
        tx.execute(
            "DELETE FROM samples WHERE ts_ms < ?1",
            params![current_hour],
        )?;

        let hourly_rolled_to_daily = tx.execute(
            "INSERT INTO daily (app, day_start_ms, bytes_sent, bytes_received)
             SELECT app, hour_start_ms - hour_start_ms % ?1, SUM(bytes_sent), SUM(bytes_received)
             FROM hourly WHERE hour_start_ms < ?2
             GROUP BY app, hour_start_ms - hour_start_ms % ?1
             ON CONFLICT (app, day_start_ms) DO UPDATE SET
                bytes_sent = bytes_sent + excluded.bytes_sent,
                bytes_received = bytes_received + excluded.bytes_received",
            params![DAY_MS as i64, current_day],
        )?;
        tx.execute(
            "DELETE FROM hourly WHERE hour_start_ms < ?1",
            params![current_day],
        )?;

        let daily_cutoff = now_ms.saturating_sub(u64::from(retention.daily_days) * DAY_MS) as i64;
        let log_cutoff = now_ms.saturating_sub(u64::from(retention.log_days) * DAY_MS) as i64;
        let mut rows_pruned = tx.execute(
            "DELETE FROM daily WHERE day_start_ms < ?1",
            params![daily_cutoff],
        )?;
        rows_pruned += tx.execute(
            "DELETE FROM connection_log WHERE last_seen_ms < ?1",
            params![log_cutoff],
        )?;
        rows_pruned += tx.execute(
            "DELETE FROM alert_log WHERE ts_ms < ?1",
            params![log_cutoff],
        )?;

        tx.commit()?;
        Ok(RollupReport {
            samples_rolled_to_hourly,
            hourly_rolled_to_daily,
            rows_pruned,
        })
    }

    /// Totals per app over `[from_ms, to_ms]` (inclusive), across all tiers, largest first.
    pub fn top_talkers(&self, from_ms: u64, to_ms: u64, limit: usize) -> Result<Vec<AppTotals>> {
        let (from, to) = range_args(from_ms, to_ms)?;
        let mut stmt = self.conn.prepare(
            "SELECT app, SUM(sent), SUM(recv) FROM (
                SELECT app, bytes_sent AS sent, bytes_received AS recv
                  FROM samples WHERE ts_ms BETWEEN ?1 AND ?2
                UNION ALL
                SELECT app, bytes_sent, bytes_received
                  FROM hourly WHERE hour_start_ms BETWEEN ?1 AND ?2
                UNION ALL
                SELECT app, bytes_sent, bytes_received
                  FROM daily WHERE day_start_ms BETWEEN ?1 AND ?2
             )
             GROUP BY app
             ORDER BY SUM(sent) + SUM(recv) DESC
             LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![from, to, limit as i64], |row| {
            Ok(AppTotals {
                app: row.get(0)?,
                totals: Totals {
                    bytes_sent: row.get::<_, i64>(1)? as u64,
                    bytes_received: row.get::<_, i64>(2)? as u64,
                },
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Totals for one app over `[from_ms, to_ms]` (inclusive).
    pub fn app_totals(&self, app: &str, from_ms: u64, to_ms: u64) -> Result<Totals> {
        Ok(self
            .top_talkers(from_ms, to_ms, usize::MAX)?
            .into_iter()
            .find(|t| t.app == app)
            .map(|t| t.totals)
            .unwrap_or_default())
    }

    /// Insert or replace a firewall rule by id.
    pub fn upsert_rule(&mut self, rule: &AppRule) -> Result<()> {
        self.conn.execute(
            "INSERT INTO firewall_rules (id, app, action, profile) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (id) DO UPDATE SET
                app = excluded.app, action = excluded.action, profile = excluded.profile",
            params![rule.id, rule.app, action_str(rule.action), rule.profile],
        )?;
        Ok(())
    }

    pub fn delete_rule(&mut self, id: i64) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM firewall_rules WHERE id = ?1", params![id])?
            > 0)
    }

    pub fn rule(&self, id: i64) -> Result<Option<AppRule>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, app, action, profile FROM firewall_rules WHERE id = ?1",
                params![id],
                row_to_rule,
            )
            .optional()?)
    }
}

/// Bucket size for [`Store::history`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Granularity {
    Hourly,
    Daily,
}

/// One bucket of a per-app time series.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HistoryPoint {
    pub bucket_start_ms: u64,
    pub totals: Totals,
}

/// An alert as stored, with its row id and user state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAlert {
    pub id: i64,
    pub alert: Alert,
    pub dismissed: bool,
}

impl Store {
    /// Time series for one app over `[from_ms, to_ms]`, across all tiers.
    ///
    /// `Hourly` only has data for hours not yet rolled into daily buckets (the current day
    /// and raw samples); older history is only available at `Daily` granularity.
    pub fn history(
        &self,
        app: &str,
        from_ms: u64,
        to_ms: u64,
        granularity: Granularity,
    ) -> Result<Vec<HistoryPoint>> {
        let (from, to) = range_args(from_ms, to_ms)?;
        let sql = match granularity {
            Granularity::Hourly => {
                "SELECT b, SUM(s), SUM(r) FROM (
                    SELECT ts_ms - ts_ms % ?4 AS b, bytes_sent AS s, bytes_received AS r
                      FROM samples WHERE app = ?1 AND ts_ms BETWEEN ?2 AND ?3
                    UNION ALL
                    SELECT hour_start_ms, bytes_sent, bytes_received
                      FROM hourly WHERE app = ?1 AND hour_start_ms BETWEEN ?2 AND ?3
                 ) GROUP BY b ORDER BY b"
            }
            Granularity::Daily => {
                "SELECT b, SUM(s), SUM(r) FROM (
                    SELECT ts_ms - ts_ms % ?4 AS b, bytes_sent AS s, bytes_received AS r
                      FROM samples WHERE app = ?1 AND ts_ms BETWEEN ?2 AND ?3
                    UNION ALL
                    SELECT hour_start_ms - hour_start_ms % ?4, bytes_sent, bytes_received
                      FROM hourly WHERE app = ?1 AND hour_start_ms BETWEEN ?2 AND ?3
                    UNION ALL
                    SELECT day_start_ms, bytes_sent, bytes_received
                      FROM daily WHERE app = ?1 AND day_start_ms BETWEEN ?2 AND ?3
                 ) GROUP BY b ORDER BY b"
            }
        };
        let bucket = match granularity {
            Granularity::Hourly => HOUR_MS,
            Granularity::Daily => DAY_MS,
        } as i64;
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![app, from, to, bucket], |row| {
            Ok(HistoryPoint {
                bucket_start_ms: row.get::<_, i64>(0)? as u64,
                totals: Totals {
                    bytes_sent: row.get::<_, i64>(1)? as u64,
                    bytes_received: row.get::<_, i64>(2)? as u64,
                },
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Persist an alert. Returns its row id.
    pub fn insert_alert(&mut self, alert: &Alert) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO alert_log (ts_ms, kind, severity, subject, message)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                alert.ts_ms as i64,
                alert.kind.as_str(),
                alert.severity.as_str(),
                alert.subject,
                alert.message
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Most recent alerts first.
    pub fn recent_alerts(&self, limit: usize) -> Result<Vec<StoredAlert>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts_ms, kind, severity, subject, message, dismissed
             FROM alert_log ORDER BY ts_ms DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let kind_s: String = row.get(2)?;
            let sev_s: String = row.get(3)?;
            let kind = AlertKind::parse(&kind_s).ok_or_else(|| bad_value(&kind_s))?;
            let severity = Severity::parse(&sev_s).ok_or_else(|| bad_value(&sev_s))?;
            Ok(StoredAlert {
                id: row.get(0)?,
                alert: Alert {
                    kind,
                    severity,
                    subject: row.get(4)?,
                    message: row.get(5)?,
                    ts_ms: row.get::<_, i64>(1)? as u64,
                },
                dismissed: row.get::<_, i64>(6)? != 0,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn dismiss_alert(&mut self, id: i64) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE alert_log SET dismissed = 1 WHERE id = ?1",
            params![id],
        )? > 0)
    }

    pub fn add_mute(&mut self, kind: AlertKind, subject: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO alert_mutes (kind, subject) VALUES (?1, ?2)",
            params![kind.as_str(), subject],
        )?;
        Ok(())
    }

    pub fn remove_mute(&mut self, kind: AlertKind, subject: &str) -> Result<bool> {
        Ok(self.conn.execute(
            "DELETE FROM alert_mutes WHERE kind = ?1 AND subject = ?2",
            params![kind.as_str(), subject],
        )? > 0)
    }

    pub fn mutes(&self) -> Result<Vec<(AlertKind, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT kind, subject FROM alert_mutes ORDER BY kind, subject")?;
        let rows = stmt.query_map([], |row| {
            let kind_s: String = row.get(0)?;
            let kind = AlertKind::parse(&kind_s).ok_or_else(|| bad_value(&kind_s))?;
            Ok((kind, row.get(1)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Insert or update a device by MAC.
    pub fn upsert_device(&mut self, d: &Device) -> Result<()> {
        self.conn.execute(
            "INSERT INTO device_log (mac, vendor, hostname, first_seen_ms, last_seen_ms, trusted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (mac) DO UPDATE SET
                vendor = excluded.vendor, hostname = excluded.hostname,
                last_seen_ms = excluded.last_seen_ms, trusted = excluded.trusted",
            params![
                d.mac,
                d.vendor,
                d.label,
                d.first_seen_ms as i64,
                d.last_seen_ms as i64,
                d.trusted as i64
            ],
        )?;
        Ok(())
    }

    pub fn load_devices(&self) -> Result<Vec<Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac, vendor, hostname, first_seen_ms, last_seen_ms, trusted
             FROM device_log ORDER BY mac",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Device {
                mac: row.get(0)?,
                ip: None,
                vendor: row.get(1)?,
                label: row.get(2)?,
                first_seen_ms: row.get::<_, i64>(3)? as u64,
                last_seen_ms: row.get::<_, i64>(4)? as u64,
                trusted: row.get::<_, i64>(5)? != 0,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

fn bad_value(value: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        format!("unknown stored value: {value}").into(),
    )
}

impl RulePersistence for Store {
    fn load_rules(&self) -> Result<Vec<AppRule>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, app, action, profile FROM firewall_rules ORDER BY id")?;
        let rows = stmt.query_map([], row_to_rule)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn save_rules(&mut self, rules: &[AppRule]) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM firewall_rules", [])?;
        for rule in rules {
            tx.execute(
                "INSERT INTO firewall_rules (id, app, action, profile) VALUES (?1, ?2, ?3, ?4)",
                params![rule.id, rule.app, action_str(rule.action), rule.profile],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

fn action_str(action: RuleAction) -> &'static str {
    match action {
        RuleAction::Allow => "allow",
        RuleAction::Block => "block",
    }
}

fn row_to_rule(row: &rusqlite::Row<'_>) -> rusqlite::Result<AppRule> {
    let action = match row.get::<_, String>(2)?.as_str() {
        "allow" => RuleAction::Allow,
        _ => RuleAction::Block,
    };
    Ok(AppRule {
        id: row.get(0)?,
        app: row.get(1)?,
        action,
        profile: row.get(3)?,
    })
}

fn range_args(from_ms: u64, to_ms: u64) -> Result<(i64, i64)> {
    if from_ms > to_ms {
        return Err(Error::InvalidInput("from must be <= to".into()));
    }
    Ok((from_ms as i64, to_ms as i64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DAY_MS, HOUR_MS};

    fn s(app: &str, ts: u64, sent: u64, recv: u64) -> ByteSample {
        ByteSample {
            app: app.into(),
            timestamp_ms: ts,
            bytes_sent: sent,
            bytes_received: recv,
        }
    }

    fn totals(sent: u64, recv: u64) -> Totals {
        Totals {
            bytes_sent: sent,
            bytes_received: recv,
        }
    }

    #[test]
    fn migrates_to_current_schema_and_is_idempotent() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        // Re-running migrate on an up-to-date database must be a no-op.
        let mut store = store;
        store.migrate().unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn rollup_preserves_totals_and_moves_tiers() {
        let mut store = Store::open_in_memory().unwrap();
        let day0 = 10 * DAY_MS;
        // Two samples in an old hour of day 10, one in the current hour of day 11.
        store
            .insert_samples(&[
                s("a.exe", day0 + 1, 10, 0),
                s("a.exe", day0 + 2, 5, 5),
                s("a.exe", day0 + DAY_MS + HOUR_MS + 7, 3, 4),
            ])
            .unwrap();
        let now = day0 + DAY_MS + HOUR_MS + 100;

        let before = store.app_totals("a.exe", 0, u64::MAX / 2).unwrap();
        let report = store.rollup(now, RetentionPolicy::default()).unwrap();
        let after = store.app_totals("a.exe", 0, u64::MAX / 2).unwrap();

        assert_eq!(before, after, "rollup must not change totals");
        assert_eq!(before, totals(18, 9));
        assert_eq!(report.samples_rolled_to_hourly, 1);
        assert_eq!(report.hourly_rolled_to_daily, 1);
        // Current-hour sample stays raw.
        let raw: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM samples", [], |r| r.get(0))
            .unwrap();
        assert_eq!(raw, 1);
    }

    #[test]
    fn rollup_is_idempotent_on_repeat_calls() {
        let mut store = Store::open_in_memory().unwrap();
        store.insert_samples(&[s("a.exe", 1, 7, 7)]).unwrap();
        let now = 3 * DAY_MS;
        store.rollup(now, RetentionPolicy::default()).unwrap();
        store.rollup(now, RetentionPolicy::default()).unwrap();
        assert_eq!(
            store.app_totals("a.exe", 0, now).unwrap(),
            totals(7, 7),
            "second rollup must not double count"
        );
    }

    #[test]
    fn retention_prunes_old_daily_rows() {
        let mut store = Store::open_in_memory().unwrap();
        store.insert_samples(&[s("old.exe", 1, 100, 0)]).unwrap();
        let now = 100 * DAY_MS;
        let report = store
            .rollup(
                now,
                RetentionPolicy {
                    daily_days: 30,
                    log_days: 30,
                },
            )
            .unwrap();
        assert_eq!(report.rows_pruned, 1);
        assert_eq!(
            store.app_totals("old.exe", 0, now).unwrap(),
            Totals::default()
        );
    }

    #[test]
    fn top_talkers_orders_by_total_and_respects_range() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert_samples(&[
                s("small.exe", 1_000, 1, 1),
                s("big.exe", 2_000, 50, 50),
                s("big.exe", 999_999_999, 1_000, 1_000),
            ])
            .unwrap();
        let top = store.top_talkers(0, 5_000, 10).unwrap();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].app, "big.exe");
        assert_eq!(top[0].totals, totals(50, 50));
        assert_eq!(top[1].app, "small.exe");
        assert!(store.top_talkers(10, 0, 10).is_err());
    }

    #[test]
    fn rules_round_trip_through_persistence_hook() {
        let mut store = Store::open_in_memory().unwrap();
        let rules = vec![
            AppRule {
                id: 1,
                app: "chrome.exe".into(),
                action: RuleAction::Block,
                profile: Some("public".into()),
            },
            AppRule {
                id: 2,
                app: "ssh".into(),
                action: RuleAction::Allow,
                profile: None,
            },
        ];
        store.save_rules(&rules).unwrap();
        assert_eq!(store.load_rules().unwrap(), rules);

        store.save_rules(&rules[..1]).unwrap();
        assert_eq!(store.load_rules().unwrap(), rules[..1].to_vec());
        assert!(store.delete_rule(1).unwrap());
        assert_eq!(store.rule(1).unwrap(), None);
    }

    #[test]
    fn history_series_buckets_by_granularity() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert_samples(&[
                s("a.exe", HOUR_MS + 1, 1, 1),
                s("a.exe", HOUR_MS + 2, 2, 2),
                s("a.exe", 2 * HOUR_MS + 5, 4, 4),
            ])
            .unwrap();
        let hourly = store
            .history("a.exe", 0, 3 * HOUR_MS, Granularity::Hourly)
            .unwrap();
        assert_eq!(
            hourly,
            vec![
                HistoryPoint {
                    bucket_start_ms: HOUR_MS,
                    totals: totals(3, 3)
                },
                HistoryPoint {
                    bucket_start_ms: 2 * HOUR_MS,
                    totals: totals(4, 4)
                },
            ]
        );
        let daily = store
            .history("a.exe", 0, DAY_MS, Granularity::Daily)
            .unwrap();
        assert_eq!(daily.len(), 1);
        assert_eq!(daily[0].totals, totals(7, 7));
        assert!(store
            .history("other.exe", 0, DAY_MS, Granularity::Daily)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn alerts_persist_dismiss_and_mutes() {
        let mut store = Store::open_in_memory().unwrap();
        let alert = Alert {
            kind: AlertKind::InboundRemote,
            severity: Severity::Critical,
            subject: "svchost.exe".into(),
            message: "RDP".into(),
            ts_ms: 5,
        };
        let id = store.insert_alert(&alert).unwrap();
        let recent = store.recent_alerts(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].alert, alert);
        assert!(!recent[0].dismissed);

        assert!(store.dismiss_alert(id).unwrap());
        assert!(store.recent_alerts(10).unwrap()[0].dismissed);

        store.add_mute(AlertKind::NewApp, "a.exe").unwrap();
        store.add_mute(AlertKind::NewApp, "a.exe").unwrap(); // idempotent
        assert_eq!(
            store.mutes().unwrap(),
            vec![(AlertKind::NewApp, "a.exe".to_string())]
        );
        assert!(store.remove_mute(AlertKind::NewApp, "a.exe").unwrap());
        assert!(store.mutes().unwrap().is_empty());
    }

    #[test]
    fn devices_persist_and_reload() {
        let mut store = Store::open_in_memory().unwrap();
        let dev = Device {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ip: None,
            vendor: Some("Acme".into()),
            label: Some("Printer".into()),
            first_seen_ms: 1,
            last_seen_ms: 9,
            trusted: true,
        };
        store.upsert_device(&dev).unwrap();
        let mut updated = dev.clone();
        updated.last_seen_ms = 20;
        store.upsert_device(&updated).unwrap();
        assert_eq!(store.load_devices().unwrap(), vec![updated]);
    }
}
