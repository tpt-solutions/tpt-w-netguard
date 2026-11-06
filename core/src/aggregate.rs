// SPDX-License-Identifier: MIT OR Apache-2.0
//! Per-app rolling totals: session totals for live graphs and hourly buckets for the store.

use std::collections::{BTreeMap, HashMap};

use crate::model::{hour_bucket, ByteSample, Totals};

/// One hourly bucket ready to be flushed into the history store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HourlyRollup {
    pub app: String,
    /// Start of the hour, Unix milliseconds.
    pub hour_start_ms: u64,
    pub totals: Totals,
}

/// Accumulates byte samples into session and hourly totals.
#[derive(Debug, Default)]
pub struct Aggregator {
    session: HashMap<String, Totals>,
    hourly: BTreeMap<(String, u64), Totals>,
}

impl Aggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one sample into the session and hourly totals.
    pub fn record(&mut self, sample: &ByteSample) {
        self.session
            .entry(sample.app.clone())
            .or_default()
            .add(sample.bytes_sent, sample.bytes_received);
        self.hourly
            .entry((sample.app.clone(), hour_bucket(sample.timestamp_ms)))
            .or_default()
            .add(sample.bytes_sent, sample.bytes_received);
    }

    /// Totals since this aggregator was created (the current session).
    pub fn session_total(&self, app: &str) -> Totals {
        self.session.get(app).copied().unwrap_or_default()
    }

    /// Remove and return all pending hourly buckets, ordered by app then hour.
    pub fn drain_hourly(&mut self) -> Vec<HourlyRollup> {
        std::mem::take(&mut self.hourly)
            .into_iter()
            .map(|((app, hour_start_ms), totals)| HourlyRollup {
                app,
                hour_start_ms,
                totals,
            })
            .collect()
    }

    /// Number of hourly buckets waiting to be flushed.
    pub fn pending_hourly(&self) -> usize {
        self.hourly.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::HOUR_MS;

    fn sample(app: &str, ts: u64, sent: u64, recv: u64) -> ByteSample {
        ByteSample {
            app: app.to_string(),
            timestamp_ms: ts,
            bytes_sent: sent,
            bytes_received: recv,
        }
    }

    #[test]
    fn session_totals_accumulate_across_hours() {
        let mut agg = Aggregator::new();
        agg.record(&sample("a.exe", 0, 10, 20));
        agg.record(&sample("a.exe", HOUR_MS + 5, 1, 2));
        assert_eq!(
            agg.session_total("a.exe"),
            Totals {
                bytes_sent: 11,
                bytes_received: 22
            }
        );
        assert_eq!(agg.session_total("missing.exe"), Totals::default());
    }

    #[test]
    fn samples_in_same_hour_share_one_bucket() {
        let mut agg = Aggregator::new();
        agg.record(&sample("a.exe", HOUR_MS + 1, 5, 5));
        agg.record(&sample("a.exe", 2 * HOUR_MS - 1, 5, 5));
        agg.record(&sample("a.exe", 2 * HOUR_MS, 7, 0));

        let rollups = agg.drain_hourly();
        assert_eq!(rollups.len(), 2);
        assert_eq!(rollups[0].hour_start_ms, HOUR_MS);
        assert_eq!(rollups[0].totals.bytes_sent, 10);
        assert_eq!(rollups[1].hour_start_ms, 2 * HOUR_MS);
        assert_eq!(rollups[1].totals.bytes_sent, 7);
    }

    #[test]
    fn drain_clears_hourly_but_keeps_session() {
        let mut agg = Aggregator::new();
        agg.record(&sample("a.exe", 0, 3, 4));
        assert_eq!(agg.pending_hourly(), 1);
        let _ = agg.drain_hourly();
        assert_eq!(agg.pending_hourly(), 0);
        assert_eq!(agg.session_total("a.exe").total(), 7);
    }
}
