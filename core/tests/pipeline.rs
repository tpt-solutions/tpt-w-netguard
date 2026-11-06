// SPDX-License-Identifier: MIT OR Apache-2.0
//! End-to-end pipeline: mocked OS backend → aggregation → history store → rollup → alerts,
//! plus firewall decisions over the same rule set. Runs without any OS network access.

use std::net::SocketAddr;

use tpt_netguard_core::aggregate::Aggregator;
use tpt_netguard_core::alerts::{AlertConfig, AlertEngine, AlertKind, WINDOWS_WATCHED_PORTS};
use tpt_netguard_core::mock::MockBackend;
use tpt_netguard_core::model::{
    ByteSample, Connection, ConnectionState, Direction, Protocol, DAY_MS, HOUR_MS,
};
use tpt_netguard_core::policy::{decide, BlockReason, Decision};
use tpt_netguard_core::store::{Granularity, RetentionPolicy, Store};
use tpt_netguard_core::traits::{
    AppRule, FirewallBackend, RuleAction, RulePersistence, TrafficMonitor,
};
use tpt_netguard_core::{Alert, Totals};

fn rdp_inbound(now: u64) -> Connection {
    Connection {
        pid: 4,
        process_name: "svchost.exe".into(),
        exe_path: None,
        local: "0.0.0.0:3389".parse::<SocketAddr>().unwrap(),
        remote: "203.0.113.50:51000".parse::<SocketAddr>().unwrap(),
        protocol: Protocol::Tcp,
        direction: Direction::Inbound,
        bytes_sent: 0,
        bytes_received: 0,
        state: ConnectionState::Established,
        first_seen_ms: now,
        last_seen_ms: now,
    }
}

fn sample(app: &str, ts: u64, sent: u64, recv: u64) -> ByteSample {
    ByteSample {
        app: app.into(),
        timestamp_ms: ts,
        bytes_sent: sent,
        bytes_received: recv,
    }
}

/// One sampling tick: pull deltas from the backend, feed every consumer, persist.
fn tick(
    mon: &mut MockBackend,
    agg: &mut Aggregator,
    store: &mut Store,
    engine: &mut AlertEngine,
    now: u64,
) -> Vec<Alert> {
    let samples = mon.sample_byte_deltas(now).unwrap();
    let mut alerts = Vec::new();
    for s in &samples {
        agg.record(s);
        let window = s.bytes_sent + s.bytes_received;
        alerts.extend(engine.on_connection_app(&s.app, now));
        alerts.extend(engine.on_usage(&s.app, window, now));
    }
    store.insert_samples(&samples).unwrap();
    for conn in mon.enumerate_connections().unwrap() {
        alerts.extend(engine.on_connection_inbound(&conn, now));
    }
    for alert in &alerts {
        store.insert_alert(alert).unwrap();
    }
    alerts
}

#[test]
fn samples_flow_through_store_rollup_and_alerts() {
    let mut mon = MockBackend::new();
    let mut agg = Aggregator::new();
    let mut store = Store::open_in_memory().unwrap();
    let mut engine = AlertEngine::new(AlertConfig::new(1_000_000, WINDOWS_WATCHED_PORTS));

    let t0 = 10 * DAY_MS + 5;
    mon.pending_samples.push_back(vec![
        sample("chrome.exe", t0, 100_000, 900_000),
        sample("small.exe", t0, 10, 10),
    ]);
    // Second tick: chrome spikes over the 1 MB window threshold.
    mon.pending_samples
        .push_back(vec![sample("chrome.exe", t0 + 60_000, 2_000_000, 0)]);
    mon.connections.push(rdp_inbound(t0));

    let first = tick(&mut mon, &mut agg, &mut store, &mut engine, t0);
    let second = tick(&mut mon, &mut agg, &mut store, &mut engine, t0 + 60_000);

    // New-app alerts for both apps, RDP inbound on the first tick only if connections exist
    // on both ticks (they do, so it fires twice).
    let kinds: Vec<AlertKind> = first.iter().map(|a| a.kind).collect();
    assert_eq!(kinds.iter().filter(|k| **k == AlertKind::NewApp).count(), 2);
    assert!(kinds.contains(&AlertKind::InboundRemote));
    assert!(second
        .iter()
        .any(|a| a.kind == AlertKind::UsageSpike && a.subject == "chrome.exe"));
    assert!(
        second.iter().all(|a| a.kind != AlertKind::NewApp),
        "no repeat new-app alerts"
    );

    // Session totals in the live aggregator match what was stored.
    let session = agg.session_total("chrome.exe");
    assert_eq!(
        session,
        Totals {
            bytes_sent: 2_100_000,
            bytes_received: 900_000
        }
    );

    // Roll up a day later: totals must be unchanged and rows move to daily.
    let now = t0 + DAY_MS + HOUR_MS;
    let before = store.app_totals("chrome.exe", 0, now).unwrap();
    store.rollup(now, RetentionPolicy::default()).unwrap();
    assert_eq!(store.app_totals("chrome.exe", 0, now).unwrap(), before);
    assert_eq!(before, session);

    let top = store.top_talkers(0, now, 10).unwrap();
    assert_eq!(top[0].app, "chrome.exe");
    let daily = store
        .history("chrome.exe", 0, now, Granularity::Daily)
        .unwrap();
    assert_eq!(daily.len(), 1);

    // Alerts persisted; dismissing one keeps it in the log.
    let stored = store.recent_alerts(50).unwrap();
    assert_eq!(stored.len(), first.len() + second.len());
    assert!(store.dismiss_alert(stored[0].id).unwrap());
    assert!(store.recent_alerts(50).unwrap().iter().any(|a| a.dismissed));
}

#[test]
fn muted_app_stays_quiet_across_ticks() {
    let mut mon = MockBackend::new();
    let mut agg = Aggregator::new();
    let mut store = Store::open_in_memory().unwrap();
    let mut engine = AlertEngine::new(AlertConfig::new(u64::MAX, WINDOWS_WATCHED_PORTS));
    engine.mute(AlertKind::NewApp, "noisy.exe");

    mon.pending_samples
        .push_back(vec![sample("noisy.exe", 1, 1, 1)]);
    let alerts = tick(&mut mon, &mut agg, &mut store, &mut engine, 1);
    assert!(alerts.is_empty());
}

#[test]
fn firewall_rules_drive_decisions_and_survive_restart() {
    let mut fw = MockBackend::new();
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
            app: "chrome.exe".into(),
            action: RuleAction::Allow,
            profile: Some("home".into()),
        },
    ];
    for rule in &rules {
        fw.apply_rule(rule).unwrap();
    }
    store.save_rules(&fw.list_rules().unwrap()).unwrap();

    // Simulate a restart: a fresh backend is rebuilt from the persisted rules.
    let mut restarted = MockBackend::new();
    for rule in store.load_rules().unwrap() {
        restarted.apply_rule(&rule).unwrap();
    }
    let active = restarted.list_rules().unwrap();
    assert_eq!(active.len(), 2);

    assert_eq!(
        decide(&active, "chrome.exe", Some("public"), false),
        Decision::Block {
            reason: BlockReason::AppRule(1)
        }
    );
    assert_eq!(
        decide(&active, "chrome.exe", Some("home"), false),
        Decision::Allow { rule_id: Some(2) }
    );

    // Panic button overrides the home-network allow.
    restarted.set_block_all(true).unwrap();
    assert!(restarted.block_all_enabled().unwrap());
    assert_eq!(
        decide(
            &active,
            "chrome.exe",
            Some("home"),
            restarted.block_all_enabled().unwrap()
        ),
        Decision::Block {
            reason: BlockReason::PanicButton
        }
    );
}
