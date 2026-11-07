// SPDX-License-Identifier: MIT OR Apache-2.0
//! Background loop: samples per-app bytes, feeds the alert pipeline, records history, scans the
//! LAN, and pushes throttled events to the UI. It owns its own history-store connection, so it
//! never blocks UI commands on the service lock.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::names::NameService;
use crate::os_notify::{AlertNotifier, OsNotifier};
use serde_json::json;
use tauri::{AppHandle, Emitter};
use tpt_netguard_core::alerts::{Alert, AlertConfig, AlertEngine, WatchedPort};
use tpt_netguard_core::crashlog::{CrashLog, Level};
use tpt_netguard_core::devices::{DeviceRegistry, OuiTable};
use tpt_netguard_core::error::{Error, Result};
use tpt_netguard_core::ipc::EventThrottle;
use tpt_netguard_core::model::{ByteSample, Connection};
use tpt_netguard_core::notify::{AlertPipeline, Notifier};
use tpt_netguard_core::scheduler::SamplingScheduler;
use tpt_netguard_core::settings::Settings;
use tpt_netguard_core::store::{RetentionPolicy, Store};
use tpt_netguard_core::traits::TrafficMonitor;
use tpt_netguard_discovery::{LanScanner, NetworkNameResolver};
use tpt_netguard_geoip::update::{self, validate_iplocate_asn, EDITION_CITY};
use tpt_netguard_geoip::{asn_path_in, IPLOCATE_ASN_URL};
use tpt_netguard_geoip::HttpFetcher;

/// How often the LAN is scanned.
const LAN_SCAN_EVERY: Duration = Duration::from_secs(10 * 60);
/// How often old history is rolled up and pruned.
const RETENTION_EVERY: Duration = Duration::from_secs(60 * 60);
/// Minimum gap between bandwidth events sent to the UI.
const BANDWIDTH_EVENT_MS: u64 = 500;
/// How often the GeoLite2 freshness check runs. Refresh itself happens only when due.
const GEO_CHECK_EVERY: Duration = Duration::from_secs(6 * 60 * 60);
/// Connections are re-enumerated for the map every this many ticks.
const CONNECTION_REFRESH_TICKS: u64 = 10;

/// Pushes alerts to the UI as "alert" events. The alert log is written by the pipeline first.
pub struct EventNotifier(pub AppHandle);

impl Notifier for EventNotifier {
    fn notify(&mut self, alert: &Alert) -> Result<()> {
        // The pipeline persisted the alert before calling us, so the tray's query sees it.
        crate::refresh_tray(&self.0);
        self.0
            .emit(
                "alert",
                json!({
                    "kind": alert.kind.as_str(),
                    "severity": alert.severity.as_str(),
                    "subject": alert.subject,
                    "message": alert.message,
                    "ts_ms": alert.ts_ms,
                }),
            )
            .map_err(|e| Error::Backend(e.to_string()))
    }
}

/// The platform traffic monitor, with its concrete type kept so status can be reported.
pub enum Monitor {
    #[cfg(windows)]
    Windows(tpt_netguard_platform_windows::IpHelperMonitor),
    #[cfg(target_os = "linux")]
    Linux(tpt_netguard_platform_linux::LinuxMonitor),
}

impl Monitor {
    pub fn for_this_platform() -> Option<Self> {
        #[cfg(windows)]
        return Some(Monitor::Windows(
            tpt_netguard_platform_windows::IpHelperMonitor::new(),
        ));
        #[cfg(target_os = "linux")]
        return Some(Monitor::Linux(
            tpt_netguard_platform_linux::LinuxMonitor::new(),
        ));
        #[allow(unreachable_code)]
        None
    }

    pub fn watched_ports(&self) -> &'static [WatchedPort] {
        match self {
            #[cfg(windows)]
            Monitor::Windows(_) => tpt_netguard_core::alerts::WINDOWS_WATCHED_PORTS,
            #[cfg(target_os = "linux")]
            Monitor::Linux(_) => tpt_netguard_core::alerts::LINUX_WATCHED_PORTS,
        }
    }

    fn as_dyn(&mut self) -> &mut dyn TrafficMonitor {
        match self {
            #[cfg(windows)]
            Monitor::Windows(m) => m,
            #[cfg(target_os = "linux")]
            Monitor::Linux(m) => m,
        }
    }

    /// Plain-language bandwidth status for the UI.
    pub fn bandwidth_status(&self) -> String {
        match self {
            #[cfg(windows)]
            Monitor::Windows(m) => match m.bandwidth_source() {
                tpt_netguard_platform_windows::BandwidthSource::EStats => "available".to_string(),
                tpt_netguard_platform_windows::BandwidthSource::Unavailable => {
                    "unavailable: run as administrator to read per-connection byte counters"
                        .to_string()
                }
            },
            #[cfg(target_os = "linux")]
            Monitor::Linux(m) => m.bandwidth_status(),
        }
    }
}

/// Append an error to the opt-in local log. Nothing is written unless the user enabled it, and
/// the GeoLite2 key is redacted from every line.
pub fn log_error(dir: &Path, message: &str) {
    let settings = Settings::load(&dir.join("settings.json")).unwrap_or_default();
    let mut log = CrashLog::new(dir.join("tpt-netguard.log"), settings.crash_log_enabled);
    if let Some(key) = &settings.geo_license_key {
        log.redact(key.clone());
    }
    let _ = log.record(Level::Error, message);
}

/// Refresh the databases that are due. The ASN database (IPLocate) needs no key and is always
/// kept current. The GeoLite2-City database is optional: it is downloaded only when a MaxMind
/// key and a file path are set. Failures keep the last good copy.
fn refresh_geo(dir: &Path) {
    refresh_asn(dir);
    let settings = Settings::load(&dir.join("settings.json")).unwrap_or_default();
    if let (Some(key), Some(path)) = (
        settings.geo_license_key.clone(),
        settings.geo_db_path.clone(),
    ) {
        refresh_city(dir, &key, &path);
    }
}

fn refresh_asn(dir: &Path) {
    let dest = asn_path_in(dir);
    if !update::is_due(update::file_age(&dest, SystemTime::now())) {
        return;
    }
    let fetcher = HttpFetcher::new(Duration::from_secs(300));
    match update::update_raw_database(&fetcher, IPLOCATE_ASN_URL, &dest, validate_iplocate_asn) {
        Ok(done) => log_error(dir, &format!("ASN database refreshed ({} bytes)", done.bytes)),
        Err(e) => log_error(dir, &format!("ASN database refresh failed: {e}")),
    }
}

fn refresh_city(dir: &Path, key: &str, path: &Path) {
    let age = update::file_age(path, SystemTime::now());
    if !update::is_due(age) {
        return;
    }
    let fetcher = HttpFetcher::new(Duration::from_secs(120));
    let edition = EDITION_CITY;
    match update::update_database(&fetcher, edition, key, path, update::validator_for(edition)) {
        Ok(done) => log_error(dir, &format!("{edition} refreshed ({} bytes)", done.bytes)),
        Err(e) => log_error(dir, &format!("{edition} refresh failed: {e}")),
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Local IPv4 address of the default route. Connecting a UDP socket sends nothing.
fn local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

/// Shared handles the sampler publishes into and the UI reads from.
pub struct Published {
    pub connections: Arc<Mutex<Vec<Connection>>>,
    pub bandwidth: Arc<Mutex<String>>,
    pub scheduler: Arc<Mutex<SamplingScheduler>>,
    pub names: Arc<NameService>,
}

pub fn spawn(app: AppHandle, dir: PathBuf, published: Published) {
    // If the thread cannot start, the app still runs without live data; the UI shows "starting".
    let _ = std::thread::Builder::new()
        .name("sampler".into())
        .spawn(move || {
            if let Err(e) = run(&app, &dir, &published) {
                log_error(&dir, &format!("monitoring stopped: {e}"));
                let _ = app.emit(
                    "notice",
                    json!({ "message": format!("monitoring stopped: {e}") }),
                );
            }
        });
}

fn run(app: &AppHandle, dir: &Path, published: &Published) -> std::result::Result<(), String> {
    let Some(mut monitor) = Monitor::for_this_platform() else {
        *published.bandwidth.lock().map_err(|_| "lock poisoned")? =
            "unavailable: no traffic monitor for this platform".into();
        return Ok(());
    };
    *published.bandwidth.lock().map_err(|_| "lock poisoned")? = monitor.bandwidth_status();

    let (tx, rx) = mpsc::channel::<Connection>();
    monitor
        .as_dyn()
        .subscribe_new_connections(Box::new(move |c: &Connection| {
            let _ = tx.send(c.clone());
        }))
        .map_err(|e| e.to_string())?;

    let store = Store::open(dir.join("history.sqlite")).map_err(|e| e.to_string())?;
    let settings = Settings::load(&dir.join("settings.json")).unwrap_or_default();
    let engine = AlertEngine::new(AlertConfig::new(
        settings.usage_spike_bytes,
        monitor.watched_ports(),
    ));
    let notifier = AlertNotifier {
        ui: EventNotifier(app.clone()),
        os: OsNotifier,
    };
    let mut pipeline = AlertPipeline::new(engine, notifier, store);

    let devices = pipeline.sink().load_devices().map_err(|e| e.to_string())?;
    let mut scanner = LanScanner::new(DeviceRegistry::from_devices(devices), OuiTable::default());
    let names = NetworkNameResolver::default();

    let mut throttle: EventThrottle<&'static str, Vec<ByteSample>> =
        EventThrottle::new(BANDWIDTH_EVENT_MS);
    let mut tick: u64 = 0;
    let mut last_retention = Instant::now() - RETENTION_EVERY;
    let mut last_scan = Instant::now() - LAN_SCAN_EVERY;
    let mut last_geo = Instant::now() - GEO_CHECK_EVERY;

    loop {
        let now = now_ms();

        for conn in rx.try_iter() {
            if let Err(e) = pipeline.on_connection(&conn, now) {
                log_error(dir, &format!("alert pipeline: {e}"));
            }
        }

        match monitor.as_dyn().sample_byte_deltas(now) {
            Ok(samples) if !samples.is_empty() => {
                if let Err(e) = pipeline.sink_mut().insert_samples(&samples) {
                    log_error(dir, &format!("history write failed: {e}"));
                }
                pipeline.on_samples(&samples);
                if let Err(e) = pipeline.on_window_end(now) {
                    log_error(dir, &format!("alert pipeline: {e}"));
                }
                if let Some(batch) = throttle.push("bandwidth", samples, now) {
                    let _ = app.emit("bandwidth", batch);
                }
            }
            Ok(_) => {}
            Err(e) => log_error(dir, &format!("sampling failed: {e}")),
        }
        for (_, batch) in throttle.flush(now) {
            let _ = app.emit("bandwidth", batch);
        }

        if tick % CONNECTION_REFRESH_TICKS == 0 {
            if let Ok(conns) = monitor.as_dyn().enumerate_connections() {
                // Names come from the configured encrypted resolver, so the list is only queued
                // for lookup, never held up waiting for one.
                let upstreams = Settings::load(&dir.join("settings.json"))
                    .map(|s| s.resolver_upstreams)
                    .unwrap_or_else(|_| Settings::default().resolver_upstreams);
                published.names.set_upstreams(&upstreams);
                published.names.enqueue(
                    conns
                        .iter()
                        .map(|c| c.remote.ip())
                        .filter(|ip| crate::is_routable(*ip)),
                );
                if let Ok(mut slot) = published.connections.lock() {
                    *slot = conns;
                }
            }
        }
        if let Ok(mut status) = published.bandwidth.lock() {
            *status = monitor.bandwidth_status();
        }

        if last_retention.elapsed() >= RETENTION_EVERY {
            let days = Settings::load(&dir.join("settings.json"))
                .map(|s| s.retention_days)
                .unwrap_or(30);
            let policy = RetentionPolicy {
                daily_days: days,
                log_days: days,
            };
            if let Err(e) = pipeline.sink_mut().rollup(now, policy) {
                log_error(dir, &format!("retention failed: {e}"));
            }
            last_retention = Instant::now();
        }

        if last_geo.elapsed() >= GEO_CHECK_EVERY {
            refresh_geo(dir);
            last_geo = Instant::now();
        }

        if last_scan.elapsed() >= LAN_SCAN_EVERY {
            if let Some(local) = local_ipv4() {
                match scanner.scan(local, 24, now, &names) {
                    Ok(report) => {
                        for mac in &report.new_macs {
                            if let Some(device) = scanner.registry().get(mac).cloned() {
                                let _ = pipeline.sink_mut().upsert_device(&device);
                            }
                        }
                        for mac in &report.alert_macs {
                            let label = scanner
                                .registry()
                                .get(mac)
                                .map(|d| d.display_label().to_string())
                                .unwrap_or_else(|| mac.clone());
                            if let Err(e) = pipeline.on_new_device(mac, &label, now) {
                                log_error(dir, &format!("alert pipeline: {e}"));
                            }
                        }
                    }
                    Err(e) => log_error(dir, &format!("LAN scan failed: {e}")),
                }
            }
            last_scan = Instant::now();
        }

        let wait = published
            .scheduler
            .lock()
            .map(|s| s.next_interval())
            .unwrap_or(Duration::from_secs(1));
        std::thread::sleep(wait);
        tick += 1;
    }
}
