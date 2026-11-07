// SPDX-License-Identifier: MIT OR Apache-2.0
//! tpt-netguard desktop shell.
//!
//! The UI talks to the backend through a small set of Tauri commands. Every state-changing
//! request is a [`Command`] from `tpt-netguard-core`, validated before it reaches the firewall or
//! the history store.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod fallback;
mod names;
mod os_notify;
mod sampler;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use names::NameService;
use serde::Serialize;
use std::time::SystemTime;
use tauri::menu::{IsMenuItem, Menu, MenuItem, Submenu};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager, State, WindowEvent};
use tpt_netguard_core::alerts::Alert;
use tpt_netguard_core::error::Error;
use tpt_netguard_core::ipc::Command;
use tpt_netguard_core::manager::FirewallManager;
use tpt_netguard_core::model::Connection;
use tpt_netguard_core::scheduler::SamplingScheduler;
use tpt_netguard_core::service::{Service, Snapshot};
use tpt_netguard_core::settings::{Settings, SettingsUpdate};
use tpt_netguard_core::store::Store;
use tpt_netguard_core::traits::{FirewallBackend, RulePersistence};

use tpt_netguard_geoip::{
    aggregate_map, asn_path_beside, owner_label, AsnDb, GeoIp, MapCell, MapPoint,
};

use fallback::Unenforced;
use sampler::Published;

/// Default sampling intervals (focused / unfocused cap), in milliseconds.
const SAMPLE_BASE_MS: u64 = 1_000;
const SAMPLE_MAX_MS: u64 = 15_000;

/// What the UI is told about enforcement at startup and after changes.
#[derive(Debug, Clone, Serialize)]
pub struct EnforcementView {
    pub active: bool,
    pub mechanism: String,
    pub reason: Option<String>,
    pub bandwidth: String,
}

pub struct AppState {
    pub service: Mutex<Service<Box<dyn FirewallBackend>>>,
    pub enforcement: Mutex<EnforcementView>,
    pub published: Published,
    geo: Mutex<Option<(PathBuf, GeoIp)>>,
    asn: Mutex<Option<AsnCache>>,
}

/// The ASN database, reloaded when its file changes (a refresh replaces it).
struct AsnCache {
    path: PathBuf,
    modified: Option<SystemTime>,
    db: Option<AsnDb>,
}

#[derive(Debug, Serialize)]
pub struct MapCellView {
    pub country: Option<String>,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub connections: usize,
    pub bytes: u64,
    pub owner: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MapView {
    pub available: bool,
    pub reason: Option<String>,
    pub cells: Vec<MapCellView>,
}

fn lock_err<T>(_: std::sync::PoisonError<T>) -> String {
    "internal state is unavailable; restart tpt-netguard".to_string()
}

fn to_string(e: Error) -> String {
    e.to_string()
}

/// Open the platform firewall. Never fails: when enforcement is impossible, the app falls back
/// to monitor-only mode and the returned view says why.
fn open_firewall() -> (Box<dyn FirewallBackend>, EnforcementView) {
    #[cfg(windows)]
    {
        match tpt_netguard_platform_windows::WfpEnforcer::open() {
            Ok(enforcer) => (
                Box::new(enforcer),
                EnforcementView {
                    active: true,
                    mechanism: "Windows Filtering Platform (application layer)".into(),
                    reason: None,
                    bandwidth: String::new(),
                },
            ),
            Err(e) => unenforced(e.to_string()),
        }
    }
    #[cfg(target_os = "linux")]
    {
        let caps = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| tpt_netguard_platform_linux::caps::effective_caps(&s))
            .map(tpt_netguard_platform_linux::caps::assess);
        match caps {
            Some(c) if c.nftables => {
                let firewall = tpt_netguard_platform_linux::LinuxFirewall::open();
                let view = EnforcementView {
                    active: true,
                    mechanism: firewall.mechanism(),
                    // Per-app rules report their own reason when they are unavailable, so the
                    // panic button is still shown as enforced.
                    reason: firewall.ebpf_unavailable().map(str::to_owned),
                    bandwidth: String::new(),
                };
                (Box::new(firewall), view)
            }
            _ => unenforced("needs CAP_NET_ADMIN: run as root or grant the capability".into()),
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        unenforced("no firewall backend for this platform".into())
    }
}

fn unenforced(reason: String) -> (Box<dyn FirewallBackend>, EnforcementView) {
    (
        Box::new(Unenforced {
            reason: reason.clone(),
        }),
        EnforcementView {
            active: false,
            mechanism: "none (monitor only)".into(),
            reason: Some(reason),
            bandwidth: String::new(),
        },
    )
}

/// Build everything the UI needs. Problems that do not stop the app are reported through the
/// enforcement view rather than failing startup.
fn build_state(dir: &Path) -> std::result::Result<AppState, String> {
    let settings_path = dir.join("settings.json");
    let (settings, settings_problem) = match Settings::load(&settings_path) {
        Ok(s) => (s, None),
        Err(e) => (
            Settings::default(),
            Some(format!("settings unreadable, defaults in use: {e}")),
        ),
    };

    let store = Store::open(dir.join("history.sqlite")).map_err(to_string)?;
    let rules = store.load_rules().map_err(to_string)?;

    let (backend, mut enforcement) = open_firewall();
    let manager = match FirewallManager::new(backend, rules.clone(), settings.panic_enabled, None) {
        Ok(m) => m,
        Err(e) => {
            enforcement.active = false;
            enforcement.reason = Some(format!("stored rules could not be enforced: {e}"));
            FirewallManager::new(
                Box::new(Unenforced {
                    reason: e.to_string(),
                }) as Box<dyn FirewallBackend>,
                Vec::new(),
                false,
                None,
            )
            .map_err(to_string)?
        }
    };
    if let Some(problem) = settings_problem {
        enforcement.reason.get_or_insert(problem);
    }

    let service = Service::new(manager, store, settings, Some(settings_path)).map_err(to_string)?;
    let scheduler = Arc::new(Mutex::new(
        SamplingScheduler::new(
            std::time::Duration::from_millis(SAMPLE_BASE_MS),
            std::time::Duration::from_millis(SAMPLE_MAX_MS),
        )
        .map_err(to_string)?,
    ));
    let published = Published {
        connections: Arc::new(Mutex::new(Vec::new())),
        bandwidth: Arc::new(Mutex::new(String::from("starting"))),
        scheduler: Arc::clone(&scheduler),
        names: NameService::start(),
    };
    Ok(AppState {
        service: Mutex::new(service),
        enforcement: Mutex::new(enforcement),
        published,
        geo: Mutex::new(None),
        asn: Mutex::new(None),
    })
}

#[tauri::command]
fn snapshot(state: State<'_, AppState>) -> std::result::Result<Snapshot, String> {
    let svc = state.service.lock().map_err(lock_err)?;
    svc.snapshot().map_err(to_string)
}

/// The closed set of changes the UI may request. See `tpt_netguard_core::ipc`.
#[tauri::command]
fn command(
    request: Command,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    let result = {
        let mut svc = state.service.lock().map_err(lock_err)?;
        svc.apply(request).map_err(to_string)
    };
    // Dismissing or muting an alert changes the tray's recent list. The service lock is released
    // above, because the refresh takes it again.
    refresh_tray(&app);
    result
}

#[tauri::command]
fn enforcement(state: State<'_, AppState>) -> std::result::Result<EnforcementView, String> {
    let mut view = state.enforcement.lock().map_err(lock_err)?.clone();
    view.bandwidth = state.published.bandwidth.lock().map_err(lock_err)?.clone();
    Ok(view)
}

/// A connection as the UI sees it: the model's fields, plus the remote name when one is known.
#[derive(Debug, Serialize)]
struct ConnectionView {
    #[serde(flatten)]
    connection: Connection,
    remote_name: Option<String>,
    /// Owner of the remote address, such as `AS15169 Google LLC`, from GeoLite2-ASN.
    remote_org: Option<String>,
}

#[tauri::command]
fn connections(state: State<'_, AppState>) -> std::result::Result<Vec<ConnectionView>, String> {
    let conns = state
        .published
        .connections
        .lock()
        .map_err(lock_err)?
        .clone();
    let ips: Vec<std::net::IpAddr> = conns.iter().map(|c| c.remote.ip()).collect();
    let owners = owner_labels(&state, &ips)?;
    Ok(conns
        .into_iter()
        .zip(owners)
        .map(|(connection, remote_org)| {
            let remote_name = state.published.names.name(connection.remote.ip());
            ConnectionView {
                connection,
                remote_name,
                remote_org,
            }
        })
        .collect())
}

/// Owner labels for remote addresses, from GeoLite2-ASN beside the City database. All `None`
/// when no City database is configured or the ASN file is absent or unreadable.
fn owner_labels(
    state: &AppState,
    ips: &[std::net::IpAddr],
) -> std::result::Result<Vec<Option<String>>, String> {
    let city_path = {
        let svc = state.service.lock().map_err(lock_err)?;
        svc.settings().geo_db_path.clone()
    };
    let none = || vec![None; ips.len()];
    let Some(asn_path) = city_path.as_deref().and_then(asn_path_beside) else {
        return Ok(none());
    };
    let modified = std::fs::metadata(&asn_path).and_then(|m| m.modified()).ok();
    let mut slot = state.asn.lock().map_err(lock_err)?;
    let stale = match &*slot {
        Some(cache) => cache.path != asn_path || cache.modified != modified || cache.db.is_none(),
        None => true,
    };
    if stale {
        *slot = Some(AsnCache {
            path: asn_path.clone(),
            modified,
            db: AsnDb::load(&asn_path).ok(),
        });
    }
    let Some(db) = slot.as_ref().and_then(|c| c.db.as_ref()) else {
        return Ok(none());
    };
    Ok(ips
        .iter()
        .map(|ip| db.lookup(*ip).map(|info| owner_label(&info)))
        .collect())
}

/// Aggregated connections for the Map tab. Offline: uses only the local GeoLite2 database.
#[tauri::command]
fn map_points(state: State<'_, AppState>) -> std::result::Result<MapView, String> {
    let geo_path = {
        let svc = state.service.lock().map_err(lock_err)?;
        svc.settings().geo_db_path.clone()
    };
    let Some(path) = geo_path else {
        return Ok(MapView {
            available: false,
            reason: Some("no GeoLite2 database configured (Settings)".into()),
            cells: Vec::new(),
        });
    };

    let mut geo_slot = state.geo.lock().map_err(lock_err)?;
    let needs_load = !matches!(&*geo_slot, Some((p, _)) if *p == path);
    if needs_load {
        *geo_slot = Some((path.clone(), GeoIp::load(Some(&path))));
    }
    let (_, geo) = geo_slot.as_ref().expect("geo cache was just filled");
    if !geo.is_available() {
        return Ok(MapView {
            available: false,
            reason: geo.disabled_reason().map(String::from),
            cells: Vec::new(),
        });
    }

    let conns = state
        .published
        .connections
        .lock()
        .map_err(lock_err)?
        .clone();
    let routable: Vec<&tpt_netguard_core::model::Connection> = conns
        .iter()
        .filter(|c| is_routable(c.remote.ip()))
        .collect();
    let ips: Vec<std::net::IpAddr> = routable.iter().map(|c| c.remote.ip()).collect();
    let owners = owner_labels(&state, &ips)?;
    let points: Vec<MapPoint> = routable
        .iter()
        .zip(owners)
        .map(|(c, owner)| MapPoint {
            remote: c.remote.ip(),
            bytes: c.bytes_sent.saturating_add(c.bytes_received),
            owner,
        })
        .collect();
    let cells: Vec<MapCell> = aggregate_map(&points, |ip| geo.lookup(ip));
    Ok(MapView {
        available: true,
        reason: None,
        cells: cells
            .into_iter()
            .map(|c| MapCellView {
                country: c.country,
                city: c.city,
                latitude: c.latitude,
                longitude: c.longitude,
                connections: c.connections,
                bytes: c.bytes,
                owner: c.owner,
            })
            .collect(),
    })
}

#[tauri::command]
fn top_talkers(
    from_ms: u64,
    to_ms: u64,
    limit: usize,
    state: State<'_, AppState>,
) -> std::result::Result<Vec<tpt_netguard_core::store::AppTotals>, String> {
    let svc = state.service.lock().map_err(lock_err)?;
    svc.top_talkers(from_ms, to_ms, limit).map_err(to_string)
}

#[tauri::command]
fn app_history(
    app: String,
    from_ms: u64,
    to_ms: u64,
    granularity: tpt_netguard_core::store::Granularity,
    state: State<'_, AppState>,
) -> std::result::Result<Vec<tpt_netguard_core::store::HistoryPoint>, String> {
    let svc = state.service.lock().map_err(lock_err)?;
    svc.app_history(&app, from_ms, to_ms, granularity)
        .map_err(to_string)
}

/// Replace settings after the settings screen has collected them. Validated in core.
#[tauri::command]
fn save_settings(
    update: SettingsUpdate,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    let mut svc = state.service.lock().map_err(lock_err)?;
    svc.update_settings(&update).map_err(to_string)
}

/// True for addresses that can be located on the map: not loopback, LAN, link-local, multicast
/// or unspecified. Private addresses are never in GeoLite2 anyway; this avoids pointless lookups.
fn is_routable(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified())
        }
        std::net::IpAddr::V6(v6) => {
            !(v6.is_loopback() || v6.is_multicast() || v6.is_unspecified())
                && (v6.segments()[0] & 0xfe00) != 0xfc00 // unique local
                && (v6.segments()[0] & 0xffc0) != 0xfe80 // link local
        }
    }
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Id of the tray icon, so that other code can find it and refresh its menu.
const TRAY_ID: &str = "main-tray";
/// How many recent alerts the tray menu lists.
const TRAY_ALERT_LIMIT: usize = 5;
/// The alert log is read this far back, so that dismissed entries can be skipped.
const TRAY_ALERT_SCAN: usize = 50;
/// Longest alert text shown in a tray entry, in characters.
const TRAY_LABEL_CHARS: usize = 60;

/// Short tray label for an alert, for example `[high] Usage spike: chrome.exe`.
fn tray_label(alert: &Alert) -> String {
    let text = format!("[{}] {}", alert.severity.as_str(), alert.message);
    if text.chars().count() <= TRAY_LABEL_CHARS {
        return text;
    }
    let mut cut: String = text.chars().take(TRAY_LABEL_CHARS - 1).collect();
    cut.push('…');
    cut
}

/// The newest alerts the user has not dismissed, as (alert id, tray label) pairs.
fn tray_alerts(app: &tauri::AppHandle) -> Vec<(i64, String)> {
    let state = app.state::<AppState>();
    let Ok(svc) = state.service.lock() else {
        return Vec::new();
    };
    svc.store()
        .recent_alerts(TRAY_ALERT_SCAN)
        .unwrap_or_default()
        .into_iter()
        .filter(|a| !a.dismissed)
        .take(TRAY_ALERT_LIMIT)
        .map(|a| (a.id, tray_label(&a.alert)))
        .collect()
}

fn tray_menu(app: &tauri::AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let open = MenuItem::with_id(app, "open", "Open tpt-netguard", true, None::<&str>)?;
    let panic = MenuItem::with_id(
        app,
        "panic",
        "Toggle panic button (block all)",
        true,
        None::<&str>,
    )?;

    let alerts = tray_alerts(app);
    let alert_items: Vec<MenuItem<tauri::Wry>> = if alerts.is_empty() {
        vec![MenuItem::with_id(
            app,
            "no-alerts",
            "No recent alerts",
            false,
            None::<&str>,
        )?]
    } else {
        alerts
            .iter()
            .map(|(id, label)| {
                MenuItem::with_id(app, format!("alert-{id}"), label, true, None::<&str>)
            })
            .collect::<tauri::Result<Vec<_>>>()?
    };
    let alert_refs: Vec<&dyn IsMenuItem<tauri::Wry>> = alert_items
        .iter()
        .map(|item| item as &dyn IsMenuItem<tauri::Wry>)
        .collect();
    let recent = Submenu::with_items(app, "Recent alerts", true, &alert_refs)?;

    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    Menu::with_items(app, &[&open, &panic, &recent, &quit])
}

/// Rebuilds the tray menu from the alert log. Call it after anything that changes the list.
/// Must not be called while the service lock is held.
pub fn refresh_tray(app: &tauri::AppHandle) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    if let Ok(menu) = tray_menu(app) {
        let _ = tray.set_menu(Some(menu));
    }
}

fn install_tray(app: &tauri::App) -> tauri::Result<()> {
    let handle = app.handle();
    let menu = tray_menu(handle)?;

    let mut tray = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip("tpt-netguard")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main_window(app),
            // Alert entries open the window, where the Alerts tab lists them.
            other if other.starts_with("alert-") => show_main_window(app),
            "panic" => {
                let state = app.state::<AppState>();
                let outcome = state.service.lock().map_err(lock_err).and_then(|mut svc| {
                    let enabled = !svc.firewall().block_all();
                    svc.apply(Command::SetBlockAll { enabled })
                        .map_err(to_string)
                });
                if let Err(message) = outcome {
                    let _ = app.emit("notice", serde_json::json!({ "message": message }));
                }
                let _ = app.emit("state-changed", ());
            }
            "quit" => app.exit(0),
            _ => {}
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;

            let state = build_state(&dir).map_err(Box::<dyn std::error::Error>::from)?;
            let scheduler = Arc::clone(&state.published.scheduler);
            let published = Published {
                connections: Arc::clone(&state.published.connections),
                bandwidth: Arc::clone(&state.published.bandwidth),
                scheduler: Arc::clone(&scheduler),
                names: Arc::clone(&state.published.names),
            };
            app.manage(state);
            sampler::spawn(app.handle().clone(), dir, published);

            if let Some(window) = app.get_webview_window("main") {
                let focus_scheduler = Arc::clone(&scheduler);
                window.on_window_event(move |event| {
                    if let WindowEvent::Focused(focused) = event {
                        if let Ok(mut s) = focus_scheduler.lock() {
                            s.set_focused(*focused);
                        }
                    }
                });
            }

            install_tray(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            snapshot,
            command,
            enforcement,
            connections,
            map_points,
            save_settings,
            top_talkers,
            app_history
        ])
        .run(tauri::generate_context!())
        .expect("error while running tpt-netguard");
}

#[cfg(test)]
mod tray_tests {
    use super::*;
    use tpt_netguard_core::alerts::{AlertKind, Severity};

    fn alert(message: &str) -> Alert {
        Alert {
            kind: AlertKind::UsageSpike,
            severity: Severity::Warning,
            subject: "chrome.exe".into(),
            message: message.into(),
            ts_ms: 0,
        }
    }

    #[test]
    fn short_labels_are_kept_whole() {
        assert_eq!(tray_label(&alert("Usage spike")), "[warning] Usage spike");
    }

    #[test]
    fn long_labels_are_cut_on_a_character_boundary() {
        let label = tray_label(&alert(&"é".repeat(200)));
        assert_eq!(label.chars().count(), TRAY_LABEL_CHARS);
        assert!(label.ends_with('…'));
    }
}
