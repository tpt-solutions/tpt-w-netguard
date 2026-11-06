// SPDX-License-Identifier: MIT OR Apache-2.0
//! tpt-netguard desktop shell.
//!
//! The UI talks to the backend through a small set of Tauri commands. Every state-changing
//! request is a [`Command`] from `tpt-netguard-core`, validated before it reaches the firewall or
//! the history store.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod fallback;
mod sampler;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager, State, WindowEvent};
use tpt_netguard_core::error::Error;
use tpt_netguard_core::ipc::Command;
use tpt_netguard_core::manager::FirewallManager;
use tpt_netguard_core::model::Connection;
use tpt_netguard_core::scheduler::SamplingScheduler;
use tpt_netguard_core::service::{Service, Snapshot};
use tpt_netguard_core::settings::{Settings, SettingsUpdate};
use tpt_netguard_core::store::Store;
use tpt_netguard_core::traits::{FirewallBackend, RulePersistence};
use tpt_netguard_geoip::{aggregate_map, GeoIp, MapCell, MapPoint};

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
}

#[derive(Debug, Serialize)]
pub struct MapCellView {
    pub country: Option<String>,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub connections: usize,
    pub bytes: u64,
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
            Some(c) if c.nftables => (
                Box::new(tpt_netguard_platform_linux::NftFirewall::new()),
                EnforcementView {
                    active: true,
                    mechanism:
                        "nftables (panic button only; per-app rules need eBPF, not yet implemented)"
                            .into(),
                    reason: None,
                    bandwidth: String::new(),
                },
            ),
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
    };
    Ok(AppState {
        service: Mutex::new(service),
        enforcement: Mutex::new(enforcement),
        published,
        geo: Mutex::new(None),
    })
}

#[tauri::command]
fn snapshot(state: State<'_, AppState>) -> std::result::Result<Snapshot, String> {
    let svc = state.service.lock().map_err(lock_err)?;
    svc.snapshot().map_err(to_string)
}

/// The closed set of changes the UI may request. See `tpt_netguard_core::ipc`.
#[tauri::command]
fn command(request: Command, state: State<'_, AppState>) -> std::result::Result<(), String> {
    let mut svc = state.service.lock().map_err(lock_err)?;
    svc.apply(request).map_err(to_string)
}

#[tauri::command]
fn enforcement(state: State<'_, AppState>) -> std::result::Result<EnforcementView, String> {
    let mut view = state.enforcement.lock().map_err(lock_err)?.clone();
    view.bandwidth = state.published.bandwidth.lock().map_err(lock_err)?.clone();
    Ok(view)
}

#[tauri::command]
fn connections(state: State<'_, AppState>) -> std::result::Result<Vec<Connection>, String> {
    Ok(state
        .published
        .connections
        .lock()
        .map_err(lock_err)?
        .clone())
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
    let points: Vec<MapPoint> = conns
        .iter()
        .filter(|c| is_routable(c.remote.ip()))
        .map(|c| MapPoint {
            remote: c.remote.ip(),
            bytes: c.bytes_sent.saturating_add(c.bytes_received),
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

fn install_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open tpt-netguard", true, None::<&str>)?;
    let panic = MenuItem::with_id(
        app,
        "panic",
        "Toggle panic button (block all)",
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &panic, &quit])?;

    let mut tray = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("tpt-netguard")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main_window(app),
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
