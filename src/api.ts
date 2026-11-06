// SPDX-License-Identifier: MIT OR Apache-2.0
/**
 * Typed client for the Tauri backend.
 *
 * Inside the desktop app it calls the Rust commands through `window.__TAURI__`. In a plain
 * browser (`npm run dev`) it uses an in-memory demo backend, so the UI can be developed and
 * tested without a window. The demo is labelled as such in the UI.
 */

export type RuleAction = "allow" | "block";
export type Granularity = "hourly" | "daily";

export interface AppRule {
  id: number;
  app: string;
  action: RuleAction;
  profile: string | null;
}

export interface AlertView {
  id: number;
  kind: "new_app" | "new_device" | "usage_spike" | "inbound_remote";
  severity: "info" | "warning" | "critical";
  subject: string;
  message: string;
  ts_ms: number;
  dismissed: boolean;
}

export interface Device {
  mac: string;
  ip: string | null;
  vendor: string | null;
  label: string | null;
  first_seen_ms: number;
  last_seen_ms: number;
  trusted: boolean;
}

export interface SettingsView {
  retention_days: number;
  resolver_upstreams: string[];
  geo_key_set: boolean;
  geo_db_path: string | null;
  usage_spike_bytes: number;
  sampling_base_ms: number;
  sampling_max_ms: number;
  onboarding_done: boolean;
  crash_log_enabled: boolean;
  panic_enabled: boolean;
}

export interface Snapshot {
  block_all: boolean;
  profile: string | null;
  rules: AppRule[];
  alerts: AlertView[];
  devices: Device[];
  settings: SettingsView;
}

export interface Connection {
  pid: number;
  process_name: string;
  exe_path: string | null;
  local: string;
  remote: string;
  protocol: "tcp" | "udp";
  direction: "inbound" | "outbound" | "unknown";
  bytes_sent: number;
  bytes_received: number;
  state: "established" | "listening" | "closed" | "other";
  first_seen_ms: number;
  last_seen_ms: number;
}

export interface ByteSample {
  app: string;
  timestamp_ms: number;
  bytes_sent: number;
  bytes_received: number;
}

export interface AppTotals {
  app: string;
  totals: { bytes_sent: number; bytes_received: number };
}

export interface HistoryPoint {
  bucket_start_ms: number;
  totals: { bytes_sent: number; bytes_received: number };
}

export interface EnforcementView {
  active: boolean;
  mechanism: string;
  reason: string | null;
  bandwidth: string;
}

export interface MapCell {
  country: string | null;
  city: string | null;
  latitude: number;
  longitude: number;
  connections: number;
  bytes: number;
}

export interface MapView {
  available: boolean;
  reason: string | null;
  cells: MapCell[];
}

/** The closed set of commands; mirrors `tpt_netguard_core::ipc::Command`. */
export type Command =
  | { cmd: "set_rule"; id: number; app: string; action: RuleAction; profile: string | null }
  | { cmd: "remove_rule"; id: number }
  | { cmd: "set_block_all"; enabled: boolean }
  | { cmd: "dismiss_alert"; id: number }
  | { cmd: "set_alert_mute"; kind: string; subject: string; muted: boolean }
  | { cmd: "label_device"; mac: string; label: string | null }
  | { cmd: "trust_device"; mac: string; trusted: boolean }
  | { cmd: "set_retention_days"; days: number }
  | { cmd: "set_resolver_upstreams"; upstreams: string[] };

/** Partial settings change; a missing `geo_license_key` keeps the stored key. */
export interface SettingsUpdate {
  retention_days: number;
  resolver_upstreams: string[];
  geo_license_key?: string;
  geo_db_path: string | null;
  usage_spike_bytes: number;
  sampling_base_ms: number;
  sampling_max_ms: number;
  onboarding_done: boolean;
  crash_log_enabled: boolean;
}

export interface Backend {
  readonly demo: boolean;
  snapshot(): Promise<Snapshot>;
  command(request: Command): Promise<void>;
  enforcement(): Promise<EnforcementView>;
  connections(): Promise<Connection[]>;
  mapPoints(): Promise<MapView>;
  topTalkers(fromMs: number, toMs: number, limit: number): Promise<AppTotals[]>;
  appHistory(app: string, fromMs: number, toMs: number, granularity: Granularity): Promise<HistoryPoint[]>;
  saveSettings(update: SettingsUpdate): Promise<void>;
  /** Subscribe to a backend event. Returns an unsubscribe function. */
  on<T>(event: "alert" | "bandwidth" | "notice" | "state-changed", handler: (payload: T) => void): () => void;
}

interface TauriGlobal {
  core: { invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T> };
  event: {
    listen: <T>(event: string, handler: (e: { payload: T }) => void) => Promise<() => void>;
  };
}

function tauriGlobal(): TauriGlobal | null {
  const g = (globalThis as { __TAURI__?: TauriGlobal }).__TAURI__;
  return g ?? null;
}

class TauriBackend implements Backend {
  readonly demo = false;
  constructor(private readonly t: TauriGlobal) {}

  snapshot(): Promise<Snapshot> {
    return this.t.core.invoke<Snapshot>("snapshot");
  }
  command(request: Command): Promise<void> {
    return this.t.core.invoke<void>("command", { request });
  }
  enforcement(): Promise<EnforcementView> {
    return this.t.core.invoke<EnforcementView>("enforcement");
  }
  connections(): Promise<Connection[]> {
    return this.t.core.invoke<Connection[]>("connections");
  }
  mapPoints(): Promise<MapView> {
    return this.t.core.invoke<MapView>("map_points");
  }
  topTalkers(fromMs: number, toMs: number, limit: number): Promise<AppTotals[]> {
    return this.t.core.invoke<AppTotals[]>("top_talkers", { fromMs, toMs, limit });
  }
  appHistory(app: string, fromMs: number, toMs: number, granularity: Granularity): Promise<HistoryPoint[]> {
    return this.t.core.invoke<HistoryPoint[]>("app_history", { app, fromMs, toMs, granularity });
  }
  saveSettings(update: SettingsUpdate): Promise<void> {
    return this.t.core.invoke<void>("save_settings", { update });
  }
  on<T>(event: string, handler: (payload: T) => void): () => void {
    let unlisten: (() => void) | null = null;
    let cancelled = false;
    void this.t.event.listen<T>(event, (e) => handler(e.payload)).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }
}

/** Browser-only stand-in with believable data. Clearly labelled as demo in the UI. */
export class DemoBackend implements Backend {
  readonly demo = true;
  private rules: AppRule[] = [
    { id: 1, app: "C:\\Program Files\\Google\\Chrome\\chrome.exe", action: "allow", profile: null },
    { id: 2, app: "C:\\Users\\demo\\AppData\\Local\\Updater\\updater.exe", action: "block", profile: null },
  ];
  private alerts: AlertView[] = [
    { id: 1, kind: "new_app", severity: "info", subject: "updater.exe", message: "updater.exe made its first network connection", ts_ms: Date.now() - 3_600_000, dismissed: false },
    { id: 2, kind: "new_device", severity: "warning", subject: "f4:5c:89:00:11:22", message: "New device on the network: living-room-tv", ts_ms: Date.now() - 600_000, dismissed: false },
  ];
  private blockAll = false;
  private handlers = new Map<string, Set<(p: unknown) => void>>();

  snapshot(): Promise<Snapshot> {
    return Promise.resolve({
      block_all: this.blockAll,
      profile: "home",
      rules: this.rules.map((r) => ({ ...r })),
      alerts: this.alerts.map((a) => ({ ...a })),
      devices: [
        { mac: "f4:5c:89:00:11:22", ip: "192.168.1.50", vendor: "Samsung", label: "living-room-tv", first_seen_ms: Date.now() - 600_000, last_seen_ms: Date.now(), trusted: false },
        { mac: "3c:22:fb:aa:bb:cc", ip: "192.168.1.1", vendor: "Apple", label: null, first_seen_ms: Date.now() - 864_000_000, last_seen_ms: Date.now(), trusted: true },
      ],
      settings: {
        retention_days: 30,
        resolver_upstreams: ["https://cloudflare-dns.com/dns-query", "https://dns.quad9.net/dns-query"],
        geo_key_set: false,
        geo_db_path: null,
        usage_spike_bytes: 524288000,
        sampling_base_ms: 1000,
        sampling_max_ms: 15000,
        onboarding_done: false,
        crash_log_enabled: false,
        panic_enabled: this.blockAll,
      },
    });
  }

  command(request: Command): Promise<void> {
    switch (request.cmd) {
      case "set_rule": {
        this.rules = this.rules.filter((r) => r.id !== request.id);
        this.rules.push({ id: request.id, app: request.app, action: request.action, profile: request.profile });
        break;
      }
      case "remove_rule":
        this.rules = this.rules.filter((r) => r.id !== request.id);
        break;
      case "set_block_all":
        this.blockAll = request.enabled;
        break;
      case "dismiss_alert":
        this.alerts = this.alerts.map((a) => (a.id === request.id ? { ...a, dismissed: true } : a));
        break;
      default:
        break;
    }
    return Promise.resolve();
  }

  enforcement(): Promise<EnforcementView> {
    return Promise.resolve({
      active: false,
      mechanism: "demo (no firewall)",
      reason: "Demo mode in a browser: nothing is enforced.",
      bandwidth: "demo data",
    });
  }

  connections(): Promise<Connection[]> {
    const now = Date.now();
    return Promise.resolve([
      { pid: 4312, process_name: "chrome.exe", exe_path: null, local: "192.168.1.20:51422", remote: "142.250.72.14:443", protocol: "tcp", direction: "outbound", bytes_sent: 2_400_000, bytes_received: 18_300_000, state: "established", first_seen_ms: now - 90_000, last_seen_ms: now },
      { pid: 880, process_name: "svchost.exe", exe_path: null, local: "0.0.0.0:3389", remote: "0.0.0.0:0", protocol: "tcp", direction: "unknown", bytes_sent: 0, bytes_received: 0, state: "listening", first_seen_ms: now - 900_000, last_seen_ms: now },
    ]);
  }

  mapPoints(): Promise<MapView> {
    return Promise.resolve({
      available: true,
      reason: null,
      cells: [
        { country: "US", city: "Mountain View", latitude: 37.4, longitude: -122.1, connections: 12, bytes: 40_000_000 },
        { country: "AU", city: "Sydney", latitude: -33.9, longitude: 151.2, connections: 3, bytes: 900_000 },
      ],
    });
  }

  topTalkers(): Promise<AppTotals[]> {
    return Promise.resolve([
      { app: "chrome.exe", totals: { bytes_sent: 120_000_000, bytes_received: 900_000_000 } },
      { app: "updater.exe", totals: { bytes_sent: 1_000_000, bytes_received: 4_000_000 } },
    ]);
  }

  appHistory(_app: string, fromMs: number, toMs: number, granularity: Granularity): Promise<HistoryPoint[]> {
    const step = granularity === "hourly" ? 3_600_000 : 86_400_000;
    const points: HistoryPoint[] = [];
    for (let t = fromMs; t <= toMs; t += step) {
      points.push({ bucket_start_ms: t, totals: { bytes_sent: 1_000_000 + (t % 7) * 100_000, bytes_received: 5_000_000 + (t % 11) * 200_000 } });
    }
    return Promise.resolve(points);
  }

  saveSettings(): Promise<void> {
    return Promise.resolve();
  }

  on<T>(event: string, handler: (payload: T) => void): () => void {
    const set = this.handlers.get(event) ?? new Set<(p: unknown) => void>();
    set.add(handler as (p: unknown) => void);
    this.handlers.set(event, set);
    return () => set.delete(handler as (p: unknown) => void);
  }
}

/** The backend for this environment: the real one inside the desktop app, demo otherwise. */
export function createBackend(): Backend {
  const t = tauriGlobal();
  return t ? new TauriBackend(t) : new DemoBackend();
}
