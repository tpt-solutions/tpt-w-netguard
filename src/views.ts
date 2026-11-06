// SPDX-License-Identifier: MIT OR Apache-2.0
/**
 * The seven tab views. Each view builds its static controls once (so typing survives polling)
 * and re-renders only its data regions, and only when the data actually changed.
 */
import {
  type AlertView,
  type AppRule,
  type Backend,
  type Connection,
  type Device,
  type EnforcementView,
  type Granularity,
  type MapView,
  type Snapshot,
  type SettingsUpdate,
} from "./api";
import { el, announce, renderIfChanged, setChildren, svg, table, type Child } from "./dom";
import {
  baseName,
  cellRadius,
  checkAppKey,
  checkDeviceLabel,
  checkLicenseKey,
  checkRetentionDays,
  checkUpstreams,
  formatBytes,
  formatTime,
  linePath,
  nextRuleId,
  project,
  remoteLabel,
  splitLines,
  topAppSeries,
  type AppWindow,
} from "./format";

export interface BandwidthPoint {
  t: number;
  sent: number;
  received: number;
}

export interface Ctx {
  backend: Backend;
  snapshot: Snapshot | null;
  enforcement: EnforcementView | null;
  connections: Connection[];
  bandwidth: BandwidthPoint[];
  /** Per-program bytes for each recent sampling window, oldest first. */
  appBandwidth: AppWindow[];
  notify(message: string, kind?: "info" | "error"): void;
  refresh(): Promise<void>;
}

export interface View {
  root: HTMLElement;
  /** Called on every poll with the latest context. Must be cheap when nothing changed. */
  update(ctx: Ctx): void;
  /** Called when the tab becomes visible. */
  show?(ctx: Ctx): void;
}

const sig = (value: unknown): string => JSON.stringify(value);

function section(title: string, ...children: Child[]): HTMLElement {
  return el("section", { class: "card", "aria-label": title }, el("h2", {}, title), ...children);
}

function button(label: string, onclick: () => void, extra: Record<string, string | boolean> = {}): HTMLButtonElement {
  return el("button", { type: "button", onclick, ...extra }, label);
}

function field(label: string, control: HTMLElement, hint?: string): HTMLElement {
  return el("div", { class: "field" }, el("label", {}, label), control, hint ? el("p", { class: "hint" }, hint) : null);
}

/* ------------------------------------------------------------------ Graph */

/** Programs drawn on the per-program graph; the rest are left out of the chart. */
const APP_SERIES_LIMIT = 5;

export function graphView(): View {
  const status = el("p", { class: "hint", "aria-live": "polite" });
  const chartBox = el("div", { class: "chart", role: "img", "aria-label": "Bytes per sampling window, last few minutes" });
  const now = el("p", { class: "stat" });
  const appChart = el("div", { class: "chart", role: "img", "aria-label": "Bytes per program over the last few minutes" });
  const appLegend = el("ul", { class: "legend" });
  const connBody = el("div", {});
  const root = el(
    "div",
    { class: "view" },
    section("Live bandwidth", status, now, chartBox),
    section("Busiest programs (last few minutes)", appChart, appLegend),
    section("Connections (largest first)", connBody),
  );
  let lastChart = "";
  let lastAppChart = "";
  return {
    root,
    update(ctx) {
      status.textContent = ctx.enforcement
        ? `Per-app byte counters: ${ctx.enforcement.bandwidth}`
        : "Starting monitor…";
      const last = ctx.bandwidth[ctx.bandwidth.length - 1];
      now.textContent = last
        ? `Last window: ${formatBytes(last.received)} received, ${formatBytes(last.sent)} sent`
        : "Waiting for the first sample…";
      const values = ctx.bandwidth.map((p) => p.sent + p.received);
      const path = linePath(values, 600, 140);
      if (path !== lastChart) {
        lastChart = path;
        chartBox.replaceChildren(
          svg("svg", { viewBox: "0 0 600 140", preserveAspectRatio: "none", class: "chart-svg" },
            svg("path", { d: path, class: "series", fill: "none" })),
        );
      }
      const perApp = topAppSeries(ctx.appBandwidth, APP_SERIES_LIMIT);
      const appMax = Math.max(1, ...perApp.flatMap((s) => s.values));
      const appKey = JSON.stringify([perApp.map((s) => s.app), appMax, perApp.map((s) => s.values)]);
      if (appKey !== lastAppChart) {
        lastAppChart = appKey;
        appChart.replaceChildren(
          perApp.length === 0
            ? el("p", { class: "empty" }, "No per-program traffic yet.")
            : svg(
                "svg",
                { viewBox: "0 0 600 140", preserveAspectRatio: "none", class: "chart-svg" },
                ...perApp.map((s, i) =>
                  svg("path", { d: linePath(s.values, 600, 140, appMax), class: `series series-${i}`, fill: "none" }),
                ),
              ),
        );
        appLegend.replaceChildren(
          ...perApp.map((s, i) => {
            const total = s.values.reduce((n, v) => n + v, 0);
            return el(
              "li",
              {},
              el("span", { class: `swatch series-${i}`, "aria-hidden": "true" }),
              `${baseName(s.app)} — ${formatBytes(total)}`,
            );
          }),
        );
      }
      const top = [...ctx.connections]
        .sort((a, b) => b.bytes_sent + b.bytes_received - (a.bytes_sent + a.bytes_received))
        .slice(0, 20);
      renderIfChanged(connBody, sig(top), () => [
        top.length === 0
          ? el("p", { class: "empty" }, "No connections reported yet.")
          : table(
              ["Program", "Remote", "Owner", "State", "Sent", "Received"],
              top.map((c) => [
                c.process_name,
                remoteLabel(c.remote, c.remote_name),
                c.remote_org ?? "—",
                `${c.protocol.toUpperCase()} ${c.state}`,
                formatBytes(c.bytes_sent),
                formatBytes(c.bytes_received),
              ]),
            ),
      ]);
    },
  };
}

/* ------------------------------------------------------------------ Usage */

const RANGES: Record<string, { label: string; ms: number; granularity: Granularity }> = {
  "1h": { label: "Last hour", ms: 3_600_000, granularity: "hourly" },
  "24h": { label: "Last 24 hours", ms: 86_400_000, granularity: "hourly" },
  "7d": { label: "Last 7 days", ms: 7 * 86_400_000, granularity: "daily" },
  "30d": { label: "Last 30 days", ms: 30 * 86_400_000, granularity: "daily" },
};

export function usageView(): View {
  const range = el(
    "select",
    { id: "usage-range", "aria-label": "Time range" },
    ...Object.entries(RANGES).map(([id, r]) => el("option", { value: id }, r.label)),
  ) as HTMLSelectElement;
  const list = el("div", { "aria-live": "polite" });
  const detail = el("div", { class: "detail" });
  let selected: string | null = null;
  let token = 0;

  async function load(backend: Backend): Promise<void> {
    const r = RANGES[range.value] ?? RANGES["24h"];
    const to = Date.now();
    const mine = ++token;
    const rows = await backend.topTalkers(to - r.ms, to, 50);
    if (mine !== token) return;
    list.replaceChildren(
      rows.length === 0
        ? el("p", { class: "empty" }, "No usage recorded in this range yet.")
        : table(
            ["Program", "Sent", "Received", "Total"],
            rows.map((row) => [
              el("button", {
                type: "button",
                class: "link",
                onclick: () => {
                  selected = row.app;
                  void showDetail(backend);
                },
              }, baseName(row.app)),
              formatBytes(row.totals.bytes_sent),
              formatBytes(row.totals.bytes_received),
              formatBytes(row.totals.bytes_sent + row.totals.bytes_received),
            ]),
          ),
    );
  }

  async function showDetail(backend: Backend): Promise<void> {
    if (!selected) return;
    const r = RANGES[range.value] ?? RANGES["24h"];
    const to = Date.now();
    const points = await backend.appHistory(selected, to - r.ms, to, r.granularity);
    const values = points.map((p) => p.totals.bytes_sent + p.totals.bytes_received);
    detail.replaceChildren(
      el("h3", {}, `${baseName(selected)} — ${r.granularity === "hourly" ? "per hour" : "per day"}`),
      points.length === 0
        ? el("p", { class: "empty" }, "No history for this program in the range.")
        : svg("svg", { viewBox: "0 0 600 140", preserveAspectRatio: "none", class: "chart-svg", role: "img", "aria-label": "Usage over time" },
            svg("path", { d: linePath(values, 600, 140), class: "series", fill: "none" })),
    );
  }

  range.addEventListener("change", () => {
    selected = null;
    detail.replaceChildren();
    void reload();
  });

  let backendRef: Backend | null = null;
  function reload(): Promise<void> {
    return backendRef ? load(backendRef) : Promise.resolve();
  }

  const root = el(
    "div",
    { class: "view" },
    section("Usage by program", el("div", { class: "toolbar" }, el("label", { for: "usage-range" }, "Range "), range), list, detail),
  );
  return {
    root,
    update(ctx) {
      backendRef = ctx.backend;
    },
    show(ctx) {
      backendRef = ctx.backend;
      void load(ctx.backend);
    },
  };
}

/* --------------------------------------------------------------- Firewall */

export function firewallView(): View {
  const status = el("p", { class: "hint", role: "status" });
  const rulesBox = el("div", {});
  const app = el("input", { type: "text", id: "rule-app", autocomplete: "off", placeholder: "C:\\Path\\to\\program.exe" }) as HTMLInputElement;
  const action = el("select", { id: "rule-action", "aria-label": "Action" },
    el("option", { value: "block" }, "Block"),
    el("option", { value: "allow" }, "Allow")) as HTMLSelectElement;
  const profile = el("select", { id: "rule-profile", "aria-label": "Network" },
    el("option", { value: "" }, "All networks"),
    el("option", { value: "home" }, "Home network only"),
    el("option", { value: "public" }, "Public networks only")) as HTMLSelectElement;
  let ctxRef: Ctx | null = null;

  async function submit(event: Event): Promise<void> {
    event.preventDefault();
    const ctx = ctxRef;
    if (!ctx) return;
    const check = checkAppKey(app.value);
    if (!check.ok) {
      announce(status, check.message, "error");
      return;
    }
    const rules = ctx.snapshot?.rules ?? [];
    try {
      await ctx.backend.command({
        cmd: "set_rule",
        id: nextRuleId(rules),
        app: app.value.trim(),
        action: action.value as AppRule["action"],
        profile: profile.value === "" ? null : profile.value,
      });
      announce(status, "Rule saved.");
      app.value = "";
      await ctx.refresh();
    } catch (err) {
      announce(status, `Rule not applied: ${String(err)}`, "error");
    }
  }

  async function removeRule(ctx: Ctx, id: number): Promise<void> {
    try {
      await ctx.backend.command({ cmd: "remove_rule", id });
      await ctx.refresh();
    } catch (err) {
      announce(status, `Could not remove rule: ${String(err)}`, "error");
    }
  }

  const root = el(
    "div",
    { class: "view" },
    section(
      "Per-program rules",
      el("p", { class: "hint" }, "Blocked programs cannot connect. The emergency block-all switch overrides every rule."),
      rulesBox,
    ),
    section(
      "Add a rule",
      el("form", { onsubmit: submit, novalidate: true },
        field("Program", app, "Use the full path where possible; a rule matches that exact program."),
        field("Action", action),
        field("Network", profile, "Rules for a specific network take precedence over rules for all networks."),
        el("div", { class: "actions" }, el("button", { type: "submit", class: "primary" }, "Save rule"))),
      status,
    ),
  );

  return {
    root,
    update(ctx) {
      ctxRef = ctx;
      const rules = ctx.snapshot?.rules ?? [];
      renderIfChanged(rulesBox, sig(rules), () => [
        rules.length === 0
          ? el("p", { class: "empty" }, "No rules yet.")
          : table(
              ["Program", "Action", "Network", ""],
              rules.map((r) => [
                el("span", { title: r.app }, baseName(r.app)),
                r.action === "block" ? "Block" : "Allow",
                r.profile ?? "All networks",
                el("button", { type: "button", onclick: () => void removeRule(ctx, r.id) }, "Remove"),
              ]),
            ),
      ]);
    },
  };
}

/* ----------------------------------------------------------------- Things */

export function thingsView(): View {
  const box = el("div", {});
  const status = el("p", { class: "hint", role: "status" });
  const root = el(
    "div",
    { class: "view" },
    section(
      "Devices on your network",
      el("p", { class: "hint" }, "Found by scanning the local subnet. A device seen for the first time raises a new-device alert, except during the first scan."),
      box,
      status,
    ),
  );
  let ctxRef: Ctx | null = null;

  async function saveLabel(mac: string, value: string): Promise<void> {
    const check = checkDeviceLabel(value);
    if (!check.ok) {
      announce(status, check.message, "error");
      return;
    }
    const ctx = ctxRef;
    if (!ctx) return;
    try {
      await ctx.backend.command({ cmd: "label_device", mac, label: value.trim() === "" ? null : value.trim() });
      announce(status, "Name saved.");
      await ctx.refresh();
    } catch (err) {
      announce(status, `Could not save name: ${String(err)}`, "error");
    }
  }

  async function setTrust(mac: string, trusted: boolean): Promise<void> {
    const ctx = ctxRef;
    if (!ctx) return;
    try {
      await ctx.backend.command({ cmd: "trust_device", mac, trusted });
      await ctx.refresh();
    } catch (err) {
      announce(status, `Could not change trust: ${String(err)}`, "error");
    }
  }

  return {
    root,
    update(ctx) {
      ctxRef = ctx;
      const devices = ctx.snapshot?.devices ?? [];
      renderIfChanged(box, sig(devices), () => [
        devices.length === 0
          ? el("p", { class: "empty" }, "No devices yet. The first scan runs a few minutes after start.")
          : table(
              ["Name", "Address", "Vendor", "First seen", "Trusted"],
              devices.map((d: Device) => [
                deviceNameEditor(d, (v) => void saveLabel(d.mac, v)),
                el("span", {}, d.ip ?? "—", el("br"), el("span", { class: "mono" }, d.mac)),
                d.vendor ?? "Unknown vendor",
                formatTime(d.first_seen_ms),
                el("input", {
                  type: "checkbox",
                  checked: d.trusted,
                  "aria-label": `Trust ${d.label ?? d.mac}`,
                  onchange: (ev: Event) => void setTrust(d.mac, (ev.target as HTMLInputElement).checked),
                }),
              ]),
            ),
      ]);
    },
  };
}

function deviceNameEditor(device: Device, onSave: (value: string) => void): HTMLElement {
  const input = el("input", {
    type: "text",
    value: device.label ?? "",
    maxlength: 64,
    placeholder: device.vendor ?? "Name this device",
    "aria-label": `Name for ${device.mac}`,
  }) as HTMLInputElement;
  return el(
    "form",
    { class: "inline", onsubmit: (ev: Event) => { ev.preventDefault(); onSave(input.value); } },
    input,
    el("button", { type: "submit" }, "Save"),
  );
}

/* -------------------------------------------------------------------- Map */

const MAP_W = 720;
const MAP_H = 360;

export function mapView(): View {
  const body = el("div", { "aria-live": "polite" });
  let timer: ReturnType<typeof setInterval> | null = null;
  let backendRef: Backend | null = null;

  async function load(): Promise<void> {
    if (!backendRef) return;
    const map: MapView = await backendRef.mapPoints();
    renderMap(body, map);
  }

  const root = el("div", { class: "view" }, section("Connection map", body));
  return {
    root,
    update(ctx) {
      backendRef = ctx.backend;
    },
    show(ctx) {
      backendRef = ctx.backend;
      void load();
      if (timer === null) timer = setInterval(() => void load(), 30_000);
    },
  };
}

function renderMap(container: HTMLElement, map: MapView): void {
  if (!map.available) {
    container.replaceChildren(
      el("p", { class: "empty" }, map.reason ?? "The map is unavailable."),
      el("p", { class: "hint" }, "Add a GeoLite2 database path in Settings. Lookups happen on this computer only."),
    );
    return;
  }
  const dots = map.cells.map((c) => {
    const { x, y } = project(c.latitude, c.longitude, MAP_W, MAP_H);
    return svg("circle", {
      cx: x.toFixed(1),
      cy: y.toFixed(1),
      r: cellRadius(c.bytes).toFixed(1),
      class: "dot",
    }, svg("title", {}, `${[c.city, c.country].filter(Boolean).join(", ") || "Unknown"}: ${c.connections} connections, ${formatBytes(c.bytes)}`));
  });
  container.replaceChildren(
    svg("svg", { viewBox: `0 0 ${MAP_W} ${MAP_H}`, class: "map", role: "img", "aria-label": "Remote connections by location" },
      svg("rect", { x: 0, y: 0, width: MAP_W, height: MAP_H, class: "sea" }),
      ...dots),
    map.cells.length === 0
      ? el("p", { class: "empty" }, "No remote connections with a known location right now.")
      : table(
          ["Location", "Connections", "Traffic"],
          map.cells.map((c) => [
            [c.city, c.country].filter(Boolean).join(", ") || "Unknown",
            String(c.connections),
            formatBytes(c.bytes),
          ]),
        ),
  );
}

/* ----------------------------------------------------------------- Alerts */

export function alertsView(): View {
  const box = el("div", { "aria-live": "polite" });
  const status = el("p", { class: "hint", role: "status" });
  const root = el("div", { class: "view" }, section("Alerts", box, status));
  let ctxRef: Ctx | null = null;

  async function act(command: Parameters<Backend["command"]>[0], message: string): Promise<void> {
    const ctx = ctxRef;
    if (!ctx) return;
    try {
      await ctx.backend.command(command);
      announce(status, message);
      await ctx.refresh();
    } catch (err) {
      announce(status, `Failed: ${String(err)}`, "error");
    }
  }

  return {
    root,
    update(ctx) {
      ctxRef = ctx;
      const alerts: AlertView[] = ctx.snapshot?.alerts ?? [];
      const visible = alerts.filter((a) => !a.dismissed);
      renderIfChanged(box, sig(visible), () => [
        visible.length === 0
          ? el("p", { class: "empty" }, "No open alerts.")
          : el("ul", { class: "alerts" }, ...visible.map((a) =>
              el("li", { class: `alert ${a.severity}` },
                el("p", { class: "alert-message" }, a.message),
                el("p", { class: "hint" }, `${formatTime(a.ts_ms)} · ${a.severity}`),
                el("div", { class: "actions" },
                  button("Dismiss", () => void act({ cmd: "dismiss_alert", id: a.id }, "Alert dismissed."), {}),
                  button("Don't alert for this again", () =>
                    void act({ cmd: "set_alert_mute", kind: a.kind, subject: a.subject, muted: true }, "Muted."), {}),
                ))),
          ),
      ]);
    },
  };
}

/* --------------------------------------------------------------- Settings */

export function settingsView(): View {
  let initialised = false;
  const retention = el("input", { type: "number", id: "set-retention", min: 1, max: 365, step: 1 }) as HTMLInputElement;
  const upstreams = el("textarea", { id: "set-upstreams", rows: 3, "aria-describedby": "set-upstreams-hint" }) as HTMLTextAreaElement;
  const geoKey = el("input", { type: "password", id: "set-geo-key", autocomplete: "off", placeholder: "Leave blank to keep the stored key" }) as HTMLInputElement;
  const clearKey = el("input", { type: "checkbox", id: "set-geo-clear" }) as HTMLInputElement;
  const geoPath = el("input", { type: "text", id: "set-geo-path", placeholder: "C:\\ProgramData\\tpt-netguard\\GeoLite2-City.mmdb" }) as HTMLInputElement;
  const spike = el("input", { type: "number", id: "set-spike", min: 1, step: 1 }) as HTMLInputElement;
  const crash = el("input", { type: "checkbox", id: "set-crash" }) as HTMLInputElement;
  const enforcementBox = el("div", { class: "status-box" });
  const status = el("p", { class: "hint", role: "status" });
  const keyNote = el("p", { class: "hint" });
  let current: Snapshot["settings"] | null = null;
  let ctxRef: Ctx | null = null;

  async function save(): Promise<void> {
    const ctx = ctxRef;
    if (!ctx || !current) return;
    const days = Number(retention.value);
    const checks = [
      checkRetentionDays(days),
      checkUpstreams(splitLines(upstreams.value)),
      checkLicenseKey(clearKey.checked ? "" : geoKey.value),
    ];
    const failed = checks.find((c) => !c.ok);
    if (failed && !failed.ok) {
      announce(status, failed.message, "error");
      return;
    }
    const update: SettingsUpdate = {
      retention_days: days,
      resolver_upstreams: splitLines(upstreams.value),
      geo_db_path: geoPath.value.trim() === "" ? null : geoPath.value.trim(),
      usage_spike_bytes: Math.max(1, Math.round(Number(spike.value) * 1024 * 1024)),
      sampling_base_ms: current.sampling_base_ms,
      sampling_max_ms: current.sampling_max_ms,
      onboarding_done: current.onboarding_done,
      crash_log_enabled: crash.checked,
    };
    if (clearKey.checked) update.geo_license_key = "";
    else if (geoKey.value.length > 0) update.geo_license_key = geoKey.value;
    try {
      await ctx.backend.saveSettings(update);
      geoKey.value = "";
      clearKey.checked = false;
      announce(status, "Settings saved.");
      await ctx.refresh();
    } catch (err) {
      announce(status, `Not saved: ${String(err)}`, "error");
    }
  }

  function fill(settings: Snapshot["settings"]): void {
    current = settings;
    retention.value = String(settings.retention_days);
    upstreams.value = settings.resolver_upstreams.join("\n");
    geoPath.value = settings.geo_db_path ?? "";
    spike.value = String(Math.round(settings.usage_spike_bytes / (1024 * 1024)));
    crash.checked = settings.crash_log_enabled;
    keyNote.textContent = settings.geo_key_set
      ? "A MaxMind license key is stored. Enter a new one to replace it."
      : "No MaxMind license key is stored. The map stays off until you add one.";
  }

  const form = el("form", { onsubmit: (ev: Event) => { ev.preventDefault(); void save(); }, novalidate: true },
    field("Keep history for (days)", retention, "Older history is rolled up and then removed. 1 to 365 days."),
    field("DNS resolvers", upstreams, "One per line. https:// is DNS over HTTPS; tls:// is DNS over TLS. Used only for names in this app."),
    field("MaxMind license key", geoKey),
    keyNote,
    el("div", { class: "field" }, el("label", {}, el("span", {}, clearKey, " Remove the stored key")), el("p", { class: "hint" }, "Ticking this removes the key on save; the map then stays off.")),
    field("GeoLite2 database file", geoPath, "Downloaded and refreshed by the app; leave blank to keep the map off."),
    field("Usage alert threshold (MB per sampling window)", spike),
    field("Keep a local error log", crash, "Stored only on this computer, never sent anywhere. Off by default."),
    el("div", { class: "actions" }, el("button", { type: "submit", class: "primary" }, "Save settings")),
  );

  const root = el(
    "div",
    { class: "view" },
    section("Firewall and monitoring status", enforcementBox),
    section("Settings", form, status),
  );

  return {
    root,
    update(ctx) {
      ctxRef = ctx;
      if (!initialised && ctx.snapshot) {
        fill(ctx.snapshot.settings);
        initialised = true;
      }
      const e = ctx.enforcement;
      setChildren(
        enforcementBox,
        [
        el("p", {}, el("strong", {}, "Enforcement: "), e ? (e.active ? `active (${e.mechanism})` : `off (${e.mechanism})`) : "checking…"),
        e?.reason ? el("p", { class: "warning" }, e.reason) : undefined,
        el("p", {}, el("strong", {}, "Byte counters: "), e ? e.bandwidth : "checking…"),
        ctx.backend.demo ? el("p", { class: "hint" }, "Demo data: this is a browser preview, not the desktop app.") : undefined,
        ],
      );
    },
  };
}
