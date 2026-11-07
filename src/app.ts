// SPDX-License-Identifier: MIT OR Apache-2.0
/**
 * Application controller: polls the backend, listens for pushed events, keeps the header and
 * the tab strip in step with the data, and shows the first-run walkthrough.
 */
import {
  createBackend,
  type ByteSample,
  type Connection,
  type Snapshot,
  type SettingsUpdate,
  type Backend,
} from "./api";
import { el, announce } from "./dom";
import { appWindow, pushBounded } from "./format";
import { cycleFocus, FOCUSABLE } from "./focus";
import { isTabId, nextTabIndex, nextTheme, TABS, type Theme, type TabId } from "./tabs";
import {
  alertsView,
  firewallView,
  graphView,
  mapView,
  settingsView,
  thingsView,
  usageView,
  type BandwidthPoint,
  type Ctx,
  type View,
} from "./views";

const POLL_MS = 2_000;
const CONNECTIONS_MS = 5_000;
const BANDWIDTH_HISTORY = 120;
const THEME_KEY = "tpt-netguard.theme";

/** Preference storage can be blocked (private windows); every access is guarded. */
function loadTheme(): Theme {
  try {
    const stored = localStorage.getItem(THEME_KEY);
    if (stored === "light" || stored === "dark" || stored === "system") return stored;
  } catch {
    /* storage unavailable: follow the system */
  }
  return "system";
}

function saveTheme(theme: Theme): void {
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* preference lasts for this session only */
  }
}

function applyTheme(theme: Theme): void {
  if (theme === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", theme);
}

/** A required element of the static shell; a missing one is a build error, not a runtime state. */
function need<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`app shell is missing #${id}`);
  return node as T;
}

/** Settings update that keeps every current value except the given patch. */
function updateFrom(snapshot: Snapshot, patch: Partial<SettingsUpdate>): SettingsUpdate {
  const s = snapshot.settings;
  return {
    retention_days: s.retention_days,
    resolver_upstreams: s.resolver_upstreams,
    geo_db_path: s.geo_db_path,
    usage_spike_bytes: s.usage_spike_bytes,
    sampling_base_ms: s.sampling_base_ms,
    sampling_max_ms: s.sampling_max_ms,
    onboarding_done: s.onboarding_done,
    crash_log_enabled: s.crash_log_enabled,
    ...patch,
  };
}

export function start(): void {
  const backend: Backend = createBackend();
  const list = need<HTMLElement>("tablist");
  const panels = need<HTMLElement>("panels");
  const panicButton = need<HTMLButtonElement>("panic-button");
  const themeButton = need<HTMLButtonElement>("theme-toggle");
  const notices = need<HTMLElement>("notices");

  const ctx: Ctx = {
    backend,
    snapshot: null,
    enforcement: null,
    connections: [],
    bandwidth: [],
    appBandwidth: [],
    notify,
    refresh,
  };

  const views: Record<TabId, View> = {
    graph: graphView(),
    usage: usageView(),
    firewall: firewallView(),
    things: thingsView(),
    map: mapView(),
    alerts: alertsView(),
    settings: settingsView(),
  };

  /* ---- tab strip ---- */
  const buttons = new Map<TabId, HTMLButtonElement>();
  for (const tab of TABS) {
    const button = el("button", {
      type: "button",
      id: `tab-${tab.id}`,
      class: "tab",
      role: "tab",
      "aria-controls": `panel-${tab.id}`,
      "aria-selected": "false",
    }, tab.label);
    button.tabIndex = -1;
    list.append(button);
    buttons.set(tab.id, button);

    const panel = el("section", { id: `panel-${tab.id}`, role: "tabpanel", "aria-labelledby": button.id });
    panel.hidden = true;
    panel.append(views[tab.id].root);
    panels.append(panel);
  }

  let current: TabId = "graph";
  function selectTab(id: TabId): void {
    current = id;
    for (const tab of TABS) {
      const selected = tab.id === id;
      const button = buttons.get(tab.id);
      if (button) {
        button.setAttribute("aria-selected", String(selected));
        button.tabIndex = selected ? 0 : -1;
      }
      const panel = document.getElementById(`panel-${tab.id}`);
      if (panel) panel.hidden = !selected;
    }
    try {
      history.replaceState(null, "", `#${id}`);
    } catch {
      /* the hash is a convenience only */
    }
    views[id].show?.(ctx);
  }

  list.addEventListener("click", (event) => {
    const target = (event.target as HTMLElement).closest<HTMLButtonElement>("[role=tab]");
    const id = target?.id.replace(/^tab-/, "") ?? "";
    if (isTabId(id)) selectTab(id);
  });
  const order = TABS.map((t) => t.id);
  list.addEventListener("keydown", (event) => {
    const next = nextTabIndex(order.indexOf(current), event.key, order.length);
    if (next === null) return;
    event.preventDefault();
    const id = order[next];
    selectTab(id);
    buttons.get(id)?.focus();
  });

  /* ---- notices ---- */
  function notify(message: string, kind: "info" | "error" = "info"): void {
    announce(notices, message, kind);
  }

  /* ---- theme ---- */
  let theme = loadTheme();
  applyTheme(theme);
  themeButton.textContent = `Theme: ${theme}`;
  themeButton.addEventListener("click", () => {
    theme = nextTheme(theme);
    applyTheme(theme);
    saveTheme(theme);
    themeButton.textContent = `Theme: ${theme}`;
  });

  /* ---- panic button ---- */
  panicButton.addEventListener("click", () => {
    const snap = ctx.snapshot;
    if (!snap) return;
    const enabled = !snap.block_all;
    void backend
      .command({ cmd: "set_block_all", enabled })
      .then(() => notify(enabled ? "All internet access is blocked." : "Internet access restored."))
      .catch((err: unknown) => notify(`Could not change the block-all switch: ${String(err)}`, "error"))
      .finally(() => void refresh());
  });

  /* ---- onboarding ---- */
  let onboardingShownThisSession = false;
  /** Focus to return to when the dialog closes, and siblings made inert while it is open. */
  let onboardingReturnFocus: HTMLElement | null = null;
  let onboardingInerted: Element[] = [];

  function closeOnboarding(): void {
    const dialog = document.getElementById("onboarding");
    if (!dialog) return;
    dialog.remove();
    for (const element of onboardingInerted) element.removeAttribute("inert");
    onboardingInerted = [];
    if (onboardingReturnFocus?.isConnected) onboardingReturnFocus.focus();
    onboardingReturnFocus = null;
  }

  function renderOnboarding(snapshot: Snapshot): void {
    const existing = document.getElementById("onboarding");
    const needed = !snapshot.settings.onboarding_done && !onboardingShownThisSession;
    if (!needed) {
      closeOnboarding();
      return;
    }
    if (existing) return;
    onboardingShownThisSession = true;
    onboardingReturnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = el("section", {
      id: "onboarding",
      class: "dialog",
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "onboarding-title",
    },
      el("h2", { id: "onboarding-title" }, "Welcome to tpt-netguard"),
      el("ol", {},
        el("li", {}, "Administrator rights (root on Linux) are needed to block programs. Windows asks once at launch."),
        el("li", {}, "Block a program: open Firewall, enter its path, choose Block. The Block-all button in the header overrides every rule."),
        el("li", {}, "Map: optional. Add your own free MaxMind license key and a GeoLite2 database in Settings. Lookups stay on this computer."),
        el("li", {}, "Privacy: apart from the MaxMind map downloads you set up, the only traffic is name lookups for remote addresses through the encrypted resolvers in Settings, which you can change there. Local network addresses are never sent."),
      ),
      el("div", { class: "actions" },
        el("button", {
          type: "button",
          class: "primary",
          onclick: () => {
            void backend
              .saveSettings(updateFrom(snapshot, { onboarding_done: true }))
              .catch((err: unknown) => notify(`Could not save: ${String(err)}`, "error"))
              .finally(() => {
                closeOnboarding();
                void refresh();
              });
          },
        }, "Got it"),
      ));
    // Escape closes the walkthrough for this session only; it is shown again next launch.
    dialog.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeOnboarding();
        return;
      }
      if (event.key !== "Tab") return;
      const controls = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE));
      if (controls.length === 0) return;
      event.preventDefault();
      const current = controls.indexOf(document.activeElement as HTMLElement);
      controls[cycleFocus(current, controls.length, event.shiftKey)]?.focus();
    });
    // The rest of the page is inert while the dialog is open, so screen readers and Tab skip it.
    onboardingInerted = Array.from(document.body.children).filter(
      (child) => child.id !== "onboarding" && !child.hasAttribute("inert"),
    );
    for (const element of onboardingInerted) element.setAttribute("inert", "");
    document.body.append(dialog);
    dialog.querySelector("button")?.focus();
  }

  /* ---- data ---- */
  async function refresh(): Promise<void> {
    try {
      const [snapshot, enforcement] = await Promise.all([backend.snapshot(), backend.enforcement()]);
      ctx.snapshot = snapshot;
      ctx.enforcement = enforcement;
      panicButton.setAttribute("aria-pressed", String(snapshot.block_all));
      panicButton.classList.toggle("active", snapshot.block_all);
      panicButton.textContent = snapshot.block_all ? "Restore internet access" : "Block all internet";
      renderOnboarding(snapshot);
      for (const view of Object.values(views)) view.update(ctx);
    } catch (err) {
      notify(`Backend unavailable: ${String(err)}`, "error");
    }
  }

  async function refreshConnections(): Promise<void> {
    try {
      ctx.connections = (await backend.connections()) as Connection[];
      views.graph.update(ctx);
    } catch {
      /* keep the last good list */
    }
  }

  backend.on<ByteSample[]>("bandwidth", (batch) => {
    const sent = batch.reduce((n, s) => n + s.bytes_sent, 0);
    const received = batch.reduce((n, s) => n + s.bytes_received, 0);
    const point: BandwidthPoint = { t: Date.now(), sent, received };
    ctx.bandwidth = pushBounded(ctx.bandwidth, point, BANDWIDTH_HISTORY);
    ctx.appBandwidth = pushBounded(ctx.appBandwidth, appWindow(point.t, batch), BANDWIDTH_HISTORY);
    views.graph.update(ctx);
  });
  backend.on<{ message: string }>("alert", (alert) => {
    notify(`Alert: ${alert.message}`);
    void refresh();
  });
  backend.on<{ message: string }>("notice", (payload) => notify(payload.message, "error"));
  backend.on("state-changed", () => void refresh());

  if (backend.demo) {
    notify("Demo data: running in a browser, nothing is enforced.");
  }

  const hash = location.hash.replace(/^#/, "");
  selectTab(isTabId(hash) ? hash : "graph");
  void refresh();
  void refreshConnections();
  setInterval(() => void refresh(), POLL_MS);
  setInterval(() => void refreshConnections(), CONNECTIONS_MS);
}
