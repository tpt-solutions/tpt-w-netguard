// SPDX-License-Identifier: MIT OR Apache-2.0
/**
 * Pure helpers: number formatting, chart geometry, map projection and input validation.
 * No DOM access, so everything here is covered by unit tests.
 *
 * The validation rules mirror `tpt_netguard_core::ipc` so the UI rejects the same inputs the
 * backend would. The backend remains the authority; these checks only give faster feedback.
 */

const UNITS = ["B", "KB", "MB", "GB", "TB"] as const;

/** Human-readable byte count, base 1024: 1536 -> "1.5 KB". */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit++;
  }
  const digits = unit === 0 || value >= 100 ? 0 : 1;
  return `${value.toFixed(digits)} ${UNITS[unit]}`;
}

/** Bytes per second as text, e.g. "1.2 MB/s". */
export function formatRate(bytesPerSecond: number): string {
  return `${formatBytes(bytesPerSecond)}/s`;
}

/** Last path segment of a Windows or POSIX path; falls back to the input. */
export function baseName(path: string): string {
  const parts = path.split(/[\\/]/).filter((p) => p.length > 0);
  return parts.length > 0 ? parts[parts.length - 1] : path;
}

/** Fixed-length rolling window: keeps only the newest `max` items. */
export function pushBounded<T>(items: readonly T[], item: T, max: number): T[] {
  const next = [...items, item];
  return next.length > max ? next.slice(next.length - max) : next;
}

/** A remote endpoint for display: the reverse-DNS name with the address after it, when known. */
export function remoteLabel(remote: string, name?: string | null): string {
  return name ? `${name} (${remote})` : remote;
}

/** Bytes per app in one sampling window, keyed by app name. */
export interface AppWindow {
  t: number;
  apps: Record<string, number>;
}

/** Sums the sent and received bytes of one sampling batch per app. */
export function appWindow(
  t: number,
  samples: readonly { app: string; bytes_sent: number; bytes_received: number }[],
): AppWindow {
  const apps: Record<string, number> = {};
  for (const s of samples) {
    apps[s.app] = (apps[s.app] ?? 0) + s.bytes_sent + s.bytes_received;
  }
  return { t, apps };
}

/**
 * The `limit` apps with the most bytes across all windows, each with one value per window
 * (zero where the app was silent). Ties are broken by name so the legend order is stable.
 */
export function topAppSeries(
  windows: readonly AppWindow[],
  limit: number,
): { app: string; values: number[] }[] {
  const totals = new Map<string, number>();
  for (const w of windows) {
    for (const [app, bytes] of Object.entries(w.apps)) {
      totals.set(app, (totals.get(app) ?? 0) + bytes);
    }
  }
  return [...totals.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, Math.max(0, limit))
    .map(([app]) => ({ app, values: windows.map((w) => w.apps[app] ?? 0) }));
}

export interface Point {
  x: number;
  y: number;
}

/**
 * SVG path for a line through `values` scaled into a `width` x `height` box.
 * An empty or single-value series yields an empty or single-point path.
 */
export function linePath(
  values: readonly number[],
  width: number,
  height: number,
  sharedMax?: number,
): string {
  if (values.length === 0) return "";
  const max = Math.max(1, sharedMax ?? 0, ...values);
  const step = values.length > 1 ? width / (values.length - 1) : 0;
  return values
    .map((v, i) => {
      const x = (i * step).toFixed(1);
      const y = (height - (Math.max(0, v) / max) * height).toFixed(1);
      return `${i === 0 ? "M" : "L"}${x},${y}`;
    })
    .join(" ");
}

/** Equirectangular projection of a latitude/longitude onto a `width` x `height` map. */
export function project(latitude: number, longitude: number, width: number, height: number): Point {
  const lat = Math.max(-90, Math.min(90, latitude));
  const lon = ((((longitude + 180) % 360) + 360) % 360) - 180;
  return {
    x: ((lon + 180) / 360) * width,
    y: ((90 - lat) / 180) * height,
  };
}

/** Circle radius for a map cell, growing with the log of its traffic. */
export function cellRadius(bytes: number, min = 4, max = 22): number {
  const scaled = Math.log10(Math.max(1, bytes)) / 12;
  return min + Math.max(0, Math.min(1, scaled)) * (max - min);
}

const CONTROL = /[\u0000-\u001f\u007f]/;

export type Check = { ok: true } | { ok: false; message: string };

const ok: Check = { ok: true };
const fail = (message: string): Check => ({ ok: false, message });

/** Application key (executable path or name) for a rule. */
export function checkAppKey(app: string): Check {
  const trimmed = app.trim();
  if (trimmed.length === 0) return fail("Enter the path to the program, for example C:\\Apps\\game.exe.");
  if (trimmed.length > 260) return fail("The path is longer than 260 characters.");
  if (CONTROL.test(trimmed)) return fail("The path contains control characters.");
  return ok;
}

export function checkRetentionDays(days: number): Check {
  if (!Number.isInteger(days)) return fail("Retention must be a whole number of days.");
  if (days < 1 || days > 365) return fail("Retention must be between 1 and 365 days.");
  return ok;
}

/** One DNS upstream per line; must be DoH (https://) or DoT (tls://) without spaces. */
export function checkUpstreams(lines: readonly string[]): Check {
  const list = lines.map((l) => l.trim()).filter((l) => l.length > 0);
  if (list.length === 0) return fail("Configure at least one resolver.");
  if (list.length > 4) return fail("Use at most four resolvers.");
  for (const up of list) {
    const schemeOk = up.startsWith("https://") || up.startsWith("tls://");
    if (!schemeOk || up.length > 256 || /\s/.test(up) || CONTROL.test(up)) {
      return fail(`"${up}" must start with https:// (DoH) or tls:// (DoT) and contain no spaces.`);
    }
  }
  return ok;
}

export function checkDeviceLabel(label: string): Check {
  if (label.length > 64) return fail("Device names can be at most 64 characters.");
  if (CONTROL.test(label)) return fail("Device names cannot contain control characters.");
  return ok;
}

/** Optional MaxMind key: letters, digits and underscores, 8-64 characters. Blank means "keep". */
export function checkLicenseKey(key: string): Check {
  if (key.length === 0) return ok;
  return /^[A-Za-z0-9_]{8,64}$/.test(key) ? ok : fail("A MaxMind license key has 8-64 letters, digits or underscores.");
}

/** Next unused positive rule id. */
export function nextRuleId(existing: readonly { id: number }[]): number {
  return existing.reduce((max, r) => Math.max(max, r.id), 0) + 1;
}

/** Split a textarea into trimmed, non-empty lines. */
export function splitLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

/** Local time as "YYYY-MM-DD HH:MM" for tables. */
export function formatTime(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
