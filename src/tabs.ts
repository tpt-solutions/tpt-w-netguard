// SPDX-License-Identifier: MIT OR Apache-2.0
/** Fixed GlassWire-style tabs. Order is part of the design, not user-configurable. */
export const TABS = [
  { id: "graph", label: "Graph" },
  { id: "usage", label: "Usage" },
  { id: "firewall", label: "Firewall" },
  { id: "things", label: "Things" },
  { id: "map", label: "Map" },
  { id: "alerts", label: "Alerts" },
  { id: "settings", label: "Settings" },
] as const;

export type TabId = (typeof TABS)[number]["id"];

export function isTabId(value: string): value is TabId {
  return TABS.some((t) => t.id === value);
}

/**
 * Index of the tab selected by an arrow/Home/End key, wrapping at both ends (WAI-ARIA tabs
 * pattern). Returns `null` for keys that do not move the selection.
 */
export function nextTabIndex(current: number, key: string, count: number): number | null {
  if (count <= 0) return null;
  switch (key) {
    case "ArrowRight":
      return (current + 1) % count;
    case "ArrowLeft":
      return (current - 1 + count) % count;
    case "Home":
      return 0;
    case "End":
      return count - 1;
    default:
      return null;
  }
}

/** Theme preference. `system` follows the OS via prefers-color-scheme. */
export type Theme = "light" | "dark" | "system";

export function nextTheme(theme: Theme): Theme {
  return theme === "system" ? "light" : theme === "light" ? "dark" : "system";
}
