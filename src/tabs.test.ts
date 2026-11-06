// SPDX-License-Identifier: MIT OR Apache-2.0
import { describe, expect, it } from "vitest";
import { isTabId, nextTabIndex, nextTheme, TABS } from "./tabs";

describe("tab navigation", () => {
  it("wraps with arrow keys", () => {
    expect(nextTabIndex(0, "ArrowLeft", 7)).toBe(6);
    expect(nextTabIndex(6, "ArrowRight", 7)).toBe(0);
    expect(nextTabIndex(2, "ArrowRight", 7)).toBe(3);
  });

  it("jumps with Home and End", () => {
    expect(nextTabIndex(4, "Home", 7)).toBe(0);
    expect(nextTabIndex(1, "End", 7)).toBe(6);
  });

  it("ignores other keys and empty lists", () => {
    expect(nextTabIndex(1, "a", 7)).toBeNull();
    expect(nextTabIndex(0, "ArrowRight", 0)).toBeNull();
  });

  it("keeps the fixed GlassWire tab set and order", () => {
    expect(TABS.map((t) => t.label)).toEqual([
      "Graph",
      "Usage",
      "Firewall",
      "Things",
      "Map",
      "Alerts",
      "Settings",
    ]);
    expect(isTabId("firewall")).toBe(true);
    expect(isTabId("archon")).toBe(false);
  });
});

describe("theme cycle", () => {
  it("cycles system -> light -> dark -> system", () => {
    expect(nextTheme("system")).toBe("light");
    expect(nextTheme("light")).toBe("dark");
    expect(nextTheme("dark")).toBe("system");
  });
});
