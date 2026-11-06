// SPDX-License-Identifier: MIT OR Apache-2.0
import { describe, expect, it } from "vitest";
import {
  baseName,
  cellRadius,
  checkAppKey,
  checkDeviceLabel,
  checkLicenseKey,
  checkRetentionDays,
  checkUpstreams,
  formatBytes,
  linePath,
  nextRuleId,
  project,
  pushBounded,
  splitLines,
} from "./format";

describe("formatBytes", () => {
  it("uses base-1024 units with sensible precision", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
    expect(formatBytes(250 * 1024 * 1024)).toBe("250 MB");
    expect(formatBytes(3 * 1024 ** 4)).toBe("3.0 TB");
  });

  it("rejects negative and non-finite input instead of printing nonsense", () => {
    expect(formatBytes(-1)).toBe("—");
    expect(formatBytes(Number.NaN)).toBe("—");
  });
});

describe("baseName", () => {
  it("takes the last segment of Windows and POSIX paths", () => {
    expect(baseName("C:\\Program Files\\Chrome\\chrome.exe")).toBe("chrome.exe");
    expect(baseName("/usr/bin/curl")).toBe("curl");
    expect(baseName("plain.exe")).toBe("plain.exe");
  });
});

describe("pushBounded", () => {
  it("keeps only the newest items", () => {
    expect(pushBounded([1, 2, 3], 4, 3)).toEqual([2, 3, 4]);
    expect(pushBounded([], 1, 3)).toEqual([1]);
  });
});

describe("linePath", () => {
  it("scales values into the box, with the largest value at the top", () => {
    expect(linePath([0, 10], 100, 50)).toBe("M0.0,50.0 L100.0,0.0");
  });

  it("handles empty and single-point series", () => {
    expect(linePath([], 100, 50)).toBe("");
    expect(linePath([5], 100, 50)).toMatch(/^M0\.0,/);
  });

  it("does not draw negative values below the baseline", () => {
    expect(linePath([-5, 10], 100, 50)).toContain("M0.0,50.0");
  });
});

describe("project", () => {
  it("maps the corners and centre of the world", () => {
    expect(project(90, -180, 360, 180)).toEqual({ x: 0, y: 0 });
    // 180 wraps to the dateline (-180), so the right edge is approached from the left.
    expect(project(-90, 179.999, 360, 180).x).toBeCloseTo(360, 0);
    expect(project(-90, 179.999, 360, 180).y).toBeCloseTo(180, 0);
    expect(project(0, 0, 360, 180)).toEqual({ x: 180, y: 90 });
  });

  it("wraps longitudes beyond 180 and clamps latitudes", () => {
    expect(project(0, 190, 360, 180).x).toBeCloseTo(project(0, -170, 360, 180).x);
    expect(project(120, 0, 360, 180).y).toBe(0);
  });
});

describe("cellRadius", () => {
  it("grows with traffic and stays within bounds", () => {
    expect(cellRadius(0)).toBeCloseTo(4);
    expect(cellRadius(1e6)).toBeGreaterThan(cellRadius(1e3));
    expect(cellRadius(1e30)).toBeLessThanOrEqual(22);
  });
});

describe("validators mirror the backend limits", () => {
  it("app keys must be non-empty, bounded and free of control characters", () => {
    expect(checkAppKey("   ").ok).toBe(false);
    expect(checkAppKey("C:\\Apps\\game.exe").ok).toBe(true);
    expect(checkAppKey("a\nb.exe").ok).toBe(false);
    expect(checkAppKey("x".repeat(261)).ok).toBe(false);
  });

  it("retention is 1 to 365 whole days", () => {
    expect(checkRetentionDays(0).ok).toBe(false);
    expect(checkRetentionDays(1).ok).toBe(true);
    expect(checkRetentionDays(365).ok).toBe(true);
    expect(checkRetentionDays(366).ok).toBe(false);
    expect(checkRetentionDays(2.5).ok).toBe(false);
  });

  it("upstreams must be encrypted schemes, at most four", () => {
    expect(checkUpstreams(["https://dns.example/dns-query"]).ok).toBe(true);
    expect(checkUpstreams(["tls://dns.example:853"]).ok).toBe(true);
    expect(checkUpstreams(["udp://8.8.8.8:53"]).ok).toBe(false);
    expect(checkUpstreams(["https://a b"]).ok).toBe(false);
    expect(checkUpstreams([]).ok).toBe(false);
    expect(checkUpstreams(Array(5).fill("https://x.example")).ok).toBe(false);
  });

  it("device labels are at most 64 characters", () => {
    expect(checkDeviceLabel("kitchen tablet").ok).toBe(true);
    expect(checkDeviceLabel("x".repeat(65)).ok).toBe(false);
  });

  it("a blank license key means keep; a malformed one is rejected", () => {
    expect(checkLicenseKey("").ok).toBe(true);
    expect(checkLicenseKey("abc_DEF_12345678").ok).toBe(true);
    expect(checkLicenseKey("short").ok).toBe(false);
    expect(checkLicenseKey("has spaces in it").ok).toBe(false);
  });
});

describe("rule ids and text helpers", () => {
  it("next rule id is one past the largest existing id", () => {
    expect(nextRuleId([])).toBe(1);
    expect(nextRuleId([{ id: 4 }, { id: 2 }])).toBe(5);
  });

  it("splitLines trims and drops blank lines", () => {
    expect(splitLines(" a \r\n\n b\n  \n")).toEqual(["a", "b"]);
  });
});
