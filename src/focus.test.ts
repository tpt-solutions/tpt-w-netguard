// SPDX-License-Identifier: MIT OR Apache-2.0
import { describe, expect, it } from "vitest";
import { cycleFocus } from "./focus";

describe("dialog focus cycle", () => {
  it("moves forward and wraps to the first control", () => {
    expect(cycleFocus(0, 3, false)).toBe(1);
    expect(cycleFocus(2, 3, false)).toBe(0);
  });

  it("moves backward and wraps to the last control", () => {
    expect(cycleFocus(1, 3, true)).toBe(0);
    expect(cycleFocus(0, 3, true)).toBe(2);
  });

  it("enters from outside the dialog at the nearest end", () => {
    expect(cycleFocus(-1, 3, false)).toBe(0);
    expect(cycleFocus(-1, 3, true)).toBe(2);
  });

  it("returns -1 when there is nothing to focus", () => {
    expect(cycleFocus(0, 0, false)).toBe(-1);
  });
});
