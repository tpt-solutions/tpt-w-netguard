// SPDX-License-Identifier: MIT OR Apache-2.0
/**
 * Index of the control that Tab (or Shift+Tab) should focus next inside a modal dialog, wrapping
 * at both ends so focus never escapes the dialog. `current` is -1 when focus is outside the
 * dialog's controls; Tab then goes to the first control and Shift+Tab to the last.
 */
export function cycleFocus(current: number, count: number, backwards: boolean): number {
  if (count <= 0) return -1;
  if (current < 0 || current >= count) return backwards ? count - 1 : 0;
  return backwards ? (current - 1 + count) % count : (current + 1) % count;
}

/** Selector for controls that can take keyboard focus. */
export const FOCUSABLE =
  "button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";
