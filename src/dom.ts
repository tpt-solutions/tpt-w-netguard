// SPDX-License-Identifier: MIT OR Apache-2.0
/**
 * Tiny DOM builder. Everything is created with `createElement`/`textContent`, never
 * `innerHTML`, so process names, device labels and alert text cannot inject markup.
 */

export type Child = Node | string | number | null | undefined | false;

type AttrValue = string | number | boolean | null | undefined | ((ev: Event) => void);

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, AttrValue> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (typeof value === "function") {
      node.addEventListener(key.replace(/^on/, ""), value);
    } else if (value === true) {
      node.setAttribute(key, "");
    } else if (key === "value" && "value" in node) {
      (node as unknown as HTMLInputElement).value = String(value);
    } else {
      node.setAttribute(key, String(value));
    }
  }
  append(node, children);
  return node;
}

function append(parent: Element, children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    parent.append(typeof child === "string" || typeof child === "number" ? String(child) : child);
  }
}

const SVG_NS = "http://www.w3.org/2000/svg";

export function svg(tag: string, attrs: Record<string, string | number> = {}, ...children: Child[]): SVGElement {
  const node = document.createElementNS(SVG_NS, tag) as SVGElement;
  for (const [key, value] of Object.entries(attrs)) {
    node.setAttribute(key, String(value));
  }
  append(node, children);
  return node;
}

/** Replace a container's children with `build()`, but only when `signature` changed. */
export function renderIfChanged(
  container: HTMLElement,
  signature: string,
  build: () => Child[],
): void {
  if (container.dataset.signature === signature) return;
  container.dataset.signature = signature;
  container.replaceChildren(...buildChildren(build()));
}

/** Replace a container's children, skipping null/undefined/false entries. */
export function setChildren(container: HTMLElement, children: Child[]): void {
  container.replaceChildren(...buildChildren(children));
}

function buildChildren(children: Child[]): Node[] {
  const out: Node[] = [];
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    out.push(typeof child === "string" || typeof child === "number" ? document.createTextNode(String(child)) : child);
  }
  return out;
}

/** Simple table: header labels plus rows of cells. Cells may be strings or nodes. */
export function table(headers: string[], rows: Child[][], caption?: string): HTMLTableElement {
  const thead = el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", { scope: "col" }, h))));
  const tbody = el(
    "tbody",
    {},
    ...rows.map((cells) => el("tr", {}, ...cells.map((c) => el("td", {}, c)))),
  );
  return el("table", { class: "data" }, caption ? el("caption", {}, caption) : null, thead, tbody);
}

/** Text intended for a polite live region (status messages). */
export function announce(region: HTMLElement, message: string, kind: "info" | "error" = "info"): void {
  region.textContent = message;
  region.dataset.kind = kind;
}
