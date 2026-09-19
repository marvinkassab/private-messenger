/* Small DOM and formatting helpers shared by the UI modules. */

export const $ = <T extends Element = HTMLElement>(sel: string, root: ParentNode = document) => root.querySelector(sel) as T | null;

type Child = Node | string | null | undefined | false | Child[];
type Attrs = Record<string, string | number | boolean | null | undefined | ((e: any) => void)>;

/* Pulls the plain tag name out of a "tag.class.class#id" string at the type
   level, so h("button.btn.primary", ...) still returns an HTMLButtonElement
   instead of the generic union HTMLElementTagNameMap[keyof ...]. The "#id"
   suffix can follow any class, so it is stripped first. */
type StripId<T extends string> = T extends `${infer Head}#${string}` ? Head : T;
type BareTag<T extends string> = StripId<T> extends `${infer Head}.${string}` ? Head : StripId<T>;
type ElementFor<T extends string> = BareTag<T> extends keyof HTMLElementTagNameMap ? HTMLElementTagNameMap[BareTag<T>] : HTMLElement;

/* h("button.btn.primary#send", { onclick, title }, "Send") */
export function h<T extends string>(tag: T, attrs?: Attrs | Child, ...children: Child[]): ElementFor<T> {
  const hashAt = tag.indexOf("#");
  const id = hashAt >= 0 ? tag.slice(hashAt + 1) : "";
  const [base, ...classes] = (hashAt >= 0 ? tag.slice(0, hashAt) : tag).split(".");
  const el = document.createElement(base || "div") as ElementFor<T>;
  if (id) el.id = id;
  if (classes.length) el.className = classes.join(" ");
  if (attrs && typeof attrs === "object" && !(attrs instanceof Node) && !Array.isArray(attrs)) {
    for (const [k, v] of Object.entries(attrs as Attrs)) {
      if (v == null || v === false) continue;
      if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v as EventListener);
      else if (k === "class") el.className += (el.className ? " " : "") + String(v);
      else if (k === "style") el.setAttribute("style", String(v));
      else if (k in el && k !== "list" && k !== "form") (el as any)[k] = v === true ? true : v;
      else el.setAttribute(k, v === true ? "" : String(v));
    }
  } else if (attrs != null) {
    children.unshift(attrs as Child);
  }
  append(el, children);
  return el;
}

export function append(el: Node, children: Child[]) {
  for (const c of children) {
    if (c == null || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
}

export function svg(markup: string): SVGElement {
  const t = document.createElement("template");
  t.innerHTML = markup.trim();
  return t.content.firstElementChild as unknown as SVGElement;
}

export function clear(el: Element) { while (el.firstChild) el.removeChild(el.firstChild); }

export function escapeHtml(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}

/* Text with URLs turned into links; returns child nodes, never innerHTML of user text. */
export function linkify(text: string): Node[] {
  const out: Node[] = [];
  const re = /\bhttps?:\/\/[^\s<]+[^\s<.,;:!?)]/g;
  let last = 0, m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(document.createTextNode(text.slice(last, m.index)));
    out.push(h("a", { href: m[0], target: "_blank", rel: "noopener noreferrer" }, m[0]));
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(document.createTextNode(text.slice(last)));
  return out;
}

export function initials(name: string): string {
  const p = String(name || "?").trim().split(/\s+/);
  return ((p[0] || "?")[0] + (p[1] ? p[1][0] : "")).toUpperCase();
}

export function colorFor(key: string): string {
  let hsh = 0;
  for (const c of String(key)) hsh = (hsh * 31 + c.charCodeAt(0)) >>> 0;
  return `var(--s${(hsh % 8) + 1})`;
}

export function avatar(name: string, key: string, cls = "avatar"): HTMLElement {
  return h("div", { class: cls, style: `background:${colorFor(key)}`, "aria-hidden": "true" }, initials(name));
}

export const fmtTime = (ms: number) => new Date(ms).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });

export function dayKey(ms: number): string { const d = new Date(ms); return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`; }

export function fmtDay(ms: number): string {
  const d = new Date(ms), t = new Date();
  const same = (a: Date, b: Date) => a.toDateString() === b.toDateString();
  if (same(d, t)) return "Today";
  const y = new Date(t); y.setDate(t.getDate() - 1);
  if (same(d, y)) return "Yesterday";
  return d.toLocaleDateString([], { weekday: "short", month: "short", day: "numeric", year: d.getFullYear() === t.getFullYear() ? undefined : "numeric" });
}

export function fmtRel(ms: number): string {
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 60) return "now";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h";
  if (s < 7 * 86400) return Math.floor(s / 86400) + "d";
  return new Date(ms).toLocaleDateString([], { month: "short", day: "numeric" });
}

export function fmtBytes(n: number): string {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10240 ? 1 : 0) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

export function describeSeconds(s: number): string {
  if (s <= 0) return "Off";
  if (s % 604800 === 0) return `${s / 604800} week${s / 604800 === 1 ? "" : "s"}`;
  if (s % 86400 === 0) return `${s / 86400} day${s / 86400 === 1 ? "" : "s"}`;
  if (s % 3600 === 0) return `${s / 3600} hour${s / 3600 === 1 ? "" : "s"}`;
  if (s % 60 === 0) return `${s / 60} min`;
  return `${s} s`;
}

export function describeSecondsShort(s: number): string {
  if (s <= 0) return "";
  if (s % 604800 === 0) return `${s / 604800}w`;
  if (s % 86400 === 0) return `${s / 86400}d`;
  if (s % 3600 === 0) return `${s / 3600}h`;
  if (s % 60 === 0) return `${s / 60}m`;
  return `${s}s`;
}

export const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e ?? "Something went wrong"));

export const finePointer = () => matchMedia("(pointer: fine)").matches;

/* ---- toasts ---- */
let toastHost: HTMLElement | null = null;
export function toast(text: string, kind: "info" | "error" = "info", ms = 3500) {
  if (!toastHost) { toastHost = h("div.toasts", { role: "status", "aria-live": "polite" }); document.body.appendChild(toastHost); }
  const t = h("div.toast", { class: kind }, text);
  toastHost.appendChild(t);
  setTimeout(() => { t.classList.add("out"); setTimeout(() => t.remove(), 300); }, ms);
}

export async function copyText(text: string): Promise<boolean> {
  try { await navigator.clipboard.writeText(text); return true; } catch {
    const ta = h("textarea", { value: text, style: "position:fixed;opacity:0" });
    document.body.appendChild(ta); ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch { /* unsupported */ }
    ta.remove();
    return ok;
  }
}

/* Keyed reconciliation: keeps DOM nodes whose key and version are unchanged. */
export function reconcile(container: HTMLElement, rows: { key: string; ver: string; make: () => HTMLElement }[]) {
  const existing = new Map<string, HTMLElement>();
  for (const c of Array.from(container.children) as HTMLElement[]) if (c.dataset.key) existing.set(c.dataset.key, c);
  let i = 0;
  for (const r of rows) {
    let node = existing.get(r.key);
    if (!node || node.dataset.ver !== r.ver) {
      const fresh = r.make();
      fresh.dataset.key = r.key; fresh.dataset.ver = r.ver;
      if (node) { node.replaceWith(fresh); } else { container.insertBefore(fresh, container.children[i] || null); }
      node = fresh;
      existing.set(r.key, node);
    }
    if (container.children[i] !== node) container.insertBefore(node, container.children[i] || null);
    i++;
  }
  while (container.children.length > rows.length) container.lastElementChild!.remove();
}
