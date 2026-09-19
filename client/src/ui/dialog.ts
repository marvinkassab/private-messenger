/* Dialog helpers built on <dialog>. Each call creates a dialog, shows it
   modally and removes it from the DOM when closed. */

import { h, errorText } from "./dom";

export interface DialogOptions {
  title: string;
  desc?: string;
  body?: (Node | string | null | false)[] | Node;
  foot?: (Node | string | null | false)[];
  wide?: boolean;
  onClose?: () => void;
  initialFocus?: HTMLElement;
}

export function openDialog(o: DialogOptions): HTMLDialogElement {
  const dlg = h("dialog", { class: o.wide ? "wide" : "" });
  dlg.setAttribute("aria-labelledby", "dlg-title-" + Math.random().toString(36).slice(2, 8));
  const title = h("h2", { id: dlg.getAttribute("aria-labelledby")! }, o.title);
  dlg.appendChild(h("div.dlg-head", title, o.desc ? h("p", o.desc) : null));
  const body = h("div.dlg-body");
  if (o.body instanceof Node) body.appendChild(o.body);
  else if (o.body) for (const c of o.body) if (c) body.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  dlg.appendChild(body);
  if (o.foot) dlg.appendChild(h("div.dlg-foot", ...o.foot));
  dlg.addEventListener("close", () => { dlg.remove(); o.onClose?.(); });
  dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });
  document.body.appendChild(dlg);
  dlg.showModal();
  if (o.initialFocus) o.initialFocus.focus();
  return dlg;
}

export const closeBtn = (dlg: () => HTMLDialogElement, label = "Cancel") =>
  h("button.btn", { type: "button", onclick: () => dlg().close() }, label);

export function confirmDialog(opts: { title: string; desc?: string; confirm: string; danger?: boolean }): Promise<boolean> {
  return new Promise((resolve) => {
    let ok = false;
    const dlg = openDialog({
      title: opts.title, desc: opts.desc,
      foot: [
        h("button.btn", { type: "button", onclick: () => dlg.close() }, "Cancel"),
        h("button.btn", { type: "button", class: opts.danger ? "danger-solid" : "primary", onclick: () => { ok = true; dlg.close(); } }, opts.confirm),
      ],
      onClose: () => resolve(ok),
    });
  });
}

/* A one-field form dialog. `submit` may throw; the error is shown inline. */
export function promptDialog(opts: {
  title: string; desc?: string; label: string; type?: string; placeholder?: string; hint?: string;
  value?: string; minLength?: number; submitLabel?: string; autocomplete?: string;
  submit: (value: string) => Promise<void> | void;
}): Promise<boolean> {
  return new Promise((resolve) => {
    let done = false;
    const input = h("input", { type: opts.type || "text", value: opts.value || "", placeholder: opts.placeholder || "", required: true, autocomplete: opts.autocomplete || "off", id: "prompt-" + Math.random().toString(36).slice(2, 8) });
    if (opts.minLength) input.minLength = opts.minLength;
    const err = h("div.err", { "aria-live": "polite" });
    const submitBtn = h("button.btn.primary", { type: "submit" }, opts.submitLabel || "Continue");
    const form = h("form", { onsubmit: async (e: Event) => {
      e.preventDefault();
      err.textContent = "";
      submitBtn.disabled = true;
      try { await opts.submit(input.value); done = true; dlg.close(); }
      catch (ex) { err.textContent = errorText(ex); submitBtn.disabled = false; input.focus(); }
    } },
      h("div.dlg-body", h("div.field", h("label", { htmlFor: input.id }, opts.label), input, opts.hint ? h("div.hint", opts.hint) : null, err)),
      h("div.dlg-foot", h("button.btn", { type: "button", onclick: () => dlg.close() }, "Cancel"), submitBtn),
    );
    const dlg = h("dialog");
    dlg.appendChild(h("div.dlg-head", h("h2", opts.title), opts.desc ? h("p", opts.desc) : null));
    dlg.appendChild(form);
    dlg.addEventListener("close", () => { dlg.remove(); resolve(done); });
    document.body.appendChild(dlg);
    dlg.showModal();
    input.focus();
  });
}

export function errorDialog(title: string, e: unknown) {
  const dlg = openDialog({ title, desc: errorText(e), foot: [h("button.btn.primary", { type: "button", onclick: () => dlg.close() }, "OK")] });
}
