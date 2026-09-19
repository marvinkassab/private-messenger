/* Full-page lock screen shown when the app starts locked. */

import type { Messenger } from "../types";
import { h, clear, errorText } from "./dom";

export function showLock(root: HTMLElement, m: Messenger): Promise<void> {
  return new Promise((resolve) => {
    clear(root);

    const pass = h("input", {
      type: "password", id: "lock-pass", "data-test": "lock-passphrase", required: true,
      autocomplete: "current-password", placeholder: "Passphrase",
    });
    const err = h("div.err", { "aria-live": "polite", "data-test": "lock-error" });
    const submitBtn = h("button.btn.primary", { type: "submit", "data-test": "lock-submit" }, "Unlock");

    const form = h("form", {
      "data-test": "lock-form",
      onsubmit: async (e: Event) => {
        e.preventDefault();
        err.textContent = "";
        submitBtn.disabled = true;
        try {
          const ok = await m.unlock(pass.value);
          if (ok) { resolve(); return; }
          err.textContent = "Wrong passphrase.";
          pass.value = ""; pass.focus();
        } catch (ex) {
          err.textContent = errorText(ex);
        } finally {
          submitBtn.disabled = false;
        }
      },
    },
      h("div.field", h("label", { htmlFor: "lock-pass" }, "Passphrase"), pass, err),
      h("div.actions", submitBtn));

    root.appendChild(h("div.screen",
      h("div.card",
        h("div.brand", h("div.mark", { "aria-hidden": "true" }, "🔒"), h("div", h("h1", "Private Messenger"))),
        h("h2", "Locked"),
        h("p", "Enter your passphrase to unlock this device."),
        form)));
    pass.focus();
  });
}
