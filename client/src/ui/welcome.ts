/* Full-page registration screen: username, invite code (prefilled from
   #invite=CODE in the URL), display name. */

import type { Account, Messenger } from "../types";
import { h, clear, errorText } from "./dom";

export function showWelcome(root: HTMLElement, m: Messenger): Promise<Account> {
  return new Promise((resolve) => {
    clear(root);

    let invite = "";
    const match = /#invite=([^&]+)/.exec(location.hash);
    if (match) {
      invite = decodeURIComponent(match[1]);
      history.replaceState(null, "", location.pathname + location.search);
    }

    const username = h("input", {
      type: "text", id: "reg-username", "data-test": "register-username", required: true,
      minLength: 3, maxLength: 32, pattern: "[a-z0-9_]{3,32}", autocomplete: "username",
      autocapitalize: "off", placeholder: "e.g. marvin",
    });
    const inviteInput = h("input", {
      type: "text", id: "reg-invite", "data-test": "register-invite", required: true,
      value: invite, autocomplete: "off", placeholder: "e.g. AB12-CD34",
    });
    const displayName = h("input", {
      type: "text", id: "reg-name", "data-test": "register-displayname",
      maxLength: 60, autocomplete: "name", placeholder: "e.g. Marvin Kassab",
    });
    const err = h("div.err", { "aria-live": "polite", "data-test": "register-error" });
    const submitBtn = h("button.btn.primary", { type: "submit", "data-test": "register-submit" }, "Create account");

    const form = h("form", {
      "data-test": "register-form",
      onsubmit: async (e: Event) => {
        e.preventDefault();
        err.textContent = "";
        submitBtn.disabled = true;
        try {
          const account = await m.register(username.value.trim().toLowerCase(), inviteInput.value.trim(), displayName.value.trim());
          resolve(account);
        } catch (ex) {
          err.textContent = errorText(ex);
          submitBtn.disabled = false;
        }
      },
    },
      h("div.field",
        h("label", { htmlFor: "reg-username" }, "Username"), username,
        h("div.hint", "3–32 characters: lowercase letters, digits and underscore.")),
      h("div.field",
        h("label", { htmlFor: "reg-invite" }, "Invite code"), inviteInput,
        h("div.hint", "Ask someone already on Private Messenger for an invite.")),
      h("div.field",
        h("label", { htmlFor: "reg-name" }, "Display name"), displayName,
        h("div.hint", "Shown to your contacts. You can change this later.")),
      err,
      h("div.actions", submitBtn));

    root.appendChild(h("div.screen",
      h("div.card",
        h("div.brand", h("div.mark", { "aria-hidden": "true" }, "🔒"), h("div", h("h1", "Private Messenger"))),
        h("h2", "Create your account"),
        h("p", "End-to-end encrypted with the Signal protocol. Your keys never leave this device."),
        form)));
    username.focus();
  });
}
