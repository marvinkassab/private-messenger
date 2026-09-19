/* "New chat" (add a contact by username) and "New group" dialogs. */

import type { App } from "./app";
import { h, errorText, avatar } from "./dom";

export function openNewChat(app: App) {
  const input = h("input", {
    type: "text", id: "new-chat-username", "data-test": "new-chat-username", required: true,
    autocomplete: "off", autocapitalize: "off", placeholder: "e.g. alice",
  });
  const err = h("div.err", { "aria-live": "polite", "data-test": "new-chat-error" });
  const submitBtn = h("button.btn.primary", { type: "submit", "data-test": "new-chat-submit" }, "Start chat");

  const form = h("form", {
    "data-test": "new-chat-form",
    onsubmit: async (e: Event) => {
      e.preventDefault();
      err.textContent = "";
      submitBtn.disabled = true;
      try {
        const username = input.value.trim().toLowerCase();
        const contact = await app.m.addContact(username);
        dlg.close();
        await app.openChat("u:" + contact.username);
      } catch (ex) {
        err.textContent = errorText(ex);
        submitBtn.disabled = false;
      }
    },
  },
    h("div.dlg-body",
      h("div.field", h("label", { htmlFor: "new-chat-username" }, "Username"), input,
        h("div.hint", "Start a private, end-to-end encrypted chat with someone by their username.")),
      err),
    h("div.dlg-foot", h("button.btn", { type: "button", onclick: () => dlg.close() }, "Cancel"), submitBtn));

  const dlg = h("dialog", { "data-test": "new-chat-dialog" });
  dlg.appendChild(h("div.dlg-head", h("h2", "New chat")));
  dlg.appendChild(form);
  dlg.addEventListener("close", () => dlg.remove());
  document.body.appendChild(dlg);
  dlg.showModal();
  input.focus();
}

export function openNewGroup(app: App) {
  const nameInput = h("input", { type: "text", id: "new-group-name", "data-test": "group-name", required: true, maxLength: 60, placeholder: "e.g. Cabin weekend" });
  const err = h("div.err", { "aria-live": "polite", "data-test": "group-error" });
  const contacts = Array.from(app.s.contacts.values());
  const checks = new Map<string, HTMLInputElement>();

  const membersList = contacts.length
    ? h("div.members", { "data-test": "group-members" },
      ...contacts.map((c) => {
        const cb = h("input", { type: "checkbox", value: c.username }) as HTMLInputElement;
        checks.set(c.username, cb);
        return h("label.member.pick", { "data-test": "group-member", "data-username": c.username },
          avatar(c.displayName || c.username, c.username),
          h("div.body", h("div.nm", c.displayName || c.username), h("div.fp", "@" + c.username)),
          cb);
      }))
    : h("div.hint", "Add someone with New chat first, then create a group with them.");

  const submitBtn = h("button.btn.primary", { type: "submit", "data-test": "group-submit" }, "Create group");
  const form = h("form", {
    "data-test": "group-form",
    onsubmit: async (e: Event) => {
      e.preventDefault();
      err.textContent = "";
      submitBtn.disabled = true;
      try {
        const members = Array.from(checks.entries()).filter(([, cb]) => cb.checked).map(([u]) => u);
        const chat = await app.m.createGroup(nameInput.value.trim(), members);
        dlg.close();
        await app.openChat(chat.id);
      } catch (ex) {
        err.textContent = errorText(ex);
        submitBtn.disabled = false;
      }
    },
  },
    h("div.dlg-body",
      h("div.field", h("label", { htmlFor: "new-group-name" }, "Group name"), nameInput),
      h("div.field", h("div.lbl", "Members"), membersList),
      err),
    h("div.dlg-foot", h("button.btn", { type: "button", onclick: () => dlg.close() }, "Cancel"), submitBtn));

  const dlg = h("dialog.wide", { "data-test": "new-group-dialog" });
  dlg.appendChild(h("div.dlg-head", h("h2", "New group")));
  dlg.appendChild(form);
  dlg.addEventListener("close", () => dlg.remove());
  document.body.appendChild(dlg);
  dlg.showModal();
  nameInput.focus();
}
