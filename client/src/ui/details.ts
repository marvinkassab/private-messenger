/* Chat details dialog: direct chats show the safety number (digits + QR) and
   a verify toggle; group chats show members, admin controls and leave. */

import type { App } from "./app";
import type { Chat } from "../types";
import { h, clear, avatar, toast, errorText, describeSeconds } from "./dom";
import { confirmDialog, promptDialog } from "./dialog";
import { icon } from "./icons";

/* qrcode-generator ships CJS types ("export =") but its browser build is a
   real ESM module with a default export; a dynamic import sidesteps the
   mismatch and lets Vite resolve the correct build either way. */
let qrFactoryPromise: Promise<any> | null = null;
function qrFactory(): Promise<any> {
  if (!qrFactoryPromise) qrFactoryPromise = import("qrcode-generator").then((mod: any) => mod.default ?? mod);
  return qrFactoryPromise;
}
async function renderQr(container: HTMLElement, text: string) {
  try {
    const factory = await qrFactory();
    const qr = factory(0, "M");
    qr.addData(text);
    qr.make();
    container.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2 });
  } catch {
    container.textContent = "QR unavailable";
  }
}

const DISAPPEAR_OPTIONS = [0, 3600, 86400, 7 * 86400];

function disappearField(app: App, chat: Chat, canEdit: boolean): HTMLElement {
  const select = h("select", { "data-test": "disappear-select", disabled: !canEdit });
  for (const s of DISAPPEAR_OPTIONS) select.appendChild(h("option", { value: String(s) }, s === 0 ? "Off" : describeSeconds(s)));
  select.value = String(chat.disappearSeconds);
  select.addEventListener("change", async () => {
    try { await app.m.setDisappearing(chat.id, Number(select.value)); }
    catch (e) { toast("Could not update: " + errorText(e), "error"); select.value = String(chat.disappearSeconds); }
  });
  return h("div.field", h("div.lbl", "Disappearing messages"), select);
}

export function openDetails(app: App, chatId: string) {
  const chat = app.s.chats.get(chatId);
  if (!chat) return;
  if (chat.kind === "direct") openDirectDetails(app, chat);
  else openGroupDetails(app, chat);
}

async function openDirectDetails(app: App, chat: Chat) {
  const username = chat.members[0];
  const dlg = h("dialog.wide", { "data-test": "details-dialog" });
  const body = h("div.dlg-body");
  dlg.appendChild(h("div.dlg-head", h("h2", app.chatTitle(chat)), h("p", "@" + username)));
  dlg.appendChild(body);
  dlg.appendChild(h("div.dlg-foot", h("button.btn.primary", { type: "button", onclick: () => dlg.close() }, "Close")));
  dlg.addEventListener("close", () => dlg.remove());
  document.body.appendChild(dlg);
  dlg.showModal();

  async function draw() {
    clear(body);
    const c = app.s.chats.get(chat.id) ?? chat;
    const peer = app.s.contacts.get(username);
    body.appendChild(h("div", { style: "display:flex;align-items:center;gap:10px" },
      avatar(app.chatTitle(c), c.id),
      h("div", h("div", { style: "font-weight:600" }, app.chatTitle(c)), h("div.muted", "@" + username))));
    body.appendChild(disappearField(app, c, true));

    const safety = h("div.safety", { "data-test": "safety-number" }, h("p.muted", "Loading safety number…"));
    body.appendChild(safety);
    try {
      const sn = await app.m.safetyNumber(username);
      clear(safety);
      const groups = sn.digits.match(/.{1,5}/g) ?? [];
      safety.appendChild(h("div.digits", { "data-test": "safety-digits" }, ...groups.map((g) => h("div", g))));
      const qr = h("div.qr", { "data-test": "safety-qr" });
      safety.appendChild(qr);
      renderQr(qr, "pm:safety:" + sn.digits);
      safety.appendChild(h("div.vstate" + (sn.verified ? ".on" : ""), { "data-test": "verify-state" },
        icon("shield"), sn.verified ? "Marked as verified" : "Not verified yet"));
      safety.appendChild(h("button.btn" + (sn.verified ? "" : ".primary"), {
        type: "button", "data-test": "toggle-verified-btn",
        onclick: async () => {
          try { await app.m.setVerified(username, !sn.verified); await draw(); }
          catch (e) { toast(errorText(e), "error"); }
        },
      }, sn.verified ? "Remove verification" : "Mark as verified"));
      if (sn.identityChanged || peer?.identityChanged) {
        safety.appendChild(h("div.note", "This safety number changed recently. Compare it with them in person or another trusted channel before trusting it again."));
        safety.appendChild(h("button.btn.sm", {
          type: "button", "data-test": "accept-identity-btn",
          onclick: async () => { try { await app.m.acceptIdentityChange(username); await draw(); } catch (e) { toast(errorText(e), "error"); } },
        }, "Accept new safety number"));
      }
    } catch (e) {
      clear(safety);
      safety.appendChild(h("p.err", errorText(e)));
    }
  }
  await draw();
}

async function openGroupDetails(app: App, chat: Chat) {
  const dlg = h("dialog.wide", { "data-test": "details-dialog" });
  const body = h("div.dlg-body");
  const foot = h("div.dlg-foot", h("button.btn.primary", { type: "button", onclick: () => dlg.close() }, "Close"));
  dlg.appendChild(h("div.dlg-head", h("h2", "Group details")));
  dlg.appendChild(body);
  dlg.appendChild(foot);
  dlg.addEventListener("close", () => dlg.remove());
  document.body.appendChild(dlg);
  dlg.showModal();

  function draw() {
    clear(body); clear(foot);
    const c = app.s.chats.get(chat.id) ?? chat;
    const g = c.group;
    if (!g) return;
    const isAdmin = g.admins.includes(app.me) && !g.leftOrRemoved;

    const nameRow = h("div.field", h("div.lbl", "Name"),
      h("div.kv", h("div", { style: "font-weight:600" }, g.name),
        isAdmin ? h("button.btn.sm", {
          type: "button", "data-test": "group-rename-btn",
          onclick: () => promptDialog({
            title: "Rename group", label: "Group name", value: g.name, submitLabel: "Rename",
            submit: async (value) => { await app.m.updateGroup(g.id, { name: value }); draw(); },
          }),
        }, "Rename") : null));
    body.appendChild(nameRow);

    body.appendChild(disappearField(app, c, isAdmin));

    const membersEl = h("div.members", { "data-test": "group-members-list" },
      ...g.members.map((u) => {
        const contact = app.s.contacts.get(u);
        const isMemberAdmin = g.admins.includes(u);
        const name = u === app.me ? "You" : (contact?.displayName || u);
        return h("div.member", { "data-test": "group-member-row", "data-username": u },
          avatar(name, u),
          h("div.body", h("div.nm", name, isMemberAdmin ? h("span.tag", "Admin") : null), h("div.fp", "@" + u)),
          isAdmin && u !== app.me ? h("button.btn.icon.ghost", {
            type: "button", "aria-label": "Remove " + name, "data-test": "group-remove-member-btn",
            onclick: async () => {
              const ok = await confirmDialog({ title: `Remove ${name}?`, confirm: "Remove", danger: true });
              if (!ok) return;
              try { await app.m.updateGroup(g.id, { remove: [u] }); draw(); } catch (e) { toast(errorText(e), "error"); }
            },
          }, icon("x")) : null);
      }));
    body.appendChild(h("div.field", h("div.lbl", "Members"), membersEl));

    if (isAdmin) {
      const candidates = Array.from(app.s.contacts.values()).filter((ct) => !g.members.includes(ct.username));
      if (candidates.length) {
        const checks = new Map<string, HTMLInputElement>();
        const addList = h("div.members", { "data-test": "group-add-candidates" },
          ...candidates.map((ct) => {
            const cb = h("input", { type: "checkbox", value: ct.username }) as HTMLInputElement;
            checks.set(ct.username, cb);
            return h("label.member.pick", { "data-test": "group-add-candidate", "data-username": ct.username },
              avatar(ct.displayName || ct.username, ct.username),
              h("div.body", h("div.nm", ct.displayName || ct.username), h("div.fp", "@" + ct.username)), cb);
          }));
        const addBtn = h("button.btn.sm", {
          type: "button", "data-test": "group-add-members-btn",
          onclick: async () => {
            const add = Array.from(checks.entries()).filter(([, cb]) => cb.checked).map(([u]) => u);
            if (!add.length) return;
            try { await app.m.updateGroup(g.id, { add }); draw(); } catch (e) { toast(errorText(e), "error"); }
          },
        }, "Add selected");
        body.appendChild(h("div.field", h("div.lbl", "Add members"), addList, addBtn));
      }
    }

    if (!g.leftOrRemoved) {
      foot.prepend(h("button.btn.danger", {
        type: "button", "data-test": "leave-group-btn",
        onclick: async () => {
          const ok = await confirmDialog({ title: "Leave group?", desc: "You will need a new invite to rejoin.", confirm: "Leave", danger: true });
          if (!ok) return;
          try { await app.m.leaveGroup(g.id); dlg.close(); } catch (e) { toast(errorText(e), "error"); }
        },
      }, "Leave group"));
    }
    foot.appendChild(h("button.btn.primary", { type: "button", onclick: () => dlg.close() }, "Close"));
  }
  draw();
}
