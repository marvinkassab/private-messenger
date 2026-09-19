/* Sidebar: brand + connection state, your card, actions, search, chat list. */

import type { Chat } from "../types";
import type { App } from "./app";
import { getTheme, setTheme, type Theme } from "./app";
import { h, clear, fmtRel, avatar, reconcile } from "./dom";
import { icon } from "./icons";

export interface Sidebar { render(): void; renderConnection(): void }

const CONN_LABEL = { online: "Online", connecting: "Connecting…", offline: "Offline" } as const;
const CONN_CLASS = { online: "", connecting: "stale", offline: "err" } as const;

export function mountSidebar(app: App, parent: HTMLElement): Sidebar {
  const dot = h("span.dot-live", { id: "conn-dot" });
  const connText = h("span", { id: "conn-text" });
  const themeBtn = h("button.btn.icon", { id: "btn-theme", type: "button", "aria-label": "Switch theme", onclick: () => {
    const order: Theme[] = ["auto", "light", "dark"];
    setTheme(order[(order.indexOf(getTheme()) + 1) % order.length]);
    renderTheme();
  } }, icon("theme"));
  const renderTheme = () => { themeBtn.title = `Theme: ${getTheme()} — click to change`; };
  renderTheme();
  document.addEventListener("pm:theme", renderTheme);

  const meName = h("div.nm");
  const meSub = h("div.fp");
  const meAv = h("div");
  const meCard = h("button.me-card", { id: "me-card", type: "button", title: "Settings", onclick: () => app.openSettings() }, meAv, h("div", meName, meSub));

  const search = h("input", { type: "search", id: "search", placeholder: "Search chats", "aria-label": "Search chats", autocomplete: "off",
    oninput: () => { app.s.search = search.value.trim().toLowerCase(); render(); } });

  const rooms = h("nav.rooms", { id: "rooms", "aria-label": "Chats" });
  const empty = h("div.side-empty", { id: "side-empty", hidden: true },
    h("p", h("strong", "No chats yet.")),
    h("p", "Add someone by their username to start a chat, or create a group."));

  const side = h("aside.side",
    h("header.topbar",
      h("div.brand", h("div.mark", { "aria-hidden": "true" }, "🔒"), h("div", h("h1", "Private Messenger"), h("div.sub", dot, connText))),
      h("div.controls", themeBtn,
        h("button.btn.icon", { id: "btn-settings", type: "button", title: "Settings", "aria-label": "Settings", onclick: () => app.openSettings() }, icon("settings")))),
    meCard,
    h("div.side-actions",
      h("button.btn.primary", { id: "btn-new-chat", type: "button", onclick: () => app.openNewChat() }, icon("plus"), "New chat"),
      h("button.btn", { id: "btn-new-group", type: "button", onclick: () => app.openNewGroup() }, icon("users"), "New group")),
    h("div.search", search),
    rooms, empty,
  );
  parent.appendChild(side);

  rooms.addEventListener("click", (e) => {
    const b = (e.target as HTMLElement).closest<HTMLElement>(".room");
    if (b?.dataset.id) app.openChat(b.dataset.id);
  });

  function roomRow(c: Chat): HTMLElement {
    const typing = app.s.typing.get(c.id) ?? [];
    const prev = typing.length
      ? (c.kind === "group" ? `${typing.map((u) => app.nameOf(u).split(" ")[0]).join(", ")} typing…` : "typing…")
      : app.preview(c);
    const ts = c.lastMessage?.sentAt ?? c.updatedAt;
    return h("button.room", { type: "button", "data-id": c.id, "aria-current": app.s.active === c.id ? "true" : "false" },
      app.avatarFor(c),
      h("div.body",
        h("div.rn", h("span", app.chatTitle(c)), c.unread ? h("span.badge", { "aria-label": `${c.unread} unread` }, String(c.unread)) : null),
        h("div.rp", { class: typing.length ? "typing" : "" }, prev)),
      h("div.rt", ts ? fmtRel(ts) : ""));
  }

  function render() {
    const a = app.s.account;
    meName.textContent = a.displayName || a.username;
    meSub.textContent = "@" + a.username;
    clear(meAv); meAv.appendChild(avatar(a.displayName || a.username, a.username));
    const q = app.s.search;
    const list = Array.from(app.s.chats.values())
      .filter((c) => !q || app.chatTitle(c).toLowerCase().includes(q) || c.members.some((u) => u.includes(q)))
      .sort((x, y) => (y.lastMessage?.sentAt ?? y.updatedAt) - (x.lastMessage?.sentAt ?? x.updatedAt));
    reconcile(rooms, list.map((c) => {
      const typing = (app.s.typing.get(c.id) ?? []).join(",");
      const ver = [app.s.active === c.id, c.unread, c.lastMessage?.sentAt, c.lastMessage?.body, app.chatTitle(c), typing, c.updatedAt].join("|");
      return { key: c.id, ver, make: () => roomRow(c) };
    }));
    empty.hidden = app.s.chats.size > 0;
    if (q && list.length === 0) { empty.hidden = false; empty.replaceChildren(h("p", "No chats match.")); }
    else if (!empty.hidden) empty.replaceChildren(h("p", h("strong", "No chats yet.")), h("p", "Add someone by their username to start a chat, or create a group."));
  }

  function renderConnection() {
    const st = app.s.connection;
    dot.className = "dot-live " + CONN_CLASS[st];
    connText.textContent = CONN_LABEL[st];
    connText.dataset.state = st;
  }
  renderConnection();
  return { render, renderConnection };
}
