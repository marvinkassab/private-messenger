/* App shell: owns the UI state, subscribes to Messenger events and mounts the
   sidebar and chat view. Every screen is driven by events; nothing polls. */

import type { Account, Chat, ChatId, Contact, ConnectionState, Message, Messenger, Username } from "../types";
import { $, h, clear, toast, errorText, avatar } from "./dom";
import { mountSidebar, type Sidebar } from "./sidebar";
import { mountChat, type ChatView } from "./chat";
import { showWelcome } from "./welcome";
import { showBackupIntro } from "./backupNudge";
import { showLock } from "./lock";
import { openSettings } from "./settings";
import { openDetails } from "./details";
import { openNewChat, openNewGroup } from "./newChat";

export type Theme = "auto" | "light" | "dark";
export const THEME_KEY = "pm.theme";

export interface ChatMessages { list: Message[]; hasMore: boolean; loading: boolean }

export interface State {
  account: Account;
  chats: Map<ChatId, Chat>;
  contacts: Map<Username, Contact>;
  msgs: Map<ChatId, ChatMessages>;
  typing: Map<ChatId, Username[]>;
  active: ChatId | null;
  connection: ConnectionState;
  search: string;
  replyTo: Message | null;
}

const PAGE = 60;

export function getTheme(): Theme {
  try { const t = localStorage.getItem(THEME_KEY); if (t === "light" || t === "dark") return t; } catch { /* blocked */ }
  return "auto";
}
export function setTheme(t: Theme) {
  document.documentElement.setAttribute("data-theme", t);
  try { localStorage.setItem(THEME_KEY, t); } catch { /* blocked */ }
  document.dispatchEvent(new CustomEvent("pm:theme", { detail: t }));
}

export class App {
  s!: State;
  root: HTMLElement;
  m: Messenger;
  sidebar!: Sidebar;
  chat!: ChatView;
  private seen = new Set<string>();       // message ids we already know (for notifications)
  private hidden = new Set<string>();     // ids deleted locally
  private bootAt = Date.now();
  private expiryTimer: ReturnType<typeof setTimeout> | null = null;
  private notifications = new Map<ChatId, Notification>();

  constructor(m: Messenger, root: HTMLElement) { this.m = m; this.root = root; }

  /* ---------- boot ---------- */
  async start() {
    document.documentElement.setAttribute("data-theme", getTheme());
    let init: { account: Account | null; locked: boolean };
    try { init = await this.m.init(); }
    catch (e) { this.fatal("Could not start", e); return; }
    let account = init.account;
    if (init.locked) {
      await showLock(this.root, this.m);
      account = this.m.account() ?? (await this.m.init()).account;
    }
    const isNewAccount = !account;
    if (!account) account = await showWelcome(this.root, this.m);
    this.s = {
      account, chats: new Map(), contacts: new Map(), msgs: new Map(), typing: new Map(),
      active: null, connection: this.m.connectionState(), search: "", replyTo: null,
    };
    await this.loadAll();
    this.mountShell();
    this.m.on((e) => this.onEvent(e));
    this.m.connect().catch((e) => toast("Could not connect: " + errorText(e), "error"));
    /* Explained at the cheapest possible moment: the account exists but holds
       nothing yet, so losing it now costs only a re-invite. */
    if (isNewAccount) await showBackupIntro(this.m);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && this.s.active) this.markReadIfVisible(this.s.active);
    });
  }

  private fatal(title: string, e: unknown) {
    clear(this.root);
    this.root.appendChild(h("div.screen", h("div.card", h("h2", title), h("p", errorText(e)),
      h("div.actions", h("button.btn.primary", { onclick: () => location.reload() }, "Reload")))));
  }

  private async loadAll() {
    const [chats, contacts] = await Promise.all([this.m.listChats(), this.m.listContacts()]);
    for (const c of chats) this.s.chats.set(c.id, c);
    for (const c of contacts) this.s.contacts.set(c.username, c);
  }

  private mountShell() {
    clear(this.root);
    document.body.classList.remove("in-room");
    const app = h("div.app");
    this.root.appendChild(app);
    this.sidebar = mountSidebar(this, app);
    this.chat = mountChat(this, app);
    this.sidebar.render();
    this.chat.render();
  }

  /* ---------- helpers ---------- */
  get me(): Username { return this.s.account.username; }

  nameOf(u: Username): string {
    if (u === this.me) return "You";
    const c = this.s.contacts.get(u);
    return c?.displayName || u;
  }
  chatTitle(c: Chat): string {
    if (c.kind === "direct") {
      const peer = this.s.contacts.get(c.members[0]);
      return peer?.displayName || c.title || c.members[0];
    }
    return c.group?.name || c.title;
  }
  peerOf(c: Chat): Contact | undefined { return c.kind === "direct" ? this.s.contacts.get(c.members[0]) : undefined; }
  avatarFor(c: Chat, cls?: string) { return avatar(this.chatTitle(c), c.id, cls); }

  preview(c: Chat): string {
    const lm = c.lastMessage;
    if (!lm) return c.kind === "group" ? "No messages yet" : "Say hello";
    const who = lm.sender === this.me ? "You: " : c.kind === "group" ? this.nameOf(lm.sender).split(" ")[0] + ": " : "";
    if (lm.kind === "system") return lm.body;
    if (lm.kind === "attachment") return who + (lm.body || "Attachment");
    return who + (lm.body || "Message deleted");
  }

  /* ---------- state changes ---------- */
  async openChat(id: ChatId | null) {
    this.s.active = id;
    this.s.replyTo = null;
    if (id) {
      document.body.classList.add("in-room");
      const n = this.notifications.get(id); if (n) { n.close(); this.notifications.delete(id); }
      if (!this.s.msgs.has(id)) await this.loadMessages(id);
      this.markReadIfVisible(id);
    } else {
      document.body.classList.remove("in-room");
    }
    this.sidebar.render();
    this.chat.render();
    this.chat.scrollToBottom();
    this.scheduleExpiry();
  }

  async loadMessages(id: ChatId, older = false) {
    const cur = this.s.msgs.get(id) ?? { list: [], hasMore: false, loading: false };
    this.s.msgs.set(id, cur);
    if (cur.loading) return;
    cur.loading = true;
    try {
      const before = older && cur.list.length ? cur.list[0].sentAt : undefined;
      const page = await this.m.getMessages(id, { before, limit: PAGE });
      const known = new Set(cur.list.map((m) => m.id));
      const fresh = page.filter((m) => !known.has(m.id) && !this.hidden.has(m.id) && !(m.expiresAt && m.expiresAt <= Date.now()));
      for (const m of fresh) this.seen.add(m.id);
      cur.list = [...fresh, ...cur.list].sort((a, b) => a.sentAt - b.sentAt);
      cur.hasMore = page.length >= PAGE;
    } catch (e) {
      toast("Could not load messages: " + errorText(e), "error");
    } finally { cur.loading = false; }
  }

  upsertMessage(m: Message): "new" | "updated" | "ignored" {
    if (this.hidden.has(m.id)) return "ignored";
    const cur = this.s.msgs.get(m.chatId);
    const isNew = !this.seen.has(m.id);
    this.seen.add(m.id);
    if (!cur) return isNew ? "new" : "ignored";
    const i = cur.list.findIndex((x) => x.id === m.id);
    if (m.expiresAt && m.expiresAt <= Date.now()) { if (i >= 0) cur.list.splice(i, 1); return "ignored"; }
    if (i >= 0) { cur.list[i] = m; return "updated"; }
    let at = cur.list.length;
    while (at > 0 && cur.list[at - 1].sentAt > m.sentAt) at--;
    cur.list.splice(at, 0, m);
    return "new";
  }

  removeMessage(id: string, chatId: ChatId) {
    this.hidden.add(id);
    const cur = this.s.msgs.get(chatId);
    if (cur) cur.list = cur.list.filter((m) => m.id !== id);
  }

  markReadIfVisible(id: ChatId) {
    if (document.hidden) return;
    const c = this.s.chats.get(id);
    if (c && c.unread > 0) { c.unread = 0; this.sidebar.render(); }
    this.m.markRead(id).catch(() => { /* not fatal */ });
  }

  /* Drops messages whose expiry has passed and re-arms for the next one. */
  scheduleExpiry() {
    if (this.expiryTimer) clearTimeout(this.expiryTimer);
    this.expiryTimer = null;
    const cur = this.s.active ? this.s.msgs.get(this.s.active) : null;
    if (!cur) return;
    const now = Date.now();
    let next = Infinity, changed = false;
    cur.list = cur.list.filter((m) => {
      if (!m.expiresAt) return true;
      if (m.expiresAt <= now) { changed = true; return false; }
      next = Math.min(next, m.expiresAt);
      return true;
    });
    if (changed) this.chat.renderMessages();
    if (next < Infinity) this.expiryTimer = setTimeout(() => this.scheduleExpiry(), Math.min(next - now + 50, 2 ** 31 - 1));
  }

  /* ---------- Messenger events ---------- */
  private onEvent(e: Parameters<Parameters<Messenger["on"]>[0]>[0]) {
    switch (e.type) {
      case "connection":
        this.s.connection = e.state;
        this.sidebar.renderConnection();
        break;
      case "chat": {
        const prev = this.s.chats.get(e.chat.id);
        this.s.chats.set(e.chat.id, { ...e.chat, typing: e.chat.typing ?? prev?.typing });
        if (e.chat.typing) this.s.typing.set(e.chat.id, e.chat.typing);
        this.sidebar.render();
        if (this.s.active === e.chat.id) {
          this.chat.renderHead();
          if (e.chat.unread > 0 && !document.hidden) this.markReadIfVisible(e.chat.id);
        }
        break;
      }
      case "contact":
        this.s.contacts.set(e.contact.username, e.contact);
        this.sidebar.render();
        if (this.s.active === "u:" + e.contact.username) this.chat.renderHead();
        document.dispatchEvent(new CustomEvent("pm:contact", { detail: e.contact }));
        break;
      case "typing":
        this.s.typing.set(e.chatId, e.users.filter((u) => u !== this.me));
        this.sidebar.render();
        if (this.s.active === e.chatId) this.chat.renderTyping();
        break;
      case "message": {
        const m = e.message;
        const fresh = !this.seen.has(m.id);
        const r = this.upsertMessage(m);
        if (this.s.active === m.chatId) {
          this.chat.renderMessages({ stick: r === "new" && m.mine });
          if (r === "new" && !m.mine) this.markReadIfVisible(m.chatId);
          if (m.expiresAt) this.scheduleExpiry();
        }
        if (fresh && !m.mine && m.kind !== "system" && !m.deleted && m.receivedAt > this.bootAt - 5000) this.notify(m);
        break;
      }
      case "error":
        toast(e.message, "error");
        break;
    }
  }

  /* Browser notification for a new message while the tab is hidden. Text is
     built locally; nothing about the message ever leaves the device. */
  private notify(m: Message) {
    if (!document.hidden || typeof Notification === "undefined" || Notification.permission !== "granted") return;
    const chat = this.s.chats.get(m.chatId);
    const title = chat ? (chat.kind === "group" ? `${this.nameOf(m.sender)} in ${this.chatTitle(chat)}` : this.chatTitle(chat)) : this.nameOf(m.sender);
    const body = m.kind === "attachment" ? (m.body || "Sent an attachment") : m.body;
    try {
      const n = new Notification(title, { body, tag: m.chatId, icon: "/icons/icon.svg" });
      n.onclick = () => { window.focus(); this.openChat(m.chatId); n.close(); };
      this.notifications.get(m.chatId)?.close();
      this.notifications.set(m.chatId, n);
    } catch { /* e.g. no SW-less notifications on Android Chrome */ }
  }

  /* ---------- dialogs ---------- */
  openSettings() { openSettings(this); }
  openDetails() { if (this.s.active) openDetails(this, this.s.active); }
  openNewChat() { openNewChat(this); }
  openNewGroup() { openNewGroup(this); }
}

export async function bootApp(m: Messenger, root = $("#app")!) {
  const app = new App(m, root);
  (window as any).__pm = app;   // handy in devtools and UI tests
  await app.start();
  return app;
}
