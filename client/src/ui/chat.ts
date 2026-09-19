/* Chat view: header, message list (bubbles, day separators, system lines,
   reactions, reply quotes, attachments), typing indicator, reply bar and
   composer. Everything here is driven by App's state; nothing polls. */

import type { Chat, Message } from "../types";
import type { App, ChatMessages } from "./app";
import {
  h, clear, toast, errorText, copyText, reconcile, linkify, fmtTime, fmtDay, dayKey,
  fmtBytes, describeSecondsShort, finePointer,
} from "./dom";
import { icon, type IconName } from "./icons";

export interface ChatView {
  render(): void;
  renderHead(): void;
  renderMessages(opts?: { stick?: boolean }): void;
  renderTyping(): void;
  scrollToBottom(): void;
}

const MENU_REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🙏"];
const CONT_WINDOW = 5 * 60_000;

/* Downloaded attachment blobs, cached by message id for the life of the tab. */
const imgCache = new Map<string, string>();

function statusLabel(s: Message["status"]): string {
  return {
    pending: "Sending…", sent: "Sent", delivered: "Delivered",
    read: "Read", failed: "Not delivered — tap to retry",
  }[s];
}

function fmtUntil(ms: number): string {
  const s = Math.max(0, (ms - Date.now()) / 1000);
  if (s < 60) return Math.ceil(s) + "s";
  if (s < 3600) return Math.ceil(s / 60) + "m";
  if (s < 86400) return Math.ceil(s / 3600) + "h";
  return Math.ceil(s / 86400) + "d";
}

export function mountChat(app: App, parent: HTMLElement): ChatView {
  let activeMenuClose: (() => void) | null = null;
  const closeAnyMenu = () => { activeMenuClose?.(); activeMenuClose = null; };

  /* ---------- empty state ---------- */
  const emptyEl = h("div.chat-empty", { "data-test": "chat-empty" },
    h("div",
      h("h3", "Select a chat"),
      h("p", "Choose a conversation from the list, or start a new one."),
      h("div.row",
        h("button.btn.primary", { type: "button", onclick: () => app.openNewChat() }, icon("plus"), "New chat"),
        h("button.btn", { type: "button", onclick: () => app.openNewGroup() }, icon("users"), "New group"))));

  /* ---------- header ---------- */
  const backBtn = h("button.btn.icon#btn-back", { type: "button", "aria-label": "Back", onclick: () => app.openChat(null) }, icon("back"));
  const headAvatar = h("div");
  const headTitle = h("h2", { "data-test": "chat-title" });
  const headStatus = h("div.status");
  const detailsBtn = h("button.btn.icon", { type: "button", "aria-label": "Chat details", "data-test": "details-btn", onclick: () => app.openDetails() }, icon("shield"));
  const head = h("header.chat-head", backBtn, headAvatar, h("div.title", headTitle, headStatus), detailsBtn);

  const identityBanner = h("div.banner.warn", { hidden: true, "data-test": "identity-banner" });
  const readonlyBanner = h("div.banner.info", { hidden: true, "data-test": "readonly-banner" });

  /* ---------- messages ---------- */
  const msgsEl = h("div.msgs", { "data-test": "messages" });
  const typingLine = h("div.typing-line", { hidden: true, "data-test": "typing-indicator" },
    h("div.dots", h("i"), h("i"), h("i")), h("span"));

  /* ---------- reply bar ---------- */
  const replyQuote = h("div.quote");
  const replyBar = h("div.reply-bar", { hidden: true, "data-test": "reply-bar" }, replyQuote,
    h("button.btn.icon.ghost", { type: "button", "aria-label": "Cancel reply", onclick: () => { app.s.replyTo = null; renderReplyBar(); } }, icon("x")));

  /* ---------- composer ---------- */
  let typingTimer: ReturnType<typeof setTimeout> | null = null;
  const fileInput = h("input", {
    type: "file", hidden: true, "data-test": "attach-input",
    onchange: async (e: Event) => {
      const input = e.target as HTMLInputElement;
      const file = input.files?.[0];
      input.value = "";
      if (!file || !app.s.active) return;
      try { await app.m.sendAttachment(app.s.active, file, { name: file.name }); }
      catch (err) { toast("Could not send file: " + errorText(err), "error"); }
    },
  });
  const attachBtn = h("button.btn.icon", { type: "button", "aria-label": "Attach file", "data-test": "attach-btn", onclick: () => fileInput.click() }, icon("clip"));
  const textarea = h("textarea", {
    rows: 1, placeholder: "Message", "aria-label": "Message", "data-test": "composer-input",
    oninput: onComposerInput, onkeydown: onComposerKeydown,
  });
  const sendBtn = h("button.btn.icon.primary", { type: "button", "aria-label": "Send", "data-test": "send-btn", onclick: () => sendCurrent() }, icon("send"));
  const composer = h("div.composer", attachBtn, fileInput, textarea, sendBtn);

  function onComposerInput() {
    textarea.style.height = "auto";
    textarea.style.height = Math.min(140, textarea.scrollHeight) + "px";
    const id = app.s.active;
    if (!id) return;
    app.m.setTyping(id, true);
    if (typingTimer) clearTimeout(typingTimer);
    typingTimer = setTimeout(() => { if (app.s.active) app.m.setTyping(app.s.active, false); }, 3000);
  }
  function onComposerKeydown(e: KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey && finePointer()) { e.preventDefault(); sendCurrent(); }
  }
  async function sendCurrent() {
    const id = app.s.active;
    if (!id) return;
    const text = textarea.value.trim();
    if (!text) return;
    const replyTo = app.s.replyTo?.id;
    textarea.value = ""; textarea.style.height = "auto";
    app.s.replyTo = null; renderReplyBar();
    if (typingTimer) { clearTimeout(typingTimer); typingTimer = null; }
    app.m.setTyping(id, false);
    sendBtn.disabled = true;
    try { await app.m.sendText(id, text, { replyTo }); }
    catch (err) { toast("Could not send: " + errorText(err), "error"); textarea.value = text; }
    finally { sendBtn.disabled = false; textarea.focus(); }
  }

  const chatShell = h("div.chat-inner", head, identityBanner, readonlyBanner, msgsEl, typingLine, replyBar, composer);
  chatShell.hidden = true;
  const root = h("section.chat", emptyEl, chatShell);
  const dropOverlay = h("div.drop-overlay", { hidden: true }, "Drop to send");
  root.appendChild(dropOverlay);
  parent.appendChild(root);

  /* drag and drop attach */
  let dragDepth = 0;
  root.addEventListener("dragover", (e) => e.preventDefault());
  root.addEventListener("dragenter", (e) => {
    e.preventDefault();
    if (!app.s.active) return;
    dragDepth++; dropOverlay.hidden = false;
  });
  root.addEventListener("dragleave", () => { dragDepth = Math.max(0, dragDepth - 1); if (dragDepth === 0) dropOverlay.hidden = true; });
  root.addEventListener("drop", async (e) => {
    e.preventDefault();
    dragDepth = 0; dropOverlay.hidden = true;
    const file = e.dataTransfer?.files?.[0];
    if (file && app.s.active) {
      try { await app.m.sendAttachment(app.s.active, file, { name: file.name }); }
      catch (err) { toast("Could not send file: " + errorText(err), "error"); }
    }
  });

  /* ---------- attachments ---------- */
  async function attachmentUrl(m: Message): Promise<string | null> {
    if (imgCache.has(m.id)) return imgCache.get(m.id)!;
    try {
      const blob = await app.m.downloadAttachment(m.id);
      const url = URL.createObjectURL(blob);
      imgCache.set(m.id, url);
      return url;
    } catch { return null; }
  }
  function openViewer(url: string) {
    const dlg = h("dialog#viewer");
    dlg.appendChild(h("img", { src: url, alt: "" }));
    dlg.addEventListener("click", () => dlg.close());
    dlg.addEventListener("close", () => dlg.remove());
    document.body.appendChild(dlg);
    dlg.showModal();
  }
  async function downloadAttachment(m: Message) {
    try {
      const blob = await app.m.downloadAttachment(m.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = m.attachment?.name || "file";
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 30_000);
    } catch (e) { toast("Could not download: " + errorText(e), "error"); }
  }

  /* ---------- message menu (reactions + actions) ---------- */
  function openMessageMenu(m: Message, anchor: HTMLElement) {
    closeAnyMenu();
    const menu = h("div.menu", { "data-test": "msg-menu" });
    const emojiRow = h("div.emojis");
    for (const emoji of MENU_REACTIONS) {
      const mine = (m.reactions[emoji] || []).includes(app.me);
      emojiRow.appendChild(h("button", {
        type: "button", class: mine ? "on" : "", "data-test": "react-btn", "data-emoji": emoji,
        onclick: () => { app.m.react(m.id, emoji).catch((e) => toast("Could not react: " + errorText(e), "error")); close(); },
      }, emoji));
    }
    menu.appendChild(emojiRow);
    if (!m.deleted) {
      menu.appendChild(h("button.item", {
        type: "button", "data-test": "menu-reply",
        onclick: () => { app.s.replyTo = m; renderReplyBar(); textarea.focus(); close(); },
      }, icon("reply"), "Reply"));
      if (m.kind === "text" && m.body) {
        menu.appendChild(h("button.item", {
          type: "button", "data-test": "menu-copy",
          onclick: async () => { await copyText(m.body); toast("Copied"); close(); },
        }, icon("copy"), "Copy"));
      }
    }
    menu.appendChild(h("button.item.danger", {
      type: "button", "data-test": "menu-delete-me",
      onclick: async () => { close(); try { await app.m.deleteLocally(m.id); } catch (e) { toast(errorText(e), "error"); } },
    }, icon("trash"), "Delete for me"));
    if (m.mine && !m.deleted) {
      menu.appendChild(h("button.item.danger", {
        type: "button", "data-test": "menu-delete-everyone",
        onclick: async () => { close(); try { await app.m.deleteForEveryone(m.id); } catch (e) { toast(errorText(e), "error"); } },
      }, icon("trash"), "Delete for everyone"));
    }
    document.body.appendChild(menu);
    positionMenu(menu, anchor);
    const onDoc = (e: MouseEvent) => { if (!menu.contains(e.target as Node)) close(); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") close(); };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    function close() {
      menu.remove();
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
      if (activeMenuClose === close) activeMenuClose = null;
    }
    activeMenuClose = close;
  }
  function positionMenu(menu: HTMLElement, anchor: HTMLElement) {
    const r = anchor.getBoundingClientRect();
    const mw = menu.offsetWidth || 220, mh = menu.offsetHeight || 260;
    let left = Math.min(r.left, window.innerWidth - mw - 8);
    let top = r.bottom + 6;
    if (top + mh > window.innerHeight - 8) top = Math.max(8, r.top - mh - 6);
    menu.style.left = Math.max(8, left) + "px";
    menu.style.top = Math.max(8, top) + "px";
  }

  /* ---------- row builders ---------- */
  function makeQuote(chat: Chat, replyToId: string): HTMLElement {
    const cur = app.s.msgs.get(chat.id);
    const orig = cur?.list.find((x) => x.id === replyToId);
    const name = orig ? app.nameOf(orig.sender) : "";
    const text = !orig ? "Original message" : orig.deleted ? "Message deleted" : orig.kind === "attachment" ? (orig.body || "Attachment") : orig.body;
    return h("div.quote", name ? h("span.qn", name) : null, text);
  }

  function appendImageContent(m: Message, bubble: HTMLElement) {
    bubble.classList.add("img");
    const att = m.attachment!;
    // The placeholder and the loaded image carry different test hooks, so a
    // test that waits for the image cannot be satisfied by "Loading image…".
    const ph = h("div.ph", { "data-test": "attachment-loading" }, "Loading image…");
    bubble.appendChild(ph);
    attachmentUrl(m).then((url) => {
      if (!url) { ph.textContent = "Could not load image"; return; }
      const img = h("img", {
        src: url,
        alt: att.caption || att.name || "Photo",
        loading: "lazy",
        "data-test": "attachment-image",
        onclick: () => openViewer(url),
      });
      ph.replaceWith(img);
    });
  }
  function appendFileCard(m: Message, bubble: HTMLElement) {
    const att = m.attachment!;
    bubble.appendChild(h("a.file-card", {
      href: "#", "data-test": "attachment-file",
      onclick: (e: Event) => { e.preventDefault(); downloadAttachment(m); },
    }, h("div.fi", icon("file")), h("div", h("div.fn", att.name || "File"), h("div.fs", fmtBytes(att.size)))));
  }

  function makeMeta(m: Message): HTMLElement {
    const meta = h("div.meta");
    meta.appendChild(h("span.time", fmtTime(m.sentAt)));
    if (m.mine) {
      const ic: IconName = m.status === "pending" ? "clock" : m.status === "sent" ? "check" : m.status === "failed" ? "alert" : "checks";
      const st = h("span.st", {
        class: m.status === "read" ? "read" : m.status === "failed" ? "failed" : "",
        title: statusLabel(m.status), "data-test": "msg-status", "data-status": m.status,
      }, icon(ic));
      if (m.status === "failed") st.addEventListener("click", () => app.m.retry(m.id).catch((e) => toast("Could not retry: " + errorText(e), "error")));
      meta.appendChild(st);
    }
    if (m.expiresAt) meta.appendChild(h("span.exp", { title: "Disappears in " + fmtUntil(m.expiresAt) }, icon("timer")));
    return meta;
  }

  function makeReacts(m: Message): HTMLElement {
    const wrap = h("div.reacts");
    for (const [emoji, who] of Object.entries(m.reactions)) {
      if (!who.length) continue;
      const mine = who.includes(app.me);
      wrap.appendChild(h("button.react" + (mine ? ".mine" : ""), {
        type: "button", "data-test": "reaction", "data-emoji": emoji, title: who.map((u) => app.nameOf(u)).join(", "),
        onclick: () => app.m.react(m.id, emoji).catch((e) => toast("Could not react: " + errorText(e), "error")),
      }, emoji, h("span", String(who.length))));
    }
    return wrap;
  }

  function makeSystemRow(m: Message): HTMLElement {
    return h("div.sys", { "data-test": "system-line" }, m.body);
  }

  function makeMessageRow(chat: Chat, m: Message, cont: boolean): HTMLElement {
    const row = h("div.row");
    const bubble = h("div.bubble" + (m.deleted ? ".deleted" : ""), { "data-test": "message-bubble" });
    if (m.deleted) {
      bubble.textContent = "Message deleted";
    } else {
      if (m.replyTo) bubble.appendChild(makeQuote(chat, m.replyTo));
      if (m.kind === "attachment" && m.attachment) {
        if (m.attachment.mime.startsWith("image/")) appendImageContent(m, bubble);
        else appendFileCard(m, bubble);
        if (m.attachment.caption) bubble.appendChild(h("div.cap", ...linkify(m.attachment.caption)));
      } else {
        bubble.append(...linkify(m.body));
      }
    }
    const more = h("button.btn.icon.more", { type: "button", "aria-label": "Message actions", "data-test": "msg-actions", onclick: (e: Event) => openMessageMenu(m, e.currentTarget as HTMLElement) }, icon("more"));
    row.append(bubble, more);

    const wrap = h("div.msg" + (m.mine ? ".me" : "") + (cont ? ".cont" : ""), {
      "data-test": "message", "data-id": m.id, "data-status": m.status, "data-mine": String(m.mine),
    });
    if (!m.mine && !cont && chat.kind === "group") wrap.appendChild(h("div.who", app.nameOf(m.sender)));
    wrap.appendChild(row);
    if (!m.deleted && Object.values(m.reactions).some((w) => w.length)) wrap.appendChild(makeReacts(m));
    if (!m.deleted) wrap.appendChild(makeMeta(m));
    return wrap;
  }

  function buildRows(chat: Chat, cur: ChatMessages): { key: string; ver: string; make: () => HTMLElement }[] {
    const rows: { key: string; ver: string; make: () => HTMLElement }[] = [];
    if (cur.hasMore) {
      rows.push({
        key: "__older", ver: String(cur.loading),
        make: () => h("button.btn.sm.older", {
          type: "button", disabled: cur.loading, "data-test": "load-older-btn",
          onclick: () => app.loadMessages(chat.id, true).then(() => renderMessages()),
        }, cur.loading ? "Loading…" : "Load earlier messages"),
      });
    }
    let lastDay = "", lastSender: string | null = null, lastTs = 0;
    for (const m of cur.list) {
      const dk = dayKey(m.sentAt);
      if (dk !== lastDay) {
        rows.push({ key: "day:" + dk, ver: dk, make: () => h("div.day", fmtDay(m.sentAt)) });
        lastDay = dk; lastSender = null;
      }
      if (m.kind === "system") {
        rows.push({ key: m.id, ver: m.body, make: () => makeSystemRow(m) });
        lastSender = null;
        continue;
      }
      const cont = lastSender === m.sender && (m.sentAt - lastTs) < CONT_WINDOW;
      const ver = [m.status, JSON.stringify(m.reactions), m.deleted, m.body, m.attachment?.id, m.replyTo, cont, m.expiresAt].join("|");
      rows.push({ key: m.id, ver, make: () => makeMessageRow(chat, m, cont) });
      lastSender = m.sender; lastTs = m.sentAt;
    }
    return rows;
  }

  function isNearBottom(): boolean { return msgsEl.scrollHeight - msgsEl.scrollTop - msgsEl.clientHeight < 120; }
  function scrollToBottom() { msgsEl.scrollTop = msgsEl.scrollHeight; }

  function renderMessages(opts: { stick?: boolean } = {}) {
    const id = app.s.active;
    if (!id) return;
    const chat = app.s.chats.get(id);
    if (!chat) return;
    closeAnyMenu();
    const nearBottom = isNearBottom();
    const cur = app.s.msgs.get(id) ?? { list: [], hasMore: false, loading: false };
    reconcile(msgsEl, buildRows(chat, cur));
    if (opts.stick || nearBottom) scrollToBottom();
  }

  function renderStatusLine(chat: Chat) {
    clear(headStatus);
    const typing = app.s.typing.get(chat.id) ?? [];
    if (typing.length) {
      const label = chat.kind === "group"
        ? typing.map((u) => app.nameOf(u).split(" ")[0]).join(", ") + (typing.length > 1 ? " are typing…" : " is typing…")
        : "typing…";
      headStatus.appendChild(h("span.typing", label));
    } else if (chat.kind === "group") {
      headStatus.appendChild(h("span", `${chat.group?.members.length ?? chat.members.length} members`));
    } else {
      const peer = app.peerOf(chat);
      headStatus.appendChild(h("span", peer?.verified ? "Verified" : "@" + chat.members[0]));
    }
    if (chat.disappearSeconds > 0) headStatus.appendChild(h("span.chip", { "data-test": "disappear-chip" }, icon("timer"), describeSecondsShort(chat.disappearSeconds)));
  }

  function renderBanners(chat: Chat) {
    const peer = app.peerOf(chat);
    if (peer?.identityChanged) {
      identityBanner.hidden = false;
      clear(identityBanner);
      identityBanner.append(
        h("div", h("strong", "Safety number changed"), h("div", `${app.nameOf(peer.username)}'s safety number changed. Verify before sending.`)),
        h("button.btn.sm", {
          type: "button", "data-test": "accept-identity-btn",
          onclick: async () => { try { await app.m.acceptIdentityChange(peer.username); toast("Safety number accepted"); } catch (e) { toast(errorText(e), "error"); } },
        }, "Accept new safety number"));
    } else identityBanner.hidden = true;

    if (chat.group?.leftOrRemoved) {
      readonlyBanner.hidden = false;
      clear(readonlyBanner);
      readonlyBanner.appendChild(h("div", "You are no longer a member of this group."));
    } else readonlyBanner.hidden = true;
  }

  function updateComposerState(chat: Chat | undefined) {
    const peer = chat ? app.peerOf(chat) : undefined;
    const blocked = !chat || !!chat.group?.leftOrRemoved || !!peer?.identityChanged;
    textarea.disabled = blocked; sendBtn.disabled = blocked; attachBtn.disabled = blocked;
    composer.hidden = !!chat?.group?.leftOrRemoved;
  }

  function renderReplyBar() {
    const r = app.s.replyTo;
    replyBar.hidden = !r;
    if (r) {
      clear(replyQuote);
      replyQuote.appendChild(h("span.qn", app.nameOf(r.sender)));
      replyQuote.append(r.deleted ? "Message deleted" : r.kind === "attachment" ? (r.body || "Attachment") : r.body);
    }
  }

  function renderHead() {
    const id = app.s.active;
    const chat = id ? app.s.chats.get(id) : undefined;
    if (!chat) return;
    clear(headAvatar); headAvatar.appendChild(app.avatarFor(chat));
    headTitle.textContent = app.chatTitle(chat);
    renderStatusLine(chat);
    renderBanners(chat);
    updateComposerState(chat);
  }

  function renderTyping() {
    const id = app.s.active;
    const chat = id ? app.s.chats.get(id) : undefined;
    const typing = id ? (app.s.typing.get(id) ?? []) : [];
    if (!id || !chat) return;
    renderStatusLine(chat);
    if (!typing.length) { typingLine.hidden = true; return; }
    typingLine.hidden = false;
    const label = chat.kind === "group"
      ? typing.map((u) => app.nameOf(u)).join(", ") + (typing.length > 1 ? " are typing…" : " is typing…")
      : app.nameOf(typing[0]) + " is typing…";
    (typingLine.querySelector("span") as HTMLElement).textContent = label;
  }

  function render() {
    const id = app.s.active;
    const chat = id ? app.s.chats.get(id) : undefined;
    if (!chat) { chatShell.hidden = true; emptyEl.hidden = false; return; }
    emptyEl.hidden = true; chatShell.hidden = false;
    renderHead();
    renderMessages();
    renderTyping();
    renderReplyBar();
  }

  return { render, renderHead, renderMessages, renderTyping, scrollToBottom };
}
