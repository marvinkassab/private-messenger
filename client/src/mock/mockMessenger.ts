/* In-memory Messenger for development and UI tests.
   Simulates the peers: after you send a text they mark it delivered, start
   typing, mark it read and reply. Nothing here touches the network or
   IndexedDB; a reload starts over (the account and lock passphrase survive in
   sessionStorage so a reload during development lands you back in the app).

   Mock-only commands you can type in a chat, handy for exercising rare UI:
     /fail       the message fails to send (tap it to retry)
     /identity   the peer's identity key "changes" (direct chats)
     /remove     an admin removes you from the group
     /silence    the peer does not reply */

import type {
  Account, Chat, ChatId, Contact, Message, Messenger, MessengerEvent, SafetyNumber, Username,
  ConnectionState, AttachmentMeta, GroupState,
} from "../types";

const SESSION_KEY = "pm.mock.account";
const LOCK_KEY = "pm.mock.lock";

const REPLIES = [
  "Sounds good!",
  "Ha, nice.",
  "Let me check and get back to you.",
  "On it.",
  "Perfect, see you then.",
  "Can you send that as a file?",
  "Got it, thanks for letting me know.",
  "Same here. Long week.",
];
const REACTIONS = ["👍", "❤️", "😂", "😮"];

function hex(n: number): string {
  const b = crypto.getRandomValues(new Uint8Array(n));
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}
const newId = () => hex(16);
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function fakeKey(seed: string): string {
  // deterministic 33-byte "identity key", base64
  let h = 2166136261;
  const out = new Uint8Array(33);
  for (let i = 0; i < 33; i++) {
    for (const c of seed + i) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
    out[i] = h & 0xff;
  }
  out[0] = 5;
  return btoa(String.fromCharCode(...out));
}

function safetyDigits(a: string, b: string): string {
  const [x, y] = [a, b].sort();
  let h = 0x811c9dc5;
  for (const c of `${x}|${y}|pm-mock`) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0;
  let s = "";
  while (s.length < 60) {
    h = (Math.imul(h, 1103515245) + 12345) >>> 0;
    s += String((h >>> 8) % 100000).padStart(5, "0");
  }
  return s.slice(0, 60);
}

interface Seed {
  contacts: Contact[];
  chats: Chat[];
  messages: Message[];
  blobs: Map<string, Blob>;
}

function svgImage(w: number, h: number, hue: number, label: string): Blob {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="hsl(${hue},70%,55%)"/><stop offset="1" stop-color="hsl(${hue + 60},70%,35%)"/></linearGradient></defs>
<rect width="${w}" height="${h}" fill="url(#g)"/>
<circle cx="${w * 0.72}" cy="${h * 0.3}" r="${h * 0.12}" fill="#fff8" />
<path d="M0 ${h * 0.8} Q ${w * 0.3} ${h * 0.55} ${w * 0.55} ${h * 0.75} T ${w} ${h * 0.6} V ${h} H 0 Z" fill="#0004"/>
<text x="16" y="${h - 18}" font-family="system-ui,sans-serif" font-size="20" fill="#fff">${label}</text></svg>`;
  return new Blob([svg], { type: "image/svg+xml" });
}

function seed(me: Username): Seed {
  const now = Date.now();
  const H = 3600_000, D = 24 * H;
  const contacts: Contact[] = [
    { username: "alice", displayName: "Alice Nguyen", identityKeyB64: fakeKey("alice"), verified: true, addedAt: now - 40 * D, hasDeliveryToken: true },
    { username: "bob", displayName: "Bob Okafor", identityKeyB64: fakeKey("bob"), verified: false, addedAt: now - 30 * D, hasDeliveryToken: true },
    { username: "carol", displayName: "Carol Weiss", identityKeyB64: fakeKey("carol"), verified: false, addedAt: now - 12 * D, hasDeliveryToken: true },
  ];
  const blobs = new Map<string, Blob>();
  const messages: Message[] = [];
  const mk = (chatId: ChatId, sender: Username, sentAt: number, body: string, extra: Partial<Message> = {}): Message => {
    const m: Message = {
      id: newId(), chatId, sender, mine: sender === me, sentAt, receivedAt: sentAt + 300,
      kind: "text", body, reactions: {}, status: sender === me ? "read" : "delivered", ...extra,
    };
    messages.push(m);
    return m;
  };

  // alice
  const a = "u:alice";
  mk(a, "alice", now - 3 * D - 5 * H, "Hey! Finally on here. This is so much nicer than the old app.");
  mk(a, me, now - 3 * D - 4.9 * H, "Welcome! Took you long enough 😄");
  mk(a, "alice", now - 3 * D - 4.8 * H, "I know, I know. Are we still on for Saturday?");
  const q1 = mk(a, me, now - 3 * D - 4.7 * H, "Yes. 10am at the trailhead, bring water.");
  mk(a, "alice", now - 3 * D - 4.6 * H, "Deal.", { reactions: { "👍": [me] } });
  const photoId = newId();
  blobs.set(photoId, svgImage(1200, 800, 200, "Trailhead, last spring"));
  mk(a, "alice", now - 1 * D - 2 * H, "Look what I found from last time", {
    kind: "attachment",
    attachment: { id: photoId, mime: "image/svg+xml", size: 1900, name: "trailhead.svg", width: 1200, height: 800, caption: "Look what I found from last time" },
    reactions: { "❤️": [me] },
  });
  mk(a, me, now - 1 * D - 1.9 * H, "Oh that was a good day", { replyTo: q1.id });
  mk(a, "alice", now - 25 * 60_000, "Running 10 minutes late tomorrow, sorry!");

  // bob
  const b = "u:bob";
  mk(b, "bob", now - 6 * D, "Sent you the numbers for the quarterly thing.");
  const pdfId = newId();
  blobs.set(pdfId, new Blob(["%PDF-1.4\n% mock itinerary\n"], { type: "application/pdf" }));
  mk(b, "bob", now - 6 * D + 60_000, "", {
    kind: "attachment",
    attachment: { id: pdfId, mime: "application/pdf", size: 48213, name: "itinerary-draft.pdf" },
  });
  mk(b, me, now - 6 * D + 5 * 60_000, "Thanks, I'll read it tonight.");
  mk(b, "bob", now - 2 * H, "Any thoughts on the draft?");
  mk(b, "bob", now - 2 * H + 30_000, "No rush, just curious.");

  // group
  const gid = hex(8);
  const g = "g:" + gid;
  mk(g, me, now - 5 * D, "You created the group", { kind: "system", status: "sent" });
  mk(g, "carol", now - 5 * D + 2 * 60_000, "Ooh, a group. What are we planning?");
  mk(g, me, now - 5 * D + 3 * 60_000, "Cabin weekend, first week of October. Who is in?");
  mk(g, "alice", now - 5 * D + 4 * 60_000, "In!", { reactions: { "🙏": ["carol", "bob"] } });
  mk(g, "bob", now - 5 * D + 6 * 60_000, "In, if I can bring the dog.");
  mk(g, "carol", now - 5 * D + 7 * 60_000, "The dog is the main reason I'm coming.", { reactions: { "😂": [me, "alice"] } });
  mk(g, "alice", now - 4 * H, "I made a shared list for food. Add what you want.");
  mk(g, "carol", now - 3.5 * H, "Added marshmallows. Non-negotiable.");

  const last = (chatId: ChatId) => {
    const ms = messages.filter((m) => m.chatId === chatId);
    const m = ms[ms.length - 1];
    return { body: m.body, sentAt: m.sentAt, sender: m.sender, kind: m.kind };
  };
  const group: GroupState = { id: gid, name: "Cabin weekend", creator: me, admins: [me], members: [me, "alice", "bob", "carol"], revision: 1 };
  const chats: Chat[] = [
    { id: a, kind: "direct", title: "Alice Nguyen", members: ["alice"], lastMessage: last(a), unread: 1, disappearSeconds: 0, updatedAt: now - 25 * 60_000 },
    { id: b, kind: "direct", title: "Bob Okafor", members: ["bob"], lastMessage: last(b), unread: 2, disappearSeconds: 0, updatedAt: now - 2 * H + 30_000 },
    { id: g, kind: "group", title: "Cabin weekend", members: group.members, group, lastMessage: last(g), unread: 0, disappearSeconds: 7 * 86400, updatedAt: now - 3.5 * H },
  ];
  return { contacts, chats, messages, blobs };
}

export function createMockMessenger(): Messenger {
  let account: Account | null = null;
  let locked = false;
  let lockPass: string | null = null;
  let state: ConnectionState = "offline";
  let push = false;
  const handlers = new Set<(e: MessengerEvent) => void>();
  const contacts = new Map<Username, Contact>();
  const chats = new Map<ChatId, Chat>();
  const messages = new Map<string, Message>();
  const blobs = new Map<string, Blob>();
  const typingTimers = new Map<ChatId, ReturnType<typeof setTimeout>>();
  let sendCounter = 0;
  const appUrl = typeof location !== "undefined" ? location.origin + location.pathname : "https://example.test/";

  const emit = (e: MessengerEvent) => { for (const h of Array.from(handlers)) { try { h(e); } catch (err) { console.error(err); } } };
  const me = () => account!.username;
  const chatMessages = (chatId: ChatId) => Array.from(messages.values()).filter((m) => m.chatId === chatId).sort((a, b) => a.sentAt - b.sentAt);

  function loadSeed(username: Username) {
    const s = seed(username);
    for (const c of s.contacts) contacts.set(c.username, c);
    for (const c of s.chats) chats.set(c.id, c);
    for (const m of s.messages) messages.set(m.id, m);
    for (const [k, v] of s.blobs) blobs.set(k, v);
  }

  function touchChat(chatId: ChatId, m: Message, unreadDelta = 0) {
    const c = chats.get(chatId);
    if (!c) return;
    c.lastMessage = { body: m.body, sentAt: m.sentAt, sender: m.sender, kind: m.kind };
    c.updatedAt = Math.max(c.updatedAt, m.sentAt);
    c.unread = Math.max(0, c.unread + unreadDelta);
    emit({ type: "chat", chat: { ...c } });
  }

  function store(m: Message) { messages.set(m.id, m); emit({ type: "message", message: { ...m } }); }

  function systemLine(chatId: ChatId, body: string) {
    const m: Message = { id: newId(), chatId, sender: me(), mine: true, sentAt: Date.now(), receivedAt: Date.now(), kind: "system", body, reactions: {}, status: "sent" };
    store(m);
    touchChat(chatId, m);
  }

  function setTypingUsers(chatId: ChatId, users: Username[]) {
    const c = chats.get(chatId);
    if (c) c.typing = users;
    emit({ type: "typing", chatId, users });
  }

  function incoming(chatId: ChatId, sender: Username, body: string, extra: Partial<Message> = {}) {
    const c = chats.get(chatId);
    const now = Date.now();
    const m: Message = {
      id: newId(), chatId, sender, mine: false, sentAt: now, receivedAt: now, kind: "text", body, reactions: {}, status: "delivered", ...extra,
    };
    if (c && c.disappearSeconds > 0) m.expiresAt = now + c.disappearSeconds * 1000;
    store(m);
    touchChat(chatId, m, 1);
    return m;
  }

  async function simulatePeer(m: Message, silent: boolean) {
    const chat = chats.get(m.chatId);
    if (!chat) return;
    const peers = chat.kind === "direct" ? chat.members : chat.members.filter((u) => u !== me());
    const responder = peers[sendCounter % peers.length];
    await sleep(150);
    if (!messages.has(m.id)) return;
    m.status = "sent"; store(m);
    await sleep(450);
    if (!messages.has(m.id)) return;
    m.status = "delivered"; store(m);
    if (silent || chat.group?.leftOrRemoved) return;
    await sleep(300);
    setTypingUsers(chat.id, [responder]);
    await sleep(200);
    if (messages.has(m.id)) { m.status = "read"; store(m); }
    if (sendCounter % 2 === 0 && messages.has(m.id)) {
      await sleep(300);
      const emoji = REACTIONS[(sendCounter / 2) % REACTIONS.length];
      m.reactions = { ...m.reactions, [emoji]: [...(m.reactions[emoji] || []), responder] };
      store(m);
    }
    await sleep(900);
    setTypingUsers(chat.id, []);
    let reply = REPLIES[sendCounter % REPLIES.length];
    if (m.kind === "attachment") reply = m.attachment?.mime.startsWith("image/") ? "Great photo!" : "Got the file, thanks.";
    incoming(chat.id, responder, reply, m.kind === "text" && sendCounter % 3 === 1 ? { replyTo: m.id } : {});
  }

  function requireAccount() { if (!account) throw new Error("Not registered"); if (locked) throw new Error("Locked"); }

  const api: Messenger = {
    async init() {
      let saved: Account | null = null;
      try { const raw = sessionStorage.getItem(SESSION_KEY); if (raw) saved = JSON.parse(raw); lockPass = sessionStorage.getItem(LOCK_KEY); } catch { /* private mode */ }
      if (saved) { account = saved; loadSeed(saved.username); locked = !!lockPass; }
      return { account, locked };
    },
    async register(username, inviteCode, displayName) {
      await sleep(400);
      if (!/^[a-z0-9_]{3,32}$/.test(username)) throw new Error("Username must be 3–32 characters: lowercase letters, digits and underscore.");
      if (!inviteCode.trim()) throw new Error("An invite code is required.");
      if (inviteCode.trim().toLowerCase() === "expired") throw new Error("That invite has expired or was already used.");
      if (username === "taken") throw new Error("That username is taken.");
      account = { username, deviceId: 1, identityKeyB64: fakeKey(username), registrationId: 4242, displayName: displayName || username, createdAt: Date.now() };
      try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(account)); } catch { /* ignore */ }
      loadSeed(username);
      return account;
    },
    account: () => account,
    async connect() {
      requireAccount();
      state = "connecting"; emit({ type: "connection", state });
      await sleep(350);
      state = "online"; emit({ type: "connection", state });
    },
    disconnect() { state = "offline"; emit({ type: "connection", state }); },
    connectionState: () => state,
    on(handler) { handlers.add(handler); return () => { handlers.delete(handler); }; },

    async addContact(username) {
      requireAccount();
      await sleep(300);
      if (!/^[a-z0-9_]{3,32}$/.test(username)) throw new Error("That is not a valid username.");
      if (username === me()) throw new Error("That is you.");
      if (username.startsWith("nobody")) throw new Error(`No account named "${username}".`);
      let c = contacts.get(username);
      if (!c) {
        c = { username, identityKeyB64: fakeKey(username), verified: false, addedAt: Date.now(), hasDeliveryToken: false };
        contacts.set(username, c);
        emit({ type: "contact", contact: { ...c } });
      }
      const id: ChatId = "u:" + username;
      if (!chats.has(id)) {
        const chat: Chat = { id, kind: "direct", title: c.displayName || username, members: [username], unread: 0, disappearSeconds: 0, updatedAt: Date.now() };
        chats.set(id, chat);
        emit({ type: "chat", chat: { ...chat } });
        // the peer answers our profile message with theirs
        setTimeout(() => {
          const cc = contacts.get(username);
          if (!cc) return;
          cc.hasDeliveryToken = true;
          cc.displayName = username[0].toUpperCase() + username.slice(1);
          emit({ type: "contact", contact: { ...cc } });
          const ch = chats.get(id);
          if (ch) { ch.title = cc.displayName; emit({ type: "chat", chat: { ...ch } }); }
        }, 1200);
      }
      return { ...c };
    },
    async listContacts() { return Array.from(contacts.values()).map((c) => ({ ...c })); },
    async getContact(username) { const c = contacts.get(username); return c && { ...c }; },
    async safetyNumber(username) {
      const c = contacts.get(username);
      if (!c) throw new Error("Unknown contact");
      return { digits: safetyDigits(me(), username), verified: c.verified, identityChanged: !!c.identityChanged } satisfies SafetyNumber;
    },
    async setVerified(username, verified) {
      const c = contacts.get(username); if (!c) throw new Error("Unknown contact");
      c.verified = verified; emit({ type: "contact", contact: { ...c } });
    },
    async acceptIdentityChange(username) {
      const c = contacts.get(username); if (!c) throw new Error("Unknown contact");
      c.identityChanged = false; c.verified = false; c.identityKeyB64 = fakeKey(username + ":" + Date.now());
      emit({ type: "contact", contact: { ...c } });
    },
    async setDisplayName(name) {
      requireAccount();
      account = { ...account!, displayName: name };
      try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(account)); } catch { /* ignore */ }
    },

    async listChats() { return Array.from(chats.values()).map((c) => ({ ...c })); },
    async getChat(id) { const c = chats.get(id); return c && { ...c }; },
    async getMessages(chatId, opts = {}) {
      const limit = opts.limit ?? 50;
      let list = chatMessages(chatId);
      if (opts.before != null) list = list.filter((m) => m.sentAt < opts.before!);
      return list.slice(-limit).map((m) => ({ ...m }));
    },
    async sendText(chatId, body, opts = {}) {
      requireAccount();
      const chat = chats.get(chatId);
      if (!chat) throw new Error("No such chat");
      if (chat.group?.leftOrRemoved) throw new Error("You are no longer a member of this group.");
      const peer = chat.kind === "direct" ? contacts.get(chat.members[0]) : undefined;
      if (peer?.identityChanged) throw new Error(`${peer.displayName || peer.username}'s safety number changed. Accept it before sending.`);
      const now = Date.now();
      const m: Message = { id: newId(), chatId, sender: me(), mine: true, sentAt: now, receivedAt: now, kind: "text", body, reactions: {}, status: "pending", replyTo: opts.replyTo };
      if (chat.disappearSeconds > 0) m.expiresAt = now + chat.disappearSeconds * 1000;
      store(m);
      touchChat(chatId, m);
      sendCounter++;
      const cmd = body.trim().toLowerCase();
      if (cmd === "/fail") {
        setTimeout(() => { m.status = "failed"; store(m); }, 400);
      } else if (cmd === "/identity" && peer) {
        setTimeout(() => { peer.identityChanged = true; peer.verified = false; emit({ type: "contact", contact: { ...peer } }); }, 600);
        void simulatePeer(m, true);
      } else if (cmd === "/remove" && chat.group) {
        setTimeout(() => {
          const g = chat.group!;
          g.members = g.members.filter((u) => u !== me()); g.revision++;
          chat.members = g.members; g.leftOrRemoved = true;
          systemLine(chatId, "Alice removed you from the group");
        }, 800);
        void simulatePeer(m, true);
      } else {
        void simulatePeer(m, cmd === "/silence");
      }
      return { ...m };
    },
    async sendAttachment(chatId, file, opts = {}) {
      requireAccount();
      const chat = chats.get(chatId);
      if (!chat) throw new Error("No such chat");
      if (chat.group?.leftOrRemoved) throw new Error("You are no longer a member of this group.");
      const id = newId();
      blobs.set(id, file);
      const meta: AttachmentMeta = { id, mime: file.type || "application/octet-stream", size: file.size, name: opts.name ?? (file as File).name, caption: opts.caption };
      if (meta.mime.startsWith("image/") && typeof createImageBitmap === "function") {
        try { const bmp = await createImageBitmap(file); meta.width = bmp.width; meta.height = bmp.height; bmp.close(); } catch { /* not decodable */ }
      }
      const now = Date.now();
      const m: Message = { id: newId(), chatId, sender: me(), mine: true, sentAt: now, receivedAt: now, kind: "attachment", body: opts.caption ?? "", attachment: meta, reactions: {}, status: "pending" };
      if (chat.disappearSeconds > 0) m.expiresAt = now + chat.disappearSeconds * 1000;
      store(m);
      touchChat(chatId, m);
      sendCounter++;
      void simulatePeer(m, false);
      return { ...m };
    },
    async downloadAttachment(messageId) {
      const m = messages.get(messageId);
      const b = m?.attachment && blobs.get(m.attachment.id);
      if (!b) throw new Error("Attachment not available");
      await sleep(200);
      return b;
    },
    async retry(messageId) {
      const m = messages.get(messageId);
      if (!m) throw new Error("No such message");
      m.status = "pending"; store(m);
      sendCounter++;
      void simulatePeer(m, false);
      return { ...m };
    },
    async react(messageId, emoji) {
      const m = messages.get(messageId);
      if (!m) throw new Error("No such message");
      const u = me();
      const next: Record<string, Username[]> = {};
      let had = false;
      for (const [e, who] of Object.entries(m.reactions)) {
        const rest = who.filter((w) => w !== u);
        if (who.includes(u) && e === emoji) had = true;
        if (rest.length) next[e] = rest;
      }
      if (!had) next[emoji] = [...(next[emoji] || []), u];
      m.reactions = next;
      store(m);
    },
    async deleteForEveryone(messageId) {
      const m = messages.get(messageId);
      if (!m) throw new Error("No such message");
      if (!m.mine) throw new Error("Only your own messages can be deleted for everyone.");
      m.deleted = true; m.body = ""; m.attachment = undefined; m.reactions = {};
      store(m);
    },
    async deleteLocally(messageId) {
      const m = messages.get(messageId);
      if (!m) return;
      messages.delete(messageId);
      emit({ type: "message", message: { ...m, deleted: true, body: "", attachment: undefined, reactions: {} } });
    },
    async markRead(chatId) {
      const c = chats.get(chatId);
      if (!c || c.unread === 0) return;
      c.unread = 0;
      emit({ type: "chat", chat: { ...c } });
    },
    setTyping(chatId, typing) {
      // Just for realism: nothing to do, but log-free no-op that clears any pending timer.
      const t = typingTimers.get(chatId);
      if (t) clearTimeout(t);
      if (typing) typingTimers.set(chatId, setTimeout(() => typingTimers.delete(chatId), 5000));
    },
    async setDisappearing(chatId, seconds) {
      const c = chats.get(chatId);
      if (!c) throw new Error("No such chat");
      if (c.group && !c.group.admins.includes(me())) throw new Error("Only admins can change the timer.");
      c.disappearSeconds = seconds;
      emit({ type: "chat", chat: { ...c } });
      systemLine(chatId, seconds === 0 ? "You turned off disappearing messages" : `You set disappearing messages to ${describeSeconds(seconds)}`);
    },

    async createGroup(name, members) {
      requireAccount();
      await sleep(300);
      if (!name.trim()) throw new Error("Give the group a name.");
      const id = hex(8);
      const all = Array.from(new Set([me(), ...members]));
      const group: GroupState = { id, name: name.trim(), creator: me(), admins: [me()], members: all, revision: 1 };
      const chat: Chat = { id: "g:" + id, kind: "group", title: group.name, members: all, group, unread: 0, disappearSeconds: 0, updatedAt: Date.now() };
      chats.set(chat.id, chat);
      emit({ type: "chat", chat: { ...chat } });
      systemLine(chat.id, "You created the group");
      return { ...chat };
    },
    async updateGroup(groupId, patch) {
      requireAccount();
      const chat = chats.get("g:" + groupId);
      if (!chat?.group) throw new Error("No such group");
      const g = chat.group;
      if (!g.admins.includes(me())) throw new Error("Only admins can change the group.");
      await sleep(200);
      if (patch.name && patch.name.trim() !== g.name) { g.name = patch.name.trim(); chat.title = g.name; systemLine(chat.id, `You renamed the group to "${g.name}"`); }
      if (patch.add?.length) {
        const added = patch.add.filter((u) => !g.members.includes(u));
        g.members = [...g.members, ...added];
        if (added.length) systemLine(chat.id, `You added ${added.map(nameOf).join(", ")}`);
      }
      if (patch.remove?.length) {
        g.members = g.members.filter((u) => !patch.remove!.includes(u));
        g.admins = g.admins.filter((u) => !patch.remove!.includes(u));
        systemLine(chat.id, `You removed ${patch.remove.map(nameOf).join(", ")}`);
      }
      g.revision++;
      chat.members = g.members;
      emit({ type: "chat", chat: { ...chat } });
      return { ...chat };
    },
    async leaveGroup(groupId) {
      const chat = chats.get("g:" + groupId);
      if (!chat?.group) throw new Error("No such group");
      const g = chat.group;
      g.members = g.members.filter((u) => u !== me());
      g.admins = g.admins.filter((u) => u !== me());
      g.revision++;
      chat.members = g.members;
      g.leftOrRemoved = true;
      systemLine(chat.id, "You left the group");
      emit({ type: "chat", chat: { ...chat } });
    },

    async mintInvite() {
      requireAccount();
      await sleep(300);
      const code = hex(6).toUpperCase().replace(/(.{4})/g, "$1-").replace(/-$/, "");
      return { code, expiresAt: Date.now() + 7 * 86400_000, link: `${appUrl}#invite=${code}` };
    },
    async enablePush() { await sleep(300); push = true; return true; },
    async disablePush() { push = false; },
    pushEnabled: () => push,
    async setLock(passphrase) {
      lockPass = passphrase;
      try { if (passphrase) sessionStorage.setItem(LOCK_KEY, passphrase); else sessionStorage.removeItem(LOCK_KEY); } catch { /* ignore */ }
    },
    async unlock(passphrase) {
      await sleep(300);
      if (passphrase !== lockPass) return false;
      locked = false;
      return true;
    },
    async exportBackup(passphrase) {
      if (!passphrase) throw new Error("A passphrase is required.");
      const payload = { v: 1, mock: true, account, contacts: Array.from(contacts.values()), groups: Array.from(chats.values()).filter((c) => c.group).map((c) => c.group) };
      return new Blob([JSON.stringify({ passphraseHint: passphrase.length, payload }, null, 2)], { type: "application/json" });
    },
    async importBackup(file, passphrase) {
      const text = await file.text();
      let parsed: { payload?: { account?: Account } };
      try { parsed = JSON.parse(text); } catch { throw new Error("That is not a backup file."); }
      if (!parsed.payload?.account) throw new Error("That is not a backup file.");
      if (!passphrase) throw new Error("Wrong passphrase.");
      account = parsed.payload.account;
      try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(account)); } catch { /* ignore */ }
      contacts.clear(); chats.clear(); messages.clear();
      loadSeed(account.username);
      return account;
    },
    async wipe() {
      account = null; locked = false; lockPass = null; push = false;
      contacts.clear(); chats.clear(); messages.clear(); blobs.clear();
      try { sessionStorage.removeItem(SESSION_KEY); sessionStorage.removeItem(LOCK_KEY); } catch { /* ignore */ }
      state = "offline"; emit({ type: "connection", state });
    },
  };

  function nameOf(u: Username) { return contacts.get(u)?.displayName || u; }
  return api;
}

function describeSeconds(s: number): string {
  if (s % 604800 === 0) return `${s / 604800} week${s / 604800 === 1 ? "" : "s"}`;
  if (s % 86400 === 0) return `${s / 86400} day${s / 86400 === 1 ? "" : "s"}`;
  if (s % 3600 === 0) return `${s / 3600} hour${s / 3600 === 1 ? "" : "s"}`;
  return `${s} seconds`;
}
