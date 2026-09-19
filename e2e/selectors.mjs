/* Page drivers for the full-stack test.
 *
 * Every selector here is a data-test attribute the UI sets deliberately, so
 * this file is the only place that knows about the DOM. If a selector breaks,
 * it breaks here rather than scattered through run.mjs.
 */

const T = (name) => `[data-test="${name}"]`;
const LONG = 30000;

/* ---------------------------------------------------------- registration */

export async function register(page, { username, invite, name }) {
  await page.waitForSelector(T("register-form"), { timeout: LONG });
  await page.fill(T("register-username"), username);
  const inviteField = await page.$(T("register-invite"));
  if (inviteField) {
    const prefilled = await inviteField.inputValue();
    if (prefilled !== invite) await page.fill(T("register-invite"), invite);
  }
  await page.fill(T("register-displayname"), name);
  await page.click(T("register-submit"));
  await page.waitForSelector(T("register-form"), { state: "detached", timeout: LONG });
  await page.waitForSelector(T("me-card"), { timeout: LONG });
}

/** Attempts a registration expected to fail, and returns the error shown. */
export async function registerExpectError(page, { username, invite, name }) {
  await page.waitForSelector(T("register-form"), { timeout: LONG });
  await page.fill(T("register-username"), username);
  await page.fill(T("register-invite"), invite);
  await page.fill(T("register-displayname"), name);
  await page.click(T("register-submit"));
  await page.waitForFunction(
    (sel) => {
      const el = document.querySelector(sel);
      return el && el.textContent && el.textContent.trim().length > 0;
    },
    T("register-error"),
    { timeout: LONG },
  );
  return (await page.textContent(T("register-error"))).trim();
}

export async function isSignedIn(page, username) {
  await page.waitForSelector(T("me-card"), { timeout: LONG });
  const text = await page.textContent(T("me-card"));
  return text.includes(username);
}

export async function connectionState(page) {
  await page.waitForSelector(T("connection-indicator"), { timeout: LONG });
  return (await page.getAttribute(T("connection-dot"), "data-state")) ?? (await page.textContent(T("connection-indicator"))).trim();
}

/** Waits until the client reports a live connection to the Worker. */
export async function waitOnline(page, timeout = LONG) {
  await page.waitForFunction(
    (sel) => {
      const el = document.querySelector(sel);
      if (!el) return false;
      const state = el.getAttribute("data-state") || el.textContent || "";
      return /online/i.test(state);
    },
    T("connection-indicator"),
    { timeout },
  );
}

/** Closes any modal dialog left open. A modal <dialog> makes the rest of the
 *  page inert, so a stray one turns every later click into a timeout whose
 *  message ("<html> intercepts pointer events") says nothing about the cause. */
export async function dismissDialogs(page) {
  for (let i = 0; i < 3; i++) {
    const open = await page.$$("dialog[open]");
    if (open.length === 0) return;
    await page.keyboard.press("Escape");
    await page.waitForTimeout(150);
  }
}

/* ---------------------------------------------------------------- chats */

/** Opens a chat by its title, or by the contact's username.
 *
 * Uses a locator rather than an element handle: the chat list re-renders
 * whenever a message or receipt arrives, which detaches a handle grabbed a
 * moment earlier and makes the click fail intermittently. A locator
 * re-resolves on each attempt. */
export async function openChat(page, titleOrUsername) {
  await dismissDialogs(page);

  // Already in the right conversation? Nothing to do. This is checked without
  // requiring the chat list to be visible, because at phone width the list is
  // hidden whenever a conversation is open.
  const already = await page.evaluate(
    ([sel, needle]) => {
      const el = document.querySelector(`${sel}[aria-current="true"]`);
      if (!el) return false;
      const title = (el.getAttribute("data-title") || el.textContent || "").toLowerCase();
      return title.includes(needle.toLowerCase());
    },
    [T("chat-item"), titleOrUsername],
  );
  if (already && (await page.$(T("composer-input")))) return;

  // On a phone the list is behind the back button while a chat is open.
  const back = await page.$("#btn-back");
  if (back && (await back.isVisible())) {
    await back.click();
    await page.waitForTimeout(200);
  }

  await page.waitForSelector(T("chat-item"), { state: "visible", timeout: LONG });
  const exact = page.locator(`${T("chat-item")}[data-title="${titleOrUsername}"]`);
  const loose = page
    .locator(T("chat-item"))
    .filter({ hasText: new RegExp(titleOrUsername.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i") });
  const target = (await exact.count()) > 0 ? exact.first() : loose.first();
  await target.click({ timeout: LONG });
  await page.waitForSelector(T("composer-input"), { timeout: LONG });
}

export async function addContact(page, username) {
  await dismissDialogs(page);
  await page.click(T("new-chat-btn"));
  await page.waitForSelector(`${T("new-chat-dialog")}[open]`, { timeout: LONG });
  await page.fill(T("new-chat-username"), username);
  await page.click(T("new-chat-submit"));
  await page.waitForSelector(`${T("new-chat-dialog")}[open]`, { state: "hidden", timeout: LONG });
}

export async function createGroup(page, name, members) {
  await dismissDialogs(page);
  await page.click(T("new-group-btn"));
  await page.waitForSelector(`${T("new-group-dialog")}[open]`, { timeout: LONG });
  await page.fill(T("group-name"), name);
  for (const m of members) {
    await page.click(`${T("group-member")}[data-username="${m}"]`);
  }
  await page.click(T("group-submit"));
  await page.waitForSelector(`${T("new-group-dialog")}[open]`, { state: "hidden", timeout: LONG });
}

/* ------------------------------------------------------------- messages */

export async function sendText(page, body) {
  await page.fill(T("composer-input"), body);
  await page.click(T("send-btn"));
  await page.waitForFunction(
    ([sel, needle]) => Array.from(document.querySelectorAll(sel)).some((el) => el.textContent.includes(needle)),
    [T("message-bubble"), body.slice(0, 40)],
    { timeout: LONG },
  );
}

/** True once a message containing `needle` is on screen. */
export async function seesText(page, needle, timeout = LONG) {
  try {
    await page.waitForFunction(
      ([sel, text]) => Array.from(document.querySelectorAll(sel)).some((el) => el.textContent.includes(text)),
      [T("message-bubble"), needle],
      { timeout },
    );
    return true;
  } catch {
    return false;
  }
}

/** The delivery status of our own message containing `needle`. */
export async function ownMessageStatus(page, needle) {
  return page.evaluate(
    ([msgSel, needleText]) => {
      const msg = Array.from(document.querySelectorAll(msgSel)).find(
        (el) => el.getAttribute("data-mine") === "true" && el.textContent.includes(needleText),
      );
      return msg ? msg.getAttribute("data-status") : null;
    },
    [T("message"), needle],
  );
}

/** Waits for one of our messages to reach a status (sent/delivered/read). */
export async function waitStatus(page, needle, statuses, timeout = LONG) {
  const wanted = Array.isArray(statuses) ? statuses : [statuses];
  try {
    await page.waitForFunction(
      ([msgSel, needleText, want]) => {
        const msg = Array.from(document.querySelectorAll(msgSel)).find(
          (el) => el.getAttribute("data-mine") === "true" && el.textContent.includes(needleText),
        );
        return msg ? want.includes(msg.getAttribute("data-status")) : false;
      },
      [T("message"), needle, wanted],
      { timeout },
    );
    return true;
  } catch {
    return false;
  }
}

export async function sendImage(page, filePath) {
  await page.setInputFiles(T("attach-input"), filePath);
}

export async function seesImage(page, timeout = LONG) {
  try {
    await page.waitForSelector(T("attachment-image"), { timeout });
    return true;
  } catch {
    return false;
  }
}

export async function react(page, needle, emoji) {
  // Locator, not a handle: the message list re-renders on every receipt.
  const msg = page.locator(T("message")).filter({ hasText: needle }).first();
  await msg.waitFor({ timeout: LONG });
  await msg.hover();
  const actions = msg.locator(T("msg-actions"));
  if ((await actions.count()) > 0) await actions.first().click({ timeout: LONG });
  await page.waitForSelector(T("msg-menu"), { timeout: LONG });
  await page.click(`${T("react-btn")}[data-emoji="${emoji}"]`);
  await page.waitForSelector(`${T("reaction")}[data-emoji="${emoji}"]`, { timeout: LONG });
}

/* ---------------------------------------------------- details and other */

/** The 60-digit safety number from the chat details dialog. */
export async function safetyNumber(page, _peer) {
  await page.click(T("details-btn"));
  await page.waitForSelector(`${T("details-dialog")}[open]`, { timeout: LONG });
  await page.waitForSelector(T("safety-digits"), { timeout: LONG });
  const digits = (await page.textContent(T("safety-digits"))).replace(/\D/g, "");
  await page.keyboard.press("Escape");
  await page.waitForSelector(`${T("details-dialog")}[open]`, { state: "hidden", timeout: LONG }).catch(() => {});
  return digits;
}

export async function mintInvite(page) {
  await dismissDialogs(page);
  await page.click(T("settings-btn"));
  await page.waitForSelector(`${T("settings-dialog")}[open]`, { timeout: LONG });
  await page.click(T("invite-mint-btn"));
  await page.waitForFunction(
    (sel) => {
      const el = document.querySelector(sel);
      return el && /#invite=/.test(el.textContent || "");
    },
    T("invite-link"),
    { timeout: LONG },
  );
  const link = (await page.textContent(T("invite-link"))).trim();
  await page.click(T("settings-done-btn"));
  await page.waitForSelector(`${T("settings-dialog")}[open]`, { state: "hidden", timeout: LONG }).catch(() => {});
  const code = (link.match(/#invite=([A-Za-z0-9_-]+)/) || [])[1] || "";
  return { link, code };
}

export default {
  dismissDialogs,
  register,
  registerExpectError,
  isSignedIn,
  connectionState,
  waitOnline,
  openChat,
  addContact,
  createGroup,
  sendText,
  seesText,
  ownMessageStatus,
  waitStatus,
  sendImage,
  seesImage,
  react,
  safetyNumber,
  mintInvite,
};
