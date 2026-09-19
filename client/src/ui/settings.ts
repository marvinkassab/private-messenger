/* Settings dialog: display name, invites, notifications, app lock, backup,
   theme and device wipe. */

import type { App } from "./app";
import { getTheme, setTheme, type Theme } from "./app";
import { h, toast, errorText, copyText, fmtRel } from "./dom";
import { confirmDialog, promptDialog } from "./dialog";
import { lastBackupAt, promptForBackup } from "./backupNudge";

function displayNameSection(app: App): HTMLElement {
  const input = h("input", { type: "text", value: app.s.account.displayName, "data-test": "settings-displayname", maxLength: 60 });
  const err = h("div.err");
  const saveBtn = h("button.btn.sm", {
    type: "button", "data-test": "settings-displayname-save",
    onclick: async () => {
      err.textContent = "";
      saveBtn.disabled = true;
      try {
        const name = input.value.trim() || app.s.account.username;
        await app.m.setDisplayName(name);
        toast("Display name updated");
        app.sidebar.render();
      } catch (e) { err.textContent = errorText(e); }
      finally { saveBtn.disabled = false; }
    },
  }, "Save");
  return h("div.field", h("div.lbl", "Display name"), h("div.rowbtns", input, saveBtn), err);
}

function inviteSection(app: App): HTMLElement {
  const box = h("code.linkbox", { hidden: true, "data-test": "invite-link" });
  const copyBtn = h("button.btn.sm", {
    type: "button", hidden: true, "data-test": "invite-copy-btn",
    onclick: async () => { const ok = await copyText(box.textContent || ""); toast(ok ? "Invite link copied" : "Could not copy", ok ? "info" : "error"); },
  }, "Copy");
  const shareBtn = h("button.btn.sm", {
    type: "button", hidden: true, "data-test": "invite-share-btn",
    onclick: async () => { try { await (navigator as any).share({ title: "Join Private Messenger", url: box.textContent }); } catch { /* cancelled */ } },
  }, "Share");
  const mintBtn = h("button.btn.sm.primary", {
    type: "button", "data-test": "invite-mint-btn",
    onclick: async () => {
      mintBtn.disabled = true;
      try {
        const inv = await app.m.mintInvite();
        box.textContent = inv.link; box.hidden = false;
        copyBtn.hidden = false;
        shareBtn.hidden = typeof (navigator as any).share !== "function";
      } catch (e) { toast("Could not create invite: " + errorText(e), "error"); }
      finally { mintBtn.disabled = false; }
    },
  }, "Create invite");
  return h("div.field", h("div.lbl", "Invite someone"),
    h("div.hint", "Invites expire after 7 days and can be used once."),
    h("div.rowbtns", mintBtn, copyBtn, shareBtn), box);
}

function notificationsSection(app: App): HTMLElement {
  const status = h("span", { "data-test": "notifications-status" }, app.m.pushEnabled() ? "Enabled" : "Disabled");
  const btn = h("button.btn.sm", {
    type: "button", "data-test": "notifications-toggle-btn",
    onclick: async () => {
      btn.disabled = true;
      try {
        if (app.m.pushEnabled()) {
          app.m.disablePush();
          status.textContent = "Disabled"; btn.textContent = "Enable";
        } else {
          if (typeof Notification !== "undefined" && Notification.permission === "default") {
            try { await Notification.requestPermission(); } catch { /* ignored */ }
          }
          const ok = await app.m.enablePush();
          status.textContent = ok ? "Enabled" : "Disabled";
          btn.textContent = ok ? "Disable" : "Enable";
        }
      } catch (e) { toast("Could not update notifications: " + errorText(e), "error"); }
      finally { btn.disabled = false; }
    },
  }, app.m.pushEnabled() ? "Disable" : "Enable");
  return h("div.field", h("div.lbl", "Notifications"), h("div.kv", status, btn));
}

function lockSection(app: App): HTMLElement {
  const setBtn = h("button.btn.sm", {
    type: "button", "data-test": "lock-set-btn",
    onclick: () => promptDialog({
      title: "Set app lock", desc: "Choose a passphrase to lock the app when it's idle.",
      label: "Passphrase", type: "password", minLength: 6, submitLabel: "Set",
      submit: async (value) => {
        if (value.length < 6) throw new Error("At least 6 characters.");
        await app.m.setLock(value);
        toast("App lock set");
      },
    }),
  }, "Set passphrase");
  const removeBtn = h("button.btn.sm.danger", {
    type: "button", "data-test": "lock-remove-btn",
    onclick: async () => {
      const ok = await confirmDialog({ title: "Remove app lock?", confirm: "Remove", danger: true });
      if (!ok) return;
      try { await app.m.setLock(null); toast("App lock removed"); } catch (e) { toast(errorText(e), "error"); }
    },
  }, "Remove lock");
  return h("div.field", h("div.lbl", "App lock"),
    h("div.hint", "Require a passphrase to open the app on this device."),
    h("div.rowbtns", setBtn, removeBtn));
}

function backupSection(app: App, dlg: HTMLDialogElement): HTMLElement {
  const status = h("div.hint", { "data-test": "backup-status" });
  const drawStatus = () => {
    const at = lastBackupAt();
    status.textContent = at
      ? `Last backup ${fmtRel(at)}. Make a new one after adding people or devices.`
      : "No backup yet. Without one, clearing this browser's data would lose this account for good.";
    status.classList.toggle("err", at === null);
  };
  drawStatus();

  const exportBtn = h("button.btn.sm", {
    type: "button", "data-test": "backup-export-btn",
    onclick: async () => { await promptForBackup(app.m); drawStatus(); },
  }, "Export backup");
  const fileInput = h("input", {
    type: "file", hidden: true, accept: "application/json", "data-test": "backup-import-input",
    onchange: (e: Event) => {
      const input = e.target as HTMLInputElement;
      const file = input.files?.[0];
      input.value = "";
      if (!file) return;
      promptDialog({
        title: "Import backup", desc: "Enter the passphrase this backup was locked with.",
        label: "Passphrase", type: "password", submitLabel: "Import",
        submit: async (value) => {
          await app.m.importBackup(file, value);
          toast("Backup imported. Reloading…");
          dlg.close();
          setTimeout(() => location.reload(), 600);
        },
      });
    },
  });
  const importBtn = h("button.btn.sm", { type: "button", "data-test": "backup-import-btn", onclick: () => fileInput.click() }, "Import backup");
  return h("div.field", h("div.lbl", "Backup"),
    h("div.hint", "A backup holds your identity and contacts, locked with a passphrase."),
    status,
    h("div.rowbtns", exportBtn, importBtn, fileInput));
}

function themeSection(): HTMLElement {
  const opts: Theme[] = ["auto", "light", "dark"];
  const buttons: HTMLElement[] = [];
  for (const t of opts) {
    const b = h("button.btn.sm" + (getTheme() === t ? ".primary" : ""), {
      type: "button", "data-test": "theme-" + t,
      onclick: () => {
        setTheme(t);
        for (const other of buttons) other.classList.toggle("primary", other === b);
      },
    }, t.charAt(0).toUpperCase() + t.slice(1));
    buttons.push(b);
  }
  return h("div.field", h("div.lbl", "Theme"), h("div.rowbtns", ...buttons));
}

function wipeSection(app: App, dlg: HTMLDialogElement): HTMLElement {
  const btn = h("button.btn.danger-solid", {
    type: "button", "data-test": "wipe-btn",
    onclick: async () => {
      const ok = await confirmDialog({
        title: "Wipe this device?",
        desc: "This deletes your identity, contacts and messages from this device. Without a backup this cannot be undone.",
        confirm: "Wipe device", danger: true,
      });
      if (!ok) return;
      try { await app.m.wipe(); dlg.close(); location.reload(); }
      catch (e) { toast("Could not wipe: " + errorText(e), "error"); }
    },
  }, "Wipe this device");
  return h("div.field", h("div.lbl", "Danger zone"), btn);
}

export function openSettings(app: App) {
  const dlg = h("dialog.wide", { "data-test": "settings-dialog" });
  const body = h("div.dlg-body");
  dlg.appendChild(h("div.dlg-head", h("h2", "Settings")));
  dlg.appendChild(body);
  dlg.appendChild(h("div.dlg-foot", h("button.btn.primary", { type: "button", "data-test": "settings-done-btn", onclick: () => dlg.close() }, "Done")));
  dlg.addEventListener("close", () => dlg.remove());
  document.body.appendChild(dlg);
  dlg.showModal();

  body.append(
    displayNameSection(app),
    inviteSection(app),
    notificationsSection(app),
    lockSection(app),
    backupSection(app, dlg),
    themeSection(),
    wipeSection(app, dlg));
}
