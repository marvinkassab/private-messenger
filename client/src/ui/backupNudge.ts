/* Telling people their keys can vanish, and helping them prevent it.
 *
 * This app has no account recovery, and that is not an oversight: the server
 * holds nothing that could restore an account, which is the whole point. The
 * consequence is that a browser clearing its site data, a phone being lost,
 * or someone tapping "Clear browsing data" takes the account with it. The
 * conversations are gone and the person has to be re-invited as a new
 * account, with new safety numbers for everyone who verified them.
 *
 * An encrypted backup is the only way out of that, so the app says so plainly
 * at registration and keeps a quiet reminder in view until one exists. It
 * never nags more than that.
 */

import type { Messenger } from "../types";
import { h, toast } from "./dom";
import { openDialog, promptDialog } from "./dialog";

const LAST_BACKUP_KEY = "pm.lastBackupAt";
const DISMISSED_KEY = "pm.backupReminderDismissedAt";
/** How long a dismissal quiets the reminder. Long enough not to nag. */
const SNOOZE_MS = 7 * 24 * 3600 * 1000;

function readTime(key: string): number | null {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null; // private mode, or storage blocked
  }
}

function writeTime(key: string, at = Date.now()): void {
  try {
    localStorage.setItem(key, String(at));
  } catch {
    /* the reminder is a convenience; losing it is not worth an error */
  }
}

export function lastBackupAt(): number | null {
  return readTime(LAST_BACKUP_KEY);
}

/** Called after a backup file is successfully produced. */
export function recordBackupMade(): void {
  writeTime(LAST_BACKUP_KEY);
  try {
    localStorage.removeItem(DISMISSED_KEY);
  } catch {
    /* ignore */
  }
}

export function shouldRemindAboutBackup(): boolean {
  if (lastBackupAt() !== null) return false;
  const dismissed = readTime(DISMISSED_KEY);
  return dismissed === null || Date.now() - dismissed > SNOOZE_MS;
}

export function snoozeBackupReminder(): void {
  writeTime(DISMISSED_KEY);
}

/**
 * Runs the export and downloads the file. Shared by the reminder, the
 * first-run dialog and Settings, so "a backup was made" is recorded in
 * exactly one place and cannot drift between them.
 */
export async function runBackupExport(m: Messenger, passphrase: string): Promise<void> {
  const blob = await m.exportBackup(passphrase);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `private-messenger-backup-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
  recordBackupMade();
}

/** The passphrase prompt, with the warnings that matter next to the field. */
export async function promptForBackup(m: Messenger): Promise<void> {
  await promptDialog({
    title: "Make an encrypted backup",
    desc:
      "Choose a passphrase. The file is useless to anyone without it, so it is safe to keep " +
      "in cloud storage or email it to yourself. Nobody can recover it for you if you forget it.",
    label: "Passphrase",
    type: "password",
    minLength: 6,
    submitLabel: "Save backup",
    submit: async (value) => {
      if (value.length < 6) throw new Error("At least 6 characters.");
      await runBackupExport(m, value);
      toast("Backup saved. Keep the file somewhere you will still have it if you lose this device.");
    },
  });
}

/**
 * Shown once, straight after registering. This is the moment the account
 * exists and holds nothing yet, so losing it costs nothing but a re-invite,
 * and it is the cheapest possible time to explain the trade.
 */
export function showBackupIntro(m: Messenger): Promise<void> {
  return new Promise((resolve) => {
    const dlg: HTMLDialogElement = openDialog({
      title: "Your keys live on this device only",
      body: [
        h(
          "p",
          "Nothing about your account is stored on the server, which is why nobody, including " +
            "whoever runs it, can read your messages.",
        ),
        h(
          "p",
          "The other side of that: if this browser's data is cleared, or this device is lost, " +
            "the account goes with it. There is no password reset, because there is nothing to " +
            "reset it from. You would need a new invite and a new identity, and anyone who " +
            "verified your safety number would have to check it again.",
        ),
        h(
          "p.muted",
          "An encrypted backup file prevents all of that. It is locked with a passphrase you " +
            "choose, so it is safe to keep anywhere, including cloud storage.",
        ),
      ],
      foot: [
        h(
          "button.btn",
          {
            type: "button",
            "data-test": "backup-intro-later",
            onclick: () => {
              snoozeBackupReminder();
              dlg.close();
              resolve();
            },
          },
          "Not now",
        ),
        h(
          "button.btn.primary",
          {
            type: "button",
            "data-test": "backup-intro-now",
            onclick: async () => {
              dlg.close();
              await promptForBackup(m);
              resolve();
            },
          },
          "Make a backup",
        ),
      ],
    });
    dlg.addEventListener("close", () => resolve(), { once: true });
  });
}

/**
 * The standing reminder in the chat list, shown until a backup exists.
 * Returns null when there is nothing to say, so the caller can append it
 * unconditionally.
 */
export function backupReminderBar(m: Messenger, onChange: () => void): HTMLElement | null {
  if (!shouldRemindAboutBackup()) return null;
  return h(
    "div.warnbar",
    { "data-test": "backup-reminder" },
    h("span", "No backup yet. If this browser's data is cleared, this account cannot be recovered."),
    h(
      "button.btn.sm.primary",
      {
        type: "button",
        "data-test": "backup-reminder-action",
        onclick: async () => {
          await promptForBackup(m);
          onChange();
        },
      },
      "Back up",
    ),
    h(
      "button.btn.sm",
      {
        type: "button",
        "data-test": "backup-reminder-dismiss",
        "aria-label": "Remind me later",
        title: "Remind me later",
        onclick: () => {
          snoozeBackupReminder();
          onChange();
        },
      },
      "Later",
    ),
  );
}
