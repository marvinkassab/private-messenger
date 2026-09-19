/* Shared test scaffolding: wires a fresh Messenger instance to a shared FakeServer,
   with its own isolated IndexedDB so instances never see each other's local storage. */

import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { createMessenger, type MessengerOptions } from "../../src/core/index";
import type { Messenger, MessengerEvent } from "../../src/types";
import { FakeServer } from "./fakeServer";

// store.ts calls the global IDBKeyRange directly; give every test process one.
(globalThis as { IDBKeyRange?: typeof IDBKeyRange }).IDBKeyRange = IDBKeyRange;

export const BASE_URL = "https://fake.test";

let dbCounter = 0;

/** A Messenger wired to `server`, with its own IndexedDB and its own FakeTransport. */
export function makeClient(server: FakeServer, opts: Partial<MessengerOptions> = {}): Messenger {
  dbCounter += 1;
  return createMessenger({
    baseUrl: BASE_URL,
    appUrl: "https://app.test",
    fetch: server.fetch,
    transport: server.transport(),
    dbName: `pm-signal-test-${dbCounter}-${Math.random().toString(36).slice(2)}`,
    indexedDB: new IDBFactory(),
    sweepIntervalMs: 50,
    ...opts,
  });
}

/** Collects every event a Messenger emits, for assertions and for `waitFor`. */
export class EventLog {
  readonly events: MessengerEvent[] = [];
  private waiters: Array<{ pred: (e: MessengerEvent) => boolean; resolve: (e: MessengerEvent) => void }> = [];

  constructor(m: Messenger) {
    m.on((e) => {
      this.events.push(e);
      this.waiters = this.waiters.filter((w) => {
        if (w.pred(e)) {
          w.resolve(e);
          return false;
        }
        return true;
      });
    });
  }

  async waitFor(pred: (e: MessengerEvent) => boolean, timeoutMs = 2000): Promise<MessengerEvent> {
    const existing = this.events.find(pred);
    if (existing) return existing;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w.resolve !== onEvent);
        reject(new Error(`waitFor timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      const onEvent = (e: MessengerEvent) => {
        clearTimeout(timer);
        resolve(e);
      };
      this.waiters.push({ pred, resolve: onEvent });
    });
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Registers a fresh account and connects it. */
export async function registerAndConnect(m: Messenger, server: FakeServer, username: string, displayName: string): Promise<void> {
  await m.init();
  await m.register(username, server.bootstrapInvite, displayName);
  await m.connect();
}
