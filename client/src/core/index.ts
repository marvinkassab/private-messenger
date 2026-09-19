/* Entry point for the core: wires store + signal + content + groups + attachments + api
   into the `Messenger` interface from ../types. See messenger.ts for the implementation. */
import type { Messenger } from "../types";
import type { FetchLike, Transport } from "./api";
import { MessengerImpl } from "./messenger";

export interface MessengerOptions {
  baseUrl: string; // e.g. "https://private-messenger.<account>.workers.dev"
  appUrl?: string; // where the client is served, used to build invite links

  /* Test / advanced injection points. Production callers can leave these unset. */
  fetch?: FetchLike; // defaults to globalThis.fetch
  transport?: Transport; // defaults to a WebSocketTransport against baseUrl
  dbName?: string; // defaults to "pm-signal"; give each test instance its own
  indexedDB?: IDBFactory; // defaults to globalThis.indexedDB
  WebSocketImpl?: typeof WebSocket; // defaults to globalThis.WebSocket
  sweepIntervalMs?: number; // how often the disappearing-message sweep runs
}

export function createMessenger(opts: MessengerOptions): Messenger {
  return new MessengerImpl(opts);
}

export type { MessengerDeps } from "./messenger";
export { IdentityChangedError, MessengerImpl } from "./messenger";
