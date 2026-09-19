/* Placeholder until the core is implemented. The core agent replaces this file. */
import type { Messenger } from "../types";

export interface MessengerOptions {
  baseUrl: string;                       // e.g. "https://private-messenger.<account>.workers.dev"
  appUrl?: string;                       // where the client is served, used to build invite links
}

export function createMessenger(_opts: MessengerOptions): Messenger {
  throw new Error("core not implemented yet");
}
