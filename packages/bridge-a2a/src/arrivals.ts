// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The packets that reached a mind of the gateway's and wait to be dealt
 * with.
 *
 * A mailbox gives a packet once. So a packet is written down as soon as it
 * is read, before anything is done with it, and stays written down until
 * the caller says it is done with it: a process that stops in between
 * finds the packet again when it next looks.
 */

import { join } from "node:path";

import type { JsonObject } from "@oip/core";
import { keptFrom, keptOf, type KeptPacket, type Opened } from "@oip/local";

import { Store } from "./store.ts";

/** What waits for one mind. */
export class Arrivals {
  readonly #opened: Opened;
  readonly #pending: Store<JsonObject>;

  /**
   * @param opened - The mind, open.
   * @param dir - The directory under which what waits is written down.
   */
  constructor(opened: Opened, dir: string) {
    this.#opened = opened;
    this.#pending = new Store(join(dir, "pending"));
  }

  /**
   * Reads the mind's mailbox, and gives every packet that waits: those it
   * found now, and those an earlier reading found that are not done with.
   * Oldest first.
   */
  async waiting(): Promise<KeptPacket[]> {
    const read = await this.#opened.mind.receive();
    for (const received of read.received) {
      const kept = keptOf(received);
      // A packet is dealt with once, however often it arrives.
      if (this.#opened.inbox.get(kept.id) !== undefined) continue;
      // Written down before anything is done with it.
      this.#pending.put(kept.id, kept as unknown as JsonObject);
      this.#opened.inbox.put(kept.id, kept);
    }
    const waiting = this.#pending.all().flatMap(({ key, value }) => {
      const kept = keptFrom(value);
      // What is written there is no packet: nothing can be done with it, now or later.
      if (kept?.id !== key) this.#pending.delete(key);
      return kept?.id === key ? [kept] : [];
    });
    // In one order whatever the directory gives them in. What one reading of the mailbox found
    // has one time: there, the time each sender gave its packet decides.
    const place = ({ time, id, packet }: KeptPacket): string => `${time} ${packet.created} ${id}`;
    waiting.sort((one, other) => (place(one) < place(other) ? -1 : 1));
    return waiting;
  }

  /** Is done with a packet: it waits no more. */
  done(id: string): void {
    this.#pending.delete(id);
  }
}
