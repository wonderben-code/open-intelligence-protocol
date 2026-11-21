// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The outbox: packets that did not reach a recipient, kept to be tried
 * again.
 *
 * A packet is signed once. Where no endpoint of a recipient took it, and
 * the reason may pass (the recipient's host could not be reached, the
 * recipient has not yet said where it is), the packet is kept in the
 * client's memory with the recipients it still owes. It is tried again when
 * the client next reads, and when it is asked to, each time after a longer
 * wait, until it has arrived or can no longer be accepted.
 *
 * What is kept is the packet as it was signed. It is sealed anew each time
 * it is sent, to the recipient's agreement key as it then stands.
 */

import { contentId, type Instant, type JsonObject, parseTimestamp } from "@oip/core";
import { KeystoreError } from "@oip/keystore";
import { type Packet, validateRecordOfType } from "@oip/schema";

import type { Own } from "./publish.ts";

/** What became of a packet for one recipient: `Delivery` of `./messages.ts`, as far as the outbox reads it. */
interface Outcome {
  readonly to: string;
  readonly stored: boolean;
  readonly failure?: string;
}

/** A packet that waits in the outbox. */
export interface Queued {
  /** The packet's content ID. */
  readonly id: string;
  /** The packet, as it was signed. */
  readonly packet: Packet;
  /** The recipients it has not reached, each with why it did not the last time. */
  readonly to: readonly { readonly mind: string; readonly failure: string }[];
  /** Whether it goes sealed. */
  readonly sealed: boolean;
  /** How often it has been sent, the first time included. */
  readonly tries: number;
  /** When it is next tried by itself. `Mind.retry` tries it at once. */
  readonly next: Instant;
}

/** What came of trying a packet of the outbox again: `Retried` of `./messages.ts`, for any delivery. */
export interface Tried<D extends Outcome> {
  /** The packet's content ID. */
  readonly id: string;
  /** What became of it for each recipient it still owed, in order. Empty for one that was dropped. */
  readonly deliveries: readonly D[];
  /** How many recipients it still owes. */
  readonly waiting: number;
  /** Whether it was dropped unsent: it has expired, and no recipient would accept it now. */
  readonly expired: boolean;
}

/** The most packets that wait at once. Past it, a packet that does not arrive is told so and not kept. */
export const MAX_QUEUED = 1000;

const SECOND = 1_000_000_000n;
/** The first wait before a packet is tried again by itself, and the longest: it doubles between them. */
const FIRST_WAIT = 30n * SECOND;
const LONGEST_WAIT = 3600n * SECOND;
/** Layer 1, 12.4: how far past its `expires` a packet is still accepted. */
const CLOCK_SKEW = 300n * SECOND;

const NAME = "client-out-";
const nameOf = (id: string): string => NAME + id.slice(4, 25);

/**
 * Whether a delivery failed for a reason that may pass: the service could
 * not be reached or was not itself, asked for patience, or does not yet
 * know the recipient or its sender. A packet that was refused for what it
 * is, is not sent again.
 */
export function mayPass(failure: string | undefined): failure is string {
  return (
    failure === "unreachable" ||
    failure === "timeout" ||
    failure === "not-oip" ||
    failure === "rate-limited" ||
    failure === "stale-version" ||
    failure === "not-found"
  );
}

/** How long after the try of a given number a packet is tried again by itself. */
function waitAfter(tries: number): bigint {
  const doubled = FIRST_WAIT * 2n ** BigInt(Math.min(tries - 1, 16));
  return doubled < LONGEST_WAIT ? doubled : LONGEST_WAIT;
}

/** A packet of the outbox as it was written down, or `undefined` if that is none. */
function read(stored: JsonObject): Omit<Queued, "id"> | undefined {
  const packet = validateRecordOfType("Packet", stored["packet"]);
  const { to, sealed, tries, next } = stored;
  if (!packet.ok || !Array.isArray(to) || typeof sealed !== "boolean") return undefined;
  if (typeof tries !== "number" || !Number.isSafeInteger(tries) || tries < 1) return undefined;
  if (typeof next !== "string" || !/^\d{1,30}$/u.test(next)) return undefined;
  const owed: { mind: string; failure: string }[] = [];
  for (const entry of to as readonly unknown[]) {
    const { mind, failure } = (entry ?? {}) as Readonly<Record<string, unknown>>;
    if (typeof mind !== "string" || typeof failure !== "string") return undefined;
    owed.push({ mind, failure });
  }
  return { packet: packet.value, to: owed, sealed, tries, next: BigInt(next) };
}

/** What a mind's client keeps of the packets that have not arrived. */
export class Outbox {
  readonly #own: Own;
  /** The tries of what waits, one after another. */
  #trying: Promise<unknown> = Promise.resolve();

  constructor(own: Own) {
    this.#own = own;
  }

  /**
   * Keeps a packet for the recipients it did not reach, if the reason may
   * pass.
   *
   * @returns The recipients it is kept for.
   */
  async keep(
    packet: Packet,
    sealed: boolean,
    deliveries: readonly Outcome[],
  ): Promise<Set<string>> {
    const owed = deliveries.flatMap(({ to, stored, failure }) =>
      !stored && mayPass(failure) ? [{ mind: to, failure }] : [],
    );
    const { memory, clock } = this.#own;
    if (owed.length === 0) return new Set();
    const name = nameOf(contentId(packet));
    const held = await memory.get(name, read);
    if (held.value === undefined && (await memory.names(NAME)).length >= MAX_QUEUED) {
      return new Set();
    }
    await memory.put(
      name,
      { packet, to: owed, sealed, tries: 1, next: String(clock.now() + waitAfter(1)) },
      held.version,
    );
    return new Set(owed.map(({ mind }) => mind));
  }

  /** The packets that wait, in no particular order. */
  async list(): Promise<Queued[]> {
    const { memory } = this.#own;
    const waiting: Queued[] = [];
    for (const name of await memory.names(NAME)) {
      const held = await memory.get(name, read);
      // One that was removed since it was listed has arrived.
      if (held.value !== undefined) {
        waiting.push({ id: contentId(held.value.packet), ...held.value });
      }
    }
    return waiting;
  }

  /**
   * Gives up packets that wait: they are not tried again.
   *
   * @returns How many of them waited.
   */
  async forget(ids: readonly string[]): Promise<number> {
    const { memory } = this.#own;
    let waited = 0;
    for (const id of ids) {
      const name = nameOf(id);
      const held = await memory.get(name, read);
      if (held.value === undefined || contentId(held.value.packet) !== id) continue;
      await memory.forget(name, held.version);
      waited++;
    }
    return waited;
  }

  /**
   * Tries again the packets that wait.
   *
   * @param deliver - Brings a packet to one recipient: `Messaging`'s own.
   * @param all - Whether those whose next try is not yet due are tried as well.
   * @returns What came of each packet that was tried, or dropped.
   */
  retry<D extends Outcome>(
    deliver: (packet: Packet, to: string, sealed: boolean) => Promise<D>,
    all: boolean,
  ): Promise<Tried<D>[]> {
    const next = this.#trying.then(() => this.#retry(deliver, all));
    this.#trying = next.catch(() => undefined);
    return next;
  }

  async #retry<D extends Outcome>(
    deliver: (packet: Packet, to: string, sealed: boolean) => Promise<D>,
    all: boolean,
  ): Promise<Tried<D>[]> {
    const { memory, clock } = this.#own;
    const retried: Tried<D>[] = [];
    for (const name of await memory.names(NAME)) {
      const held = await memory.get(name, read);
      if (held.value === undefined) continue;
      const { packet, to, sealed, tries } = held.value;
      const id = contentId(packet);
      const now = clock.now();
      try {
        const expires = packet.expires === undefined ? undefined : parseTimestamp(packet.expires);
        if (expires !== undefined && expires + CLOCK_SKEW < now) {
          // Nobody would accept it now (12.4): it is not sent, and not kept.
          await memory.forget(name, held.version);
          retried.push({ id, deliveries: [], waiting: 0, expired: true });
          continue;
        }
        if (!all && held.value.next > now) continue;
        const deliveries: D[] = [];
        const owed: { mind: string; failure: string }[] = [];
        for (const { mind } of to) {
          const delivery = await deliver(packet, mind, sealed);
          deliveries.push(delivery);
          // One that is now refused for what it is, is given up: sending it again changes nothing.
          const { stored, failure } = delivery;
          if (!stored && mayPass(failure)) owed.push({ mind, failure });
        }
        if (owed.length === 0) {
          await memory.forget(name, held.version);
        } else {
          await memory.put(
            name,
            {
              packet,
              to: owed,
              sealed,
              tries: tries + 1,
              next: String(clock.now() + waitAfter(tries + 1)),
            },
            held.version,
          );
        }
        retried.push({ id, deliveries, waiting: owed.length, expired: false });
      } catch (error) {
        // Another process of the mind tried it at the same time: it is that one's to tell.
        if (!(error instanceof KeystoreError && error.code === "changed")) throw error;
      }
    }
    return retried;
  }
}
