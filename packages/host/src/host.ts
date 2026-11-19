// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A host (Layer 1, Section 13): the minds it serves, the packets that
 * arrive for them, and their mailboxes. This is what the host does with a
 * record once it has been read. The HTTP interface is `app.ts`.
 *
 * - **The inbox** (13.2) takes a packet as its recipient would (12.4): it
 *   is addressed to the mind, its dates allow it, and its sender signed it,
 *   by the sender's log as the host holds it. A packet that passes is kept
 *   for the mind and answered: with an `Ack` if the host signs for the
 *   mind, and with `{ "stored": true }` if it does not. The same packet
 *   again gets the same answer, and is not kept twice.
 * - **A sealed record** is kept as it is. The host cannot open it, so it
 *   cannot judge the packet inside: that is the recipient's to do.
 * - **The mailbox** (13.5) keeps what is posted to it until its owner
 *   removes it or it has been there longer than the host keeps things.
 *
 * What the host keeps for a mind is bounded, in items and in bytes: anyone
 * can post to a mailbox.
 */

import {
  contentId,
  createProofSync,
  formatKeyRef,
  formatTimestamp,
  type Instant,
  type JsonObject,
  OipError,
  type OipRecord,
  proofDigest,
  type SyncSigner,
  withProofs,
} from "@oip/core";
import { latestState, witnessRecord } from "@oip/identity";
import { draftAck, receivePacket } from "@oip/net";
import { cutShort, validateRecordOfType } from "@oip/schema";
import { type Database, HttpFailure, type LogArchive, Unavailable } from "@oip/server";

import { HostStore, type MailboxItem } from "./store.ts";

/** How much a host keeps for one mind, and for how long. */
export interface HostLimits {
  /** The most items in one mailbox. */
  readonly mailboxItems: number;
  /** The most bytes in one mailbox. */
  readonly mailboxBytes: number;
  /** How long an item stays in a mailbox, in nanoseconds. Layer 1, 13.5 asks for 30 days at least. */
  readonly retention: bigint;
  /** How far back the host remembers a packet that states no `expires`, in nanoseconds (12.4). */
  readonly window: bigint;
  /** The most bytes of records in one page of a drained mailbox. A page holds one item at least. */
  readonly pageBytes: number;
}

const DAY = 86_400_000_000_000n;

/**
 * A thousand items and 64 MiB for each mailbox, kept 30 days; an hour's
 * memory of packets; pages of 4 MiB.
 */
export const DEFAULT_HOST_LIMITS: HostLimits = {
  mailboxItems: 1000,
  mailboxBytes: 64 * 1024 * 1024,
  retention: 30n * DAY,
  window: 3_600_000_000_000n,
  pageBytes: 4 * 1024 * 1024,
};

/** How a host is made. */
export interface HostOptions {
  /** Its database, opened with `HOST_MIGRATIONS`. */
  readonly db: Database;
  /** The identity logs it holds, and its record of first sight. */
  readonly archive: LogArchive;
  readonly limits?: Partial<HostLimits>;
  /**
   * The key the host signs with for a mind it serves, if it holds one: an
   * operational key of the mind. A host that holds none acknowledges
   * nothing, and answers `{ "stored": true }` (13.2).
   */
  readonly signer?: (mind: string) => SyncSigner | undefined;
}

/** What the host answers to a record it has kept: an `Ack`, or that it is stored. */
export type Answer = JsonObject;

const STORED: Answer = Object.freeze({ stored: true });

/** The problem for a packet that the inbox does not take (core 10.2). */
function refusalOf(
  issues: readonly [{ path: string; message: string; clause: string }, ...unknown[]],
  senderKnown: boolean,
): OipError {
  const [first] = issues;
  const options = { clause: first.clause, issues: issues as never };
  if (first.path.endsWith("/to")) return new OipError("forbidden", first.message, options);
  if (/\/(?:created|expires)$/u.test(first.path)) {
    return new OipError("expired", first.message, options);
  }
  if (first.path.endsWith("/proof")) {
    // Without the sender's log the host cannot tell a forgery from a stranger.
    return senderKnown
      ? new OipError("invalid-proof", first.message, options)
      : new OipError(
          "stale-version",
          "the host holds no log of the packet's sender that verifies, so it cannot judge the packet's proof",
          options,
        );
  }
  return new OipError("invalid-record", first.message, options);
}

/** A host. */
export class Host {
  readonly #db: Database;
  readonly #archive: LogArchive;
  readonly #store: HostStore;
  readonly #limits: HostLimits;
  readonly #signer: (mind: string) => SyncSigner | undefined;
  /** Those to tell when a mind's mailbox has something new, by mind. */
  readonly #listeners = new Map<string, Set<() => void>>();

  constructor(options: HostOptions) {
    this.#db = options.db;
    this.#archive = options.archive;
    this.#store = new HostStore(options.db);
    this.#limits = { ...DEFAULT_HOST_LIMITS, ...options.limits };
    this.#signer = options.signer ?? (() => undefined);
  }

  /** Whether the host serves a mind. */
  hosts(mind: string): boolean {
    return this.#store.hosts(mind);
  }

  /**
   * Takes a mind on. The host must hold a log of it that verifies: a mind
   * is served by what its own log says of it.
   *
   * @throws OipError `not-found` if the host holds no such log.
   */
  adopt(mind: string): void {
    this.#archive.witnessing((_seen, now) => {
      if (!this.#archive.view(now).log(mind).ok) {
        throw new OipError("not-found", "the host holds no log of that mind");
      }
      this.#store.adopt(mind, now);
    });
  }

  /** How many minds the host serves. */
  get minds(): number {
    return this.#store.minds();
  }

  #served(mind: string): void {
    if (!this.#store.hosts(mind))
      throw new OipError("not-found", "the host does not serve that mind");
  }

  /**
   * Whether there is room for a record in a mind's mailbox.
   *
   * @throws HttpFailure 507 if there is none.
   */
  #room(mind: string, record: JsonObject): void {
    const held = this.#store.held(mind);
    const bytes = Buffer.byteLength(JSON.stringify(record));
    if (held.items >= this.#limits.mailboxItems || held.bytes + bytes > this.#limits.mailboxBytes) {
      throw new HttpFailure(507, "Insufficient Storage");
    }
  }

  /** Keeps a record for a mind, and tells whoever waits for its mail. */
  #put(mind: string, id: string, record: JsonObject, now: Instant): void {
    if (!this.#store.put(mind, id, record, now)) return;
    for (const listener of this.#listeners.get(mind) ?? []) {
      try {
        listener();
      } catch {
        // A listener that fails is its own affair.
      }
    }
  }

  /** The `Ack` for a packet, signed for the mind, if the host holds a key of the mind's that is valid. */
  #acknowledged(
    mind: string,
    received: Parameters<typeof draftAck>[0]["received"],
    now: Instant,
  ): Answer | undefined {
    const signer = this.#signer(mind);
    const log = this.#archive.view(now).log(mind);
    if (signer === undefined || !log.ok) return undefined;
    const state = latestState(log.value);
    if (!state.keys.includes(signer.publicKey)) return undefined;
    const at = formatTimestamp(now);
    const ack = draftAck({ received, recipient: mind, at, created: at });
    const proof = createProofSync(
      ack,
      { verificationMethod: formatKeyRef(mind, state.versionId, signer.publicKey), created: at },
      signer,
    );
    return withProofs(ack, [proof]) as unknown as Answer;
  }

  /**
   * Layer 1, 13.2: a record that arrives at a mind's inbox.
   *
   * @param record - A `Packet` or a `Sealed` record, already read.
   * @returns What to answer with `202`: an `Ack`, or `{ "stored": true }`.
   * @throws OipError `not-found` if the host does not serve the mind;
   *   `forbidden` for a record addressed to another; `expired`,
   *   `invalid-proof` or `invalid-record` for a packet that 12.4 does not
   *   let a recipient accept; `stale-version` if the host cannot judge the
   *   packet because it holds no log of its sender.
   * @throws HttpFailure 507 if the mind's mailbox is full.
   * @throws Unavailable if the judging was cut short.
   */
  deliver(mind: string, record: OipRecord): Answer {
    this.#served(mind);
    if (record.type === "Sealed") return this.post(mind, record);
    const shown = (record as { proof?: unknown }).proof;
    const digests = new Set(
      (Array.isArray(shown) ? shown : []).flatMap((proof) => {
        try {
          return [proofDigest(proof as never)];
        } catch {
          return [];
        }
      }),
    );
    return this.#archive.witnessing((seen, now) => {
      const view = this.#archive.view(now);
      // Judged as it will be once its proofs are recorded as seen now. They are recorded
      // only if the packet is kept: one that is refused leaves nothing behind.
      const received = receivePacket(record, {
        address: mind,
        now,
        view: {
          log: (other) => view.log(other),
          evidence: {
            eventSeen: (id) => view.evidence.eventSeen(id),
            proofSeen: (digest) =>
              view.evidence.proofSeen(digest) ?? (digests.has(digest) ? now : undefined),
          },
        },
        accepted: (id) => this.#store.answered(mind, id) !== undefined,
        window: this.#limits.window,
      });
      if (!received.ok) {
        if (received === cutShort())
          throw new Unavailable("the packet could not be judged just now");
        const from = (record as { from?: unknown }).from;
        throw refusalOf(received.issues, typeof from === "string" && view.log(from).ok);
      }
      const { id, duplicate, forgetAfter, judged } = received.value;
      if (duplicate) return this.#store.answered(mind, id) ?? STORED;
      this.#room(mind, record as unknown as JsonObject);
      witnessRecord(judged, now, seen);
      const answer = this.#acknowledged(mind, received.value, now) ?? STORED;
      this.#put(mind, id, record as unknown as JsonObject, now);
      this.#store.accept(mind, id, forgetAfter, answer);
      return answer;
    });
  }

  /**
   * Layer 1, 13.5: a record posted to a mind's mailbox. It is kept as it
   * is, for the mind to judge when it drains the mailbox.
   *
   * @param record - A `Packet` or a `Sealed` record, already read.
   * @throws OipError `not-found` if the host does not serve the mind;
   *   `invalid-record` for any other record; `forbidden` for one addressed
   *   to another.
   * @throws HttpFailure 507 if the mailbox is full.
   */
  post(mind: string, record: OipRecord): Answer {
    this.#served(mind);
    if (record.type !== "Sealed" && record.type !== "Packet") {
      throw new OipError("invalid-record", "a mailbox takes a Packet or a Sealed record", {
        clause: "L1 13.5",
      });
    }
    // Its form is checked, and no more: the mind judges what it drains.
    const formed = validateRecordOfType(record.type, record);
    if (!formed.ok) {
      if (formed === cutShort()) throw new Unavailable("the record could not be judged just now");
      const [first] = formed.issues;
      throw new OipError("invalid-record", first.message, {
        clause: first.clause,
        issues: formed.issues,
      });
    }
    const to = (record as { to?: unknown }).to;
    const addressed =
      record.type === "Sealed" ? to === mind : Array.isArray(to) && to.includes(mind);
    if (!addressed) {
      throw new OipError("forbidden", "the record is addressed to another mind", {
        clause: "L1 12.4",
      });
    }
    this.#archive.witnessing((_seen, now) => {
      this.#room(mind, record as unknown as JsonObject);
      this.#put(mind, contentId(record), record as unknown as JsonObject, now);
    });
    return STORED;
  }

  /**
   * Layer 1, 13.5: the items of a mind's mailbox after a cursor.
   *
   * @param after - The cursor of the last item the owner has. 0 for the first.
   * @param limit - The most items in the page. A page is bounded in bytes
   *   as well, and may hold fewer.
   * @returns The items, and the cursor to ask after next if there are more.
   */
  drain(mind: string, after: number, limit: number): { items: MailboxItem[]; next?: number } {
    this.#served(mind);
    const items = this.#store.after(mind, after, limit, this.#limits.pageBytes);
    const last = items.at(-1)?.cursor;
    return last !== undefined && this.#store.more(mind, last) ? { items, next: last } : { items };
  }

  /** Layer 1, 13.5: removes an item from a mind's mailbox. Whether it was there. */
  remove(mind: string, cursor: number): boolean {
    this.#served(mind);
    return this.#db.transaction(() => this.#store.remove(mind, cursor));
  }

  /**
   * Lets go of what is kept only for a time. A host calls it now and then.
   *
   * @returns How many things went.
   */
  prune(now: Instant): number {
    return this.#db.transaction(() => this.#store.prune(now, now - this.#limits.retention));
  }

  /**
   * Asks to be told when a mind's mailbox has something new: for the mind's
   * own instance, which holds a socket open (13.4).
   *
   * @returns How to stop being told.
   */
  subscribe(mind: string, listener: () => void): () => void {
    const listeners = this.#listeners.get(mind) ?? new Set();
    listeners.add(listener);
    this.#listeners.set(mind, listeners);
    return () => {
      listeners.delete(listener);
      if (listeners.size === 0) this.#listeners.delete(mind);
    };
  }
}
