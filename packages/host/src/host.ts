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
 * - **The feed** (10.1, 13.1) is the one the mind brings, entry by entry,
 *   with every record an entry lists. The host holds one entry at each
 *   position, so a mind whose instances all publish through its host has a
 *   single writer (10.3).
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
import {
  type IdentityView,
  type JudgedRecord,
  judgeRecord,
  latestState,
  ownSignedTime,
  witnessRecord,
} from "@oip/identity";
import { draftAck, receivePacket } from "@oip/net";
import {
  cutShort,
  cutShortCount,
  type Entry,
  isRecordType,
  validateExtensionRecord,
  validateRecord,
  validateRecordOfType,
} from "@oip/schema";
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
  /** The most bytes of records in one page of a mailbox or of a feed. A page holds one item at least. */
  readonly pageBytes: number;
  /** The most bytes of records the host serves for one mind by their content IDs. */
  readonly objectBytes: number;
  /** The most entries in the feed of one mind. */
  readonly feedEntries: number;
}

const DAY = 86_400_000_000_000n;

/**
 * A thousand items and 64 MiB for each mailbox, kept 30 days; an hour's
 * memory of packets; pages of 4 MiB; 256 MiB of records and a million feed
 * entries for each mind.
 */
export const DEFAULT_HOST_LIMITS: HostLimits = {
  mailboxItems: 1000,
  mailboxBytes: 64 * 1024 * 1024,
  retention: 30n * DAY,
  window: 3_600_000_000_000n,
  pageBytes: 4 * 1024 * 1024,
  objectBytes: 256 * 1024 * 1024,
  feedEntries: 1_000_000,
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

/** The logs and the evidence held, with some proofs counted as first seen at `now`. */
function seenNow(view: IdentityView, digests: ReadonlySet<string>, now: Instant): IdentityView {
  return {
    log: (mind) => view.log(mind),
    evidence: {
      eventSeen: (id) => view.evidence.eventSeen(id),
      proofSeen: (digest) =>
        view.evidence.proofSeen(digest) ?? (digests.has(digest) ? now : undefined),
    },
  };
}

/**
 * The time a record counts from as its author's own, or `undefined` if it
 * is not signed by the mind's own authority.
 *
 * @throws Unavailable if the check was cut short: that says nothing of the record.
 */
function ownTime(judged: JudgedRecord, mind: string, view: IdentityView): Instant | undefined {
  const before = cutShortCount();
  const time = ownSignedTime(judged, mind, view);
  if (time === undefined && cutShortCount() !== before) {
    throw new Unavailable("the record could not be judged just now");
  }
  return time;
}

/** The problem for a value that is no record of the form asked for. */
function malformed(
  refused: { readonly issues: readonly [{ message: string; clause: string }, ...unknown[]] },
  prefix = "",
): never {
  if (refused === cutShort()) throw new Unavailable("the record could not be judged just now");
  const [first] = refused.issues;
  throw new OipError("invalid-record", prefix + first.message, {
    clause: first.clause,
    issues: refused.issues as never,
  });
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
        view: seenNow(view, digests, now),
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
    if (!formed.ok) malformed(formed);
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
   * Layer 1, 10.2, 13.1: keeps a record a mind brings, to serve it by its
   * content ID. A record held already is replaced by the copy brought: a
   * record gains proofs, and its content ID stays.
   *
   * Its form is checked and its proofs are not: a feed may list records
   * of other minds, whose logs the host need not hold. Whoever fetches the
   * record judges it.
   *
   * @returns The record's content ID, and whether the host did not hold it before.
   * @throws OipError `not-found` if the host does not serve the mind;
   *   `invalid-record` for what is no record.
   * @throws HttpFailure 507 if the mind has no room left.
   */
  keep(mind: string, record: OipRecord): { id: string; fresh: boolean } {
    this.#served(mind);
    const formed = isRecordType(record.type)
      ? validateRecord(record)
      : validateExtensionRecord(record);
    if (!formed.ok) malformed(formed);
    const id = contentId(record);
    return this.#db.transaction(() => {
      const held = this.#store.objectHeld(mind, id);
      const bytes = Buffer.byteLength(JSON.stringify(record));
      if (this.#store.objectBytes(mind) - (held?.bytes ?? 0) + bytes > this.#limits.objectBytes) {
        throw new HttpFailure(507, "Insufficient Storage");
      }
      this.#store.keep(mind, id, record.type, record as unknown as JsonObject);
      return { id, fresh: held === undefined };
    });
  }

  /** Layer 1, 13.1: a record the host serves for a mind by its content ID, if it holds it. */
  object(mind: string, id: string): JsonObject | undefined {
    this.#served(mind);
    return this.#store.object(mind, id);
  }

  /**
   * Layer 1, 10.1: adds entries to the feed the host serves for a mind.
   *
   * An entry is taken if it is the mind's own (signed by a valid
   * operational key, judged as first seen now), stands at the end of the
   * feed held and names the entry before it, and lists a record the host
   * holds for the mind (10.2). An entry the host holds already is passed
   * over. All of the entries given are taken, or none.
   *
   * The host holds one entry at each position. Another valid entry at a
   * position it holds is refused, not served beside the first: that would
   * be feed equivocation (10.3), and a mind that publishes through its
   * host is kept from it. If the entry held there no longer verifies, as
   * after its key was declared compromised (10.4), it and what follows it
   * are dropped, and the feed goes on with the entry given.
   *
   * @returns How many entries were added.
   * @throws OipError `not-found` if the host does not serve the mind;
   *   `invalid-record` for a value that is no entry of the mind's, that
   *   does not stand at the end of the feed, or that lists a record the
   *   host does not hold; `invalid-proof` for one the mind did not sign;
   *   `duplicity` for one at a position where the host holds another.
   * @throws HttpFailure 507 if the feed is as long as the host keeps one.
   */
  append(mind: string, entries: readonly unknown[]): number {
    this.#served(mind);
    return this.#archive.witnessing((seen, now) => {
      const view = this.#archive.view(now);
      let added = 0;
      for (const [index, value] of entries.entries()) {
        const where = `entry ${index}: `;
        const judged = judgeRecord(value);
        if (!judged.ok) malformed(judged, where);
        const { type, author } = judged.value.record as { type: string; author?: unknown };
        if (type !== "Entry" || author !== mind) {
          throw new OipError("invalid-record", `${where}it is no entry of this mind's feed`, {
            clause: "L1 10.1",
          });
        }
        const entry = judged.value.record as Entry;
        const id = contentId(entry);
        if (this.#store.entryAt(mind, entry.seq)?.id === id) continue;
        const digests = new Set(judged.value.proofs.map((proof) => proof.digest));
        if (ownTime(judged.value, mind, seenNow(view, digests, now)) === undefined) {
          throw new OipError(
            "invalid-proof",
            `${where}it is not signed by a valid operational key of the mind`,
            { clause: "L1 10.1" },
          );
        }
        const length = this.#length(mind, entry.seq, view, where);
        if (entry.seq !== length) {
          throw new OipError(
            "invalid-record",
            `${where}the feed held here has ${length} entries, and the next is at seq ${length}`,
            { clause: "L1 10.1" },
          );
        }
        if (entry.seq > 0 && this.#store.entryAt(mind, entry.seq - 1)?.id !== entry.prev) {
          throw new OipError("invalid-record", `${where}it does not name the entry before it`, {
            clause: "L1 10.1",
          });
        }
        if (this.#store.objectHeld(mind, entry.object)?.type !== entry.objectType) {
          throw new OipError(
            "invalid-record",
            `${where}the host holds no ${entry.objectType} record with the content ID it lists: bring the record first`,
            { clause: "L1 10.2" },
          );
        }
        if (length >= this.#limits.feedEntries) throw new HttpFailure(507, "Insufficient Storage");
        witnessRecord(judged.value, now, seen);
        this.#store.append(mind, entry.seq, id, judged.value.record as unknown as JsonObject);
        added++;
      }
      return added;
    });
  }

  /**
   * How long a mind's feed is for an entry given at `seq`: as long as it
   * is held, unless the entry held at `seq` no longer verifies. Then the
   * feed ends before it (10.4).
   *
   * @throws OipError `duplicity` if the entry held at `seq` is valid.
   */
  #length(mind: string, seq: number, view: IdentityView, where: string): number {
    const length = this.#store.feedLength(mind);
    const held = seq < length ? this.#store.entryAt(mind, seq) : undefined;
    if (held === undefined) return length;
    const judged = judgeRecord(held.entry);
    if (!judged.ok && judged === cutShort()) {
      throw new Unavailable("the feed could not be judged just now");
    }
    if (judged.ok && ownTime(judged.value, mind, view) !== undefined) {
      throw new OipError(
        "duplicity",
        `${where}the feed holds another valid entry at seq ${seq}, and a feed has one at each (10.3)`,
        { clause: "L1 10.3" },
      );
    }
    this.#store.truncate(mind, seq);
    return seq;
  }

  /**
   * Layer 1, 13.1: a page of a mind's feed.
   *
   * @param after - The `seq` of the last entry the reader has, or
   *   `undefined` to start at `seq` 0.
   * @returns The entries in order, and what to pass as `after` next if there are more.
   */
  feed(
    mind: string,
    after: number | undefined,
    limit: number,
  ): { entries: JsonObject[]; next?: number } {
    this.#served(mind);
    const from = after === undefined ? 0 : after + 1;
    const entries = this.#store.entriesFrom(mind, from, limit, this.#limits.pageBytes);
    const last = from + entries.length - 1;
    return entries.length > 0 && last + 1 < this.#store.feedLength(mind)
      ? { entries, next: last }
      : { entries };
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
