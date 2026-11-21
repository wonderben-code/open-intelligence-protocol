// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What minds deal with each other by: delegation (Layer 1, Section 11) and
 * the records of the Mind Web (Layer 2): Intents, Offers, Commitments and
 * Receipts.
 *
 * A record binds whoever it counts for (Layer 2, Section 7), and for
 * nobody else: by a mind's own key, or by the key of a delegate whose proof
 * names a chain of delegations that covers the record. Whether it counts,
 * and what its status is (Section 8), is computed here from the records the
 * client holds and the identity logs its resolvers serve, fetched afresh
 * each time: a log held from before a proof was first seen does not judge
 * it (core 9.4).
 */

import {
  bytesToBase64url,
  contentId,
  formatRecordRef,
  formatTimestamp,
  type Instant,
  isMindAddress,
  type JsonObject,
  OipError,
  type OipRecord,
  parseRecordRef,
  parseTimestamp,
} from "@oip/core";
import {
  authorityOf,
  draftDelegation,
  draftRevocation,
  draftSubDelegation,
  sentFor,
  witnessProofs,
} from "@oip/delegation";
import { FirstSeen, type IdentityView, type JudgedRecord, judgeRecord } from "@oip/identity";
import {
  type AuthorityItem,
  type Collective as Charter,
  type Commitment,
  type Delegation,
  type Intent,
  type Offer,
  type Receipt,
  type Revocation,
  validateRecord,
} from "@oip/schema";
import { countsFor, type Status, status, WebRecordSet, withHeld } from "@oip/web";

import { accepted } from "./accepted.ts";
import type { Lookup } from "./lookup.ts";
import type { Own } from "./publish.ts";
import { TransportError } from "./transport.ts";

/** What a mind grants another (Layer 1, 11.1). */
export interface Grant {
  /** The mind that is given the authority. */
  readonly delegate: string;
  /**
   * What it may do (11.2): `/oip/sign/Intent`, `/oip/sign/Offer`,
   * `/oip/sign/Commitment` or `/oip/sign/Receipt` to sign records of that
   * type for the mind, `/oip/send` to send packets on its behalf, or a
   * command of an extension.
   */
  readonly command: string;
  /**
   * What must hold of each record it signs so (11.3). A policy constrains
   * only what it selects: constrain every term that matters, and exclude
   * the delegate itself as a party. Default: no statement, which constrains
   * nothing.
   */
  readonly policy?: Delegation["policy"];
  /** Until when, as a timestamp. No longer than its purpose needs: expiry is what bounds a revocation that is missed. */
  readonly expires: string;
  /** From when, as a timestamp. */
  readonly notBefore?: string;
}

/**
 * How a mind signs for another: by the chain of delegations that lets it
 * (Layer 1, 11.6), or, for a collective it is a member of, by the charter
 * that gives it a role (Layer 2, 7.1, item 4). One of the two.
 */
export interface Acting {
  /**
   * One chain, root first: the first is by the mind acted for, and the last
   * names this mind as its delegate.
   */
  readonly chain?: readonly Delegation[];
  /**
   * The collective's charter in force, in which this mind is assigned to a
   * role with a power that covers the record.
   */
  readonly charter?: Charter;
  /**
   * Whether the proof carries the delegations, or the charter, whole, or
   * names them. A proof that names them counts only for a verifier that
   * holds them. Default: `records`.
   */
  readonly as?: "records" | "references";
}

/** The members of a record that are its maker's to choose. Its author is this mind unless it says. */
export type Fields<T extends { author: string }> = Omit<
  T,
  "oip" | "type" | "created" | "proof" | "author"
> & { readonly author?: string };

type Made = Intent | Offer | Commitment | Receipt | Charter;
type Failure = OipError | TransportError;
const isFailure = (error: unknown): error is Failure =>
  error instanceof OipError || error instanceof TransportError;

/** The most minds whose logs are fetched to judge one record. */
const MAX_MINDS = 64;
/** An address of a mind, wherever it stands in a string: alone, or at the head of a reference. */
const ADDRESS = /did:oip:[a-z2-7]{20,}/gu;

/** Every address of a mind that a value names, at any depth. */
function mindsIn(value: unknown, into: Set<string>): void {
  if (typeof value === "string") {
    for (const [address] of value.matchAll(ADDRESS)) into.add(address);
  } else if (Array.isArray(value)) {
    for (const item of value) mindsIn(item, into);
  } else if (typeof value === "object" && value !== null) {
    for (const member of Object.values(value)) mindsIn(member, into);
  }
}

/**
 * Every mind a record names: in its members, and in its proofs, whose
 * signers and whose delegations' authors are named nowhere else.
 */
function named(judged: JudgedRecord, into: Set<string>): void {
  mindsIn(judged.record, into);
  for (const { proof } of judged.proofs) mindsIn(proof, into);
}

/**
 * The minds whose logs decide whether a record counts, and for whom: its
 * author, its sender and whoever it says it was sent for, its parties, and
 * every mind its proofs name, which are their signers and the authors of
 * the delegations and charters they rest on.
 *
 * A record names other minds too, wherever its author chose to write an
 * address. Those decide nothing, and are asked for after these.
 */
function deciding(judged: JudgedRecord, into: Set<string>): void {
  const { author, from, parties, provenance } = judged.record as {
    author?: unknown;
    from?: unknown;
    parties?: unknown;
    provenance?: { onBehalfOf?: unknown } | null;
  };
  mindsIn([author, from, provenance?.onBehalfOf], into);
  for (const party of Array.isArray(parties) ? (parties as unknown[]) : []) {
    mindsIn((party as { mind?: unknown } | null)?.mind, into);
  }
  for (const { proof } of judged.proofs) mindsIn(proof, into);
}

/** What a proof names to count for another mind (core 5.2): one chain, or one charter. */
function authorityFor(acting: Acting | undefined): readonly AuthorityItem[] | undefined {
  if (acting === undefined) return undefined;
  const { chain, charter, as = "records" } = acting;
  if (chain !== undefined && charter === undefined) return authorityOf(chain, as);
  if (charter !== undefined && chain === undefined) {
    return [as === "records" ? charter : formatRecordRef(charter.author, contentId(charter))];
  }
  throw new OipError(
    "invalid-record",
    "a proof acts for another mind by one chain of delegations, or by one charter",
    { clause: "core 5.2" },
  );
}

/**
 * A client's own record of when it first obtained proofs: for each, by its
 * digest (core 9.4), the time. It is evidence that the proof existed then
 * (core 9.4, item 1), and it is the only evidence a verifier has for a proof
 * that nobody else witnessed.
 */
export type Sightings = Readonly<Record<string, Instant>>;

/**
 * What `witnessProofs` is given to write to, in place of the client's own
 * record, so that each proof it names is dealt with as one function says:
 * the proofs of a record, and of the delegations its proofs carry whole.
 */
class EachProof extends FirstSeen {
  readonly #each: (digest: string, at: Instant) => Instant;

  constructor(each: (digest: string, at: Instant) => Instant) {
    super();
    this.#each = each;
  }

  override sawProof(digest: string, at: Instant): Instant {
    return this.#each(digest, at);
  }
}

/** What reading records needs of the world. */
export interface ReadingContext {
  /**
   * A way to ask for the logs of minds and for what they published. The
   * reader reads the clock of this lookup, and no other: the times of what
   * the lookup found and of what the reader holds are compared.
   */
  readonly lookup: Lookup;
}

/**
 * How a reader has its own evidence of when a proof existed (core 9.4, item 1).
 *
 * - `live`: it takes records in as they are made, and notes when it first
 *   obtained each proof. A mind's own client does.
 * - `history`: it reads what was made before it looked. The order in which
 *   it happens to take such records in says nothing of the order in which
 *   they were made, so it holds every proof as of its latest look: its only
 *   own evidence is that the proof existed by then.
 */
export type Sight = "live" | "history";

/**
 * Records, held and judged, by a client that needs no key to do it.
 *
 * A record counts for a mind, and a Commitment stands as it stands, by the
 * records and the logs alone (Layer 2, Sections 7 and 8). Anyone can work
 * that out: a mind for the records it deals by, and a stranger for
 * records it only reads. This is the working out. `Mind` has it, and signs
 * besides.
 *
 * Hold every record that bears on the question: a Commitment, and the
 * Receipts about it. The logs of the minds they name are asked for when a
 * question is put, after the proofs were first seen (core 9.4).
 *
 * A reader made with nothing more said reads history. What it holds, it
 * holds as of its latest look, in whatever order it took the records in: a
 * Revocation counts against a signature made under the delegation it takes
 * back, whichever of the two was read first (Layer 1, 11.4, item 7). Its
 * verdict on a signature that rests on something with an end, a delegation
 * that expires or a key that was removed, is the verdict of now: evidence
 * that the signature was made in time is what a feed with anchored
 * checkpoints gives (core 9.7), and a reader has none of its own.
 */
export class Reader {
  readonly #at: { readonly lookup: Lookup; readonly clock: Lookup["clock"] };
  readonly #live: boolean;
  readonly #records = new WebRecordSet();
  /**
   * The records held, by content ID, each as the copy with the proofs of
   * every copy seen that verify. A record none of whose proofs verifies is
   * held as it was given: it counts for nobody.
   */
  readonly #held = new Map<string, OipRecord>();
  /** The Revocations held that have counted for their authors, by content ID. */
  readonly #revoked = new Set<string>();
  /** For a reader of history: the proofs it has taken in, by digest. */
  readonly #read = new Set<string>();
  /** For a reader of history: when it last took anything in. */
  #asOf: Instant | undefined;

  /**
   * @param sight - How the reader has its own evidence of time. Default: `history`.
   */
  constructor(at: ReadingContext, sight: Sight = "history") {
    this.#at = { lookup: at.lookup, clock: at.lookup.clock };
    this.#live = sight === "live";
  }

  /**
   * The logs and the evidence a record is judged by.
   *
   * For a reader of history, a proof it has taken in existed by its latest
   * look, or by when a witness the lookup trusts first saw it, if that is
   * earlier. The lookup's own first sight of such a proof, at the moment it
   * happened to be fetched, is not used.
   */
  #context(): { identity: IdentityView; records: WebRecordSet } {
    const { view, witnessed } = this.#at.lookup;
    if (this.#live) return { identity: view, records: this.#records };
    const asOf = this.#asOf;
    const read = this.#read;
    return {
      identity: {
        log: (mind) => view.log(mind),
        evidence: {
          eventSeen: (id) => view.evidence.eventSeen(id),
          proofSeen: (digest) => {
            if (!read.has(digest)) return view.evidence.proofSeen(digest);
            const witness = witnessed.proofSeen(digest);
            return witness !== undefined && (asOf === undefined || witness < asOf) ? witness : asOf;
          },
        },
      },
      records: this.#records,
    };
  }

  /** Holds a record: see `Mind.hold`. */
  hold(record: unknown, seen?: Sightings): string {
    return this.#take(record, seen).id;
  }

  /**
   * Takes a record in, and gives it back as the client holds it: judged,
   * with the proofs of every copy the client has seen (Layer 2, Section 2).
   */
  #take(
    record: unknown,
    kept?: Sightings,
    now: Instant = this.#at.clock.now(),
  ): { id: string; judged: JudgedRecord } {
    const own = this.#at;
    const id = accepted(this.#records.add(record), "invalid-record", "that is no record");
    const judged = withHeld(
      accepted(judgeRecord(record), "invalid-record", "that is no record"),
      this.#records,
    );
    // The copy held has every proof that verifies, of every copy seen, and no other (Layer 2,
    // Section 2). A copy with fewer proofs, or with proofs that verify nothing, takes none away.
    const proofs = judged.proofs.map(({ proof }) => proof);
    this.#held.set(
      id,
      (proofs.length === 0 ? judged.record : { ...judged.record, proof: proofs }) as OipRecord,
    );
    if (!this.#live) {
      // A reader of history holds what it holds as of its latest look.
      witnessProofs(
        judged,
        now,
        new EachProof((digest, at) => {
          this.#read.add(digest);
          return at;
        }),
      );
      if (this.#asOf === undefined || now > this.#asOf) this.#asOf = now;
      return { id, judged };
    }
    // Its proofs are first seen now, by this client (core 9.4, item 1): a delegation that a
    // later proof names is judged by when it was first held. Or they were first seen when
    // the client's own record, kept from before, says: never later than now, whatever it says.
    const { seen } = own.lookup;
    witnessProofs(
      judged,
      now,
      kept === undefined
        ? seen
        : new EachProof((digest, now) => {
            const before = Object.hasOwn(kept, digest) ? kept[digest] : undefined;
            return seen.sawProof(digest, typeof before === "bigint" && before < now ? before : now);
          }),
    );
    return { id, judged };
  }

  /** When the client first obtained the proofs of a record it holds: see `Mind.sightings`. */
  sightings(id: string): Sightings {
    const record = this.#held.get(id);
    const found: Record<string, Instant> = {};
    if (record === undefined) return found;
    const judged = accepted(judgeRecord(record), "invalid-record", "that is no record");
    const { seen } = this.#at.lookup;
    const asOf = this.#asOf;
    // Each was seen when the record was taken in: the earliest time held for it is the answer.
    // A reader of history has one time for all it holds.
    witnessProofs(
      judged,
      this.#at.clock.now(),
      new EachProof(
        (digest, now) =>
          (found[digest] = this.#live || asOf === undefined ? seen.sawProof(digest, now) : asOf),
      ),
    );
    return found;
  }

  /** The records held: see `Mind.records`. */
  held(): OipRecord[] {
    return [...this.#held.values()];
  }

  /**
   * A record as the client holds it, judged, with the logs of every mind it
   * names fetched afresh after its proofs were first seen (core 9.4).
   */
  async #fresh(record: unknown): Promise<{ judged: JudgedRecord; now: Instant }> {
    const own = this.#at;
    const { id, judged } = this.#take(record);
    const now = own.clock.now();
    // The minds whose logs decide, first: a record's author chooses what else it names, and in
    // what order, and must not so choose whose log is left unasked.
    const minds = new Set<string>();
    deciding(judged, minds);
    // And the minds of what it rests on, among the records held: delegations it names,
    // Receipts about it, what supersedes it, Commitments that resolve it.
    const resting = [
      ...this.#records.receiptsAbout(id),
      ...this.#records.resolversOf(id),
      ...this.#records.supersedersOf(id),
    ];
    for (const related of resting) {
      witnessProofs(
        related,
        now,
        this.#live
          ? own.lookup.seen
          : new EachProof((digest, at) => {
              this.#read.add(digest);
              return at;
            }),
      );
      deciding(related, minds);
    }
    if (minds.size > MAX_MINDS) {
      throw new OipError(
        "too-large",
        `the record rests on the logs of ${String(minds.size)} minds, and a client asks for ${String(MAX_MINDS)} to judge one record`,
        { clause: "core 9.4" },
      );
    }
    // Then whoever else it names, as far as the bound goes: they decide nothing.
    named(judged, minds);
    for (const related of resting) named(related, minds);
    for (const mind of [...minds].slice(0, MAX_MINDS)) {
      try {
        await own.lookup.resolve(mind);
      } catch (error) {
        // A mind whose log cannot be had signs nothing that counts here.
        if (!isFailure(error)) throw error;
      }
    }
    return { judged, now };
  }

  /** Whether a record counts for a mind: see `Mind.countsFor`. */
  async countsFor(record: unknown, mind: string): Promise<boolean> {
    const { judged } = await this.#fresh(record);
    return countsFor(judged, mind, this.#context());
  }

  /** The status of a record: see `Mind.statusOf`. */
  async status(record: unknown): Promise<Status> {
    const { judged, now } = await this.#fresh(record);
    return accepted(
      status(judged, now, this.#context()),
      "invalid-record",
      "that record has no status",
    );
  }

  /**
   * Whether a packet was sent for the mind it names in
   * `provenance.onBehalfOf` (Layer 1, 11.2): its sender's proof carries a
   * chain from that mind that covers `/oip/send`.
   *
   * @returns The mind, or `undefined` if the packet names none, or names one in words only.
   */
  async sentFor(packet: unknown): Promise<string | undefined> {
    // What is no packet was sent for nobody.
    const subject = (packet as { provenance?: { onBehalfOf?: unknown } | null } | null | undefined)
      ?.provenance?.onBehalfOf;
    if (typeof subject !== "string") return undefined;
    const { judged } = await this.#fresh(packet);
    return sentFor(judged, subject, this.#context()) === undefined ? undefined : subject;
  }

  /** What a record's proofs list as their authority: delegations carried whole, or named by reference. */
  #authorityOf(record: unknown): unknown[] {
    const proofs = (record as { proof?: unknown } | null)?.proof;
    return (Array.isArray(proofs) ? (proofs as unknown[]) : []).flatMap((proof) => {
      const authority = (proof as { authority?: unknown } | null)?.authority;
      return Array.isArray(authority) ? (authority as unknown[]) : [];
    });
  }

  /**
   * Whether the delegations a record's proofs rest on stand now: see
   * `Mind.delegationsStand`.
   */
  async delegationsStand(record: unknown): Promise<boolean> {
    const now = this.#at.clock.now();
    for (const item of this.#authorityOf(record)) {
      // Carried whole, or named and held.
      let delegation = item as
        { type?: unknown; author?: unknown; expires?: unknown } | null | undefined;
      if (typeof item === "string") {
        const named = parseRecordRef(item);
        delegation = named === undefined ? undefined : this.#held.get(named.contentId);
        // One that is named and not held shows nothing.
        if (delegation === undefined) return false;
      }
      // A charter is authority too, and is not taken back by a Revocation.
      if (delegation?.type !== "Delegation") continue;
      const { author, expires } = delegation;
      if (!isMindAddress(author)) return false;
      // One with no end that can be read is no delegation (Layer 1, 11.1).
      const until = parseTimestamp(expires);
      if (until === undefined || until <= now) return false;
      const revoked = formatRecordRef(author, contentId(delegation));
      for (const held of this.#held.values()) {
        const { type, revokes } = held as { type: string; revokes?: unknown };
        if (type !== "Revocation" || revokes !== revoked) continue;
        // Its author's own word, whenever it was first seen.
        if (await this.countsFor(held, author)) return false;
      }
    }
    return true;
  }

  /**
   * Reads what the authors of the delegations a record rests on have
   * revoked, and holds it: see `Mind.holdRevocations`.
   */
  async holdRevocations(record: unknown): Promise<number> {
    const { lookup } = this.#at;
    const authors = new Set<string>();
    for (const item of this.#authorityOf(record)) {
      // A delegation is carried whole, or named by its reference: either says whose it is.
      const author =
        typeof item === "string"
          ? parseRecordRef(item)?.mind
          : (item as { author?: unknown } | null)?.author;
      if (isMindAddress(author)) authors.add(author);
    }
    let held = 0;
    for (const author of authors) {
      let entries;
      try {
        ({
          feed: { entries },
        } = await lookup.feed(author));
      } catch (error) {
        // A mind with no home has no feed, and has published nothing there.
        if (error instanceof OipError && error.code === "not-found") continue;
        throw error;
      }
      for (const { entry } of entries) {
        if (entry.objectType !== "Revocation" || this.#revoked.has(entry.object)) continue;
        // A copy that is held shows nothing unless it counts for its author. Anyone who has
        // read a Revocation can give out the same record, by its content ID, under a
        // signature that is nobody's: with that copy held, the author's own is fetched still.
        const before = this.#held.get(entry.object);
        if (before === undefined || !(await this.countsFor(before, author))) {
          const fetched = await lookup.record(author, entry.object);
          this.hold(fetched.record);
          held += 1;
          continue;
        }
        // Its proofs are kept with every copy that comes later: it need not be asked of again.
        this.#revoked.add(entry.object);
      }
    }
    return held;
  }

  /**
   * Holds the records a packet carries (Layer 1, 12.2): its body, or its
   * parts, where they are records.
   *
   * They came together, and are first seen together: at one reading of the
   * clock. A record whose proof names a delegation by reference counts by
   * a delegation that another part carries, whichever of the two comes
   * first in the packet (Layer 1, 11.4, item 1; 11.6).
   */
  holdCarried(content: unknown): void {
    const now = this.#at.clock.now();
    const parts = (content as { parts?: unknown } | null | undefined)?.parts;
    for (const part of Array.isArray(parts) ? (parts as unknown[]) : [content]) {
      // What a packet carries is data: a part that is no object carries no record.
      const { mediaType, body } = (part ?? {}) as { mediaType?: unknown; body?: unknown };
      if (mediaType !== "application/oip+json") continue;
      // What a packet carries is data: what is no record is no record, and is not held.
      if (this.#records.add(body).ok) this.#take(body, undefined, now);
    }
  }
}

/** A record of Layer 2 as its content carries it in a packet (Layer 1, 12.2). */
export function carried(record: object): { mediaType: string; body: JsonObject } {
  return { mediaType: "application/oip+json", body: record as JsonObject };
}

/** What a mind makes of the records it deals by: it reads them as anyone can, and signs its own. */
export class Dealings extends Reader {
  readonly #own: Own;

  constructor(own: Own) {
    // A mind takes records in as they are made, and notes when it first obtained each proof.
    super(own, "live");
    this.#own = own;
  }

  /** Signs a delegation: see `Mind.delegate`. */
  async delegate(grant: Grant): Promise<Delegation> {
    const own = this.#own;
    const draft = draftDelegation(formatTimestamp(own.clock.now()), {
      author: own.address,
      subject: own.address,
      delegate: grant.delegate,
      command: grant.command,
      ...(grant.policy === undefined ? {} : { policy: grant.policy }),
      ...(grant.notBefore === undefined ? {} : { notBefore: grant.notBefore }),
      expires: grant.expires,
      nonce: bytesToBase64url(own.randomness.bytes(16)),
    });
    return this.#signed<Delegation>(draft, undefined);
  }

  /** Passes on part of what the mind was delegated: see `Mind.subDelegate`. */
  async subDelegate(chain: readonly Delegation[], grant: Grant): Promise<Delegation> {
    const own = this.#own;
    const parent = chain.at(-1);
    if (parent?.delegate !== own.address) {
      throw new OipError("forbidden", "the chain does not end with a delegation to this mind", {
        clause: "L1 11.4",
      });
    }
    const { proof: _, ...unsigned } = parent;
    let draft: Omit<Delegation, "proof">;
    try {
      // The next link: the same subject, every statement of the parent's policy, and no more
      // than the parent grants (11.4, item 4).
      draft = draftSubDelegation(unsigned, formatTimestamp(own.clock.now()), {
        delegate: grant.delegate,
        command: grant.command,
        ...(grant.policy === undefined ? {} : { policy: grant.policy }),
        ...(grant.notBefore === undefined ? {} : { notBefore: grant.notBefore }),
        expires: grant.expires,
        nonce: bytesToBase64url(own.randomness.bytes(16)),
      });
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      throw new OipError("forbidden", error.message, { clause: "L1 11.4", cause: error });
    }
    return this.#signed<Delegation>(draft, undefined);
  }

  /** Signs the revocation of a delegation: see `Mind.revoke`. */
  async revoke(delegation: Delegation): Promise<Revocation> {
    const own = this.#own;
    if (delegation.author !== own.address) {
      throw new OipError("forbidden", "a delegation is revoked by the mind that made it", {
        clause: "L1 11.5",
      });
    }
    const { proof: _, ...unsigned } = delegation;
    const draft = draftRevocation(formatTimestamp(own.clock.now()), unsigned);
    return this.#signed<Revocation>(draft, undefined);
  }

  /** Makes a record of Layer 2: see `Mind.intent`, `offer`, `commitment` and `receipt`. */
  make<T extends Made>(type: T["type"], fields: Fields<T>, acting: Acting | undefined): Promise<T> {
    const own = this.#own;
    const { author, ...rest } = fields;
    return this.#signed<T>(
      {
        oip: "1",
        type,
        author: author ?? own.address,
        created: formatTimestamp(own.clock.now()),
        ...rest,
      },
      acting,
    );
  }

  /** Adds the mind's proof to a record: see `Mind.cosign`. */
  cosign<T extends object>(record: T, acting: Acting | undefined): Promise<T> {
    return this.#signed<T>(record, acting);
  }

  /** Signs a record, checks that it is one, and holds it. */
  async #signed<T extends object>(record: object, acting: Acting | undefined): Promise<T> {
    const signed = await this.#own.sign(record, authorityFor(acting));
    accepted(validateRecord(signed), "invalid-record", "that is no record of its type");
    this.hold(signed);
    return signed as unknown as T;
  }
}
