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
  type JsonObject,
  OipError,
  type OipRecord,
} from "@oip/core";
import {
  authorityOf,
  draftDelegation,
  draftRevocation,
  draftSubDelegation,
  sentFor,
  witnessProofs,
} from "@oip/delegation";
import { type JudgedRecord, judgeRecord } from "@oip/identity";
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

/** What a mind makes of the records it deals by. */
export class Dealings {
  readonly #own: Own;
  readonly #records = new WebRecordSet();
  /** The records held, by content ID, each as the copy with every proof seen of it. */
  readonly #held = new Map<string, OipRecord>();

  constructor(own: Own) {
    this.#own = own;
  }

  /** Holds a record: see `Mind.hold`. */
  hold(record: unknown): string {
    return this.#take(record).id;
  }

  /**
   * Takes a record in, and gives it back as the client holds it: judged,
   * with the proofs of every copy the client has seen (Layer 2, Section 2).
   */
  #take(record: unknown): { id: string; judged: JudgedRecord } {
    const own = this.#own;
    const id = accepted(this.#records.add(record), "invalid-record", "that is no record");
    const judged = withHeld(
      accepted(judgeRecord(record), "invalid-record", "that is no record"),
      this.#records,
    );
    this.#held.set(id, judged.record as OipRecord);
    // Its proofs are first seen now, by this client (core 9.4, item 1): a delegation that a
    // later proof names is judged by when it was first held.
    witnessProofs(judged, own.clock.now(), own.lookup.seen);
    return { id, judged };
  }

  /** The records held: see `Mind.records`. */
  held(): OipRecord[] {
    return [...this.#held.values()];
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

  /**
   * A record as the client holds it, judged, with the logs of every mind it
   * names fetched afresh after its proofs were first seen (core 9.4).
   */
  async #fresh(record: unknown): Promise<{ judged: JudgedRecord; now: Instant }> {
    const own = this.#own;
    const { id, judged } = this.#take(record);
    const now = own.clock.now();
    const minds = new Set<string>();
    named(judged, minds);
    // And the minds of what it rests on, among the records held: delegations it names,
    // Receipts about it, what supersedes it, Commitments that resolve it.
    for (const related of [
      ...this.#records.receiptsAbout(id),
      ...this.#records.resolversOf(id),
      ...this.#records.supersedersOf(id),
    ]) {
      witnessProofs(related, now, own.lookup.seen);
      named(related, minds);
    }
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
    return countsFor(judged, mind, { identity: this.#own.lookup.view, records: this.#records });
  }

  /** The status of a record: see `Mind.statusOf`. */
  async status(record: unknown): Promise<Status> {
    const { judged, now } = await this.#fresh(record);
    return accepted(
      status(judged, now, { identity: this.#own.lookup.view, records: this.#records }),
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
    const subject = (packet as { provenance?: { onBehalfOf?: unknown } }).provenance?.onBehalfOf;
    if (typeof subject !== "string") return undefined;
    const { judged } = await this.#fresh(packet);
    const context = { identity: this.#own.lookup.view, records: this.#records };
    return sentFor(judged, subject, context) === undefined ? undefined : subject;
  }

  /** Holds the records a packet carries (Layer 1, 12.2): its body, or its parts, where they are records. */
  holdCarried(content: unknown): void {
    const parts = (content as { parts?: unknown }).parts;
    for (const part of Array.isArray(parts) ? (parts as unknown[]) : [content]) {
      const { mediaType, body } = part as { mediaType?: unknown; body?: unknown };
      if (mediaType !== "application/oip+json") continue;
      // What a packet carries is data: what is no record is no record, and is not held.
      if (this.#records.add(body).ok) this.hold(body);
    }
  }
}

/** A record of Layer 2 as its content carries it in a packet (Layer 1, 12.2). */
export function carried(record: object): { mediaType: string; body: JsonObject } {
  return { mediaType: "application/oip+json", body: record as JsonObject };
}
