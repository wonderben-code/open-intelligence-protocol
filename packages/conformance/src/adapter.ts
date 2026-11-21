// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** How the suite calls an implementation. */

import type {
  AckCase,
  ChainCase,
  CheckpointCase,
  FeedCase,
  HelloCase,
  JsonObject,
  LocationCase,
  Log,
  LogCopy,
  ParticipantCase,
  ReceiveCase,
  Seen,
} from "./vectors.ts";

/**
 * What the verifier holds when it judges a case: the baseline of the vectors,
 * and whatever the case adds. The adapter merges them, because replacing a
 * mind's log means knowing its address, which is the implementation's work.
 */
export interface VerifierView {
  /** The baseline identity logs, one per mind. */
  readonly logs: readonly Log[];
  /** Logs that replace the baseline logs of the same minds. */
  readonly extraLogs: readonly Log[];
  /**
   * Further copies of a mind's log, conflicting or not (Layer 1, Section 7).
   * A copy holds what a source served: its values need not all be events.
   */
  readonly branches: readonly LogCopy[];
  /** The baseline records. */
  readonly records: readonly JsonObject[];
  /** Records the case adds. */
  readonly extraRecords: readonly JsonObject[];
  /**
   * Evidence of time (core 9.4), keyed by proof digest or by an identity
   * event's content ID. The map is partial: a proof or an event it does not
   * name is taken to have been obtained at its own `created` time, as a
   * witness that followed every log from the start would have obtained it.
   * When `seen` is `undefined`, that holds for every proof and event.
   */
  readonly seen: Seen | undefined;
}

/**
 * What a method answers for a case it does not judge yet. The case is then
 * reported as pending. It is never a pass, and it is not a way to fail
 * quietly: an implementation says it of a whole class of cases it has not
 * built, such as records signed through a delegation.
 */
export const NOT_JUDGED: unique symbol = Symbol("not judged");

/** An answer to a case: a verdict, or the statement that the implementation does not judge it yet. */
export type Answer = boolean | typeof NOT_JUDGED;

/** Whether a parent acknowledges a child that names it (Layer 1, 8.2). */
export type LineageStatus = "acknowledged" | "claimed";

/** How far a copy of a log verifies, for a verifier (Layer 1, 4.9). */
export interface LogIntake {
  /** The number of its events that verify, from the first. */
  readonly verified: number;
  /**
   * Of the event after them: `true` if the verifier cannot judge it, `false`
   * if it is invalid, and `null` if there is none because every event
   * verified.
   */
  readonly undecided: boolean | null;
}

/**
 * An answer to a case of Layer 1, Sections 10 and 12 to 16: whether its claim
 * holds, and what the implementation worked out on the way. The suite reads
 * `holds`. A differential test compares `value` too, so that two
 * implementations are compared on what they concluded and not only on a yes
 * or a no.
 */
export interface NetworkAnswer<T> {
  readonly holds: boolean;
  readonly value: T;
}

/** How far a feed verifies (Layer 1, 10.1 to 10.4). */
export interface FeedReading {
  /** How many entries verify, from `seq` 0. */
  readonly verified: number;
  /**
   * The content IDs of the valid entries at the place after them, in order,
   * when there is more than one (10.3). Empty otherwise.
   */
  readonly equivocation: readonly string[];
}

/** What a receiver took from what arrived (Layer 1, 12.4). */
export interface Received {
  /** The packet's content ID. */
  readonly packet: string;
  /** The broker that forwarded it, for a packet addressed to a query. */
  readonly broker: string | null;
}

/** What a receiver holds of one sending chain once every packet of a case has arrived (Layer 1, 14.3). */
export interface ChainReading {
  /** The content IDs of the packets it delivered, in the order of the chain. */
  readonly delivered: readonly string[];
  /** The two links at one place that it found, if it found any. */
  readonly equivocation: { readonly seq: number; readonly packets: readonly string[] } | null;
  /** How many packets wait behind a gap. */
  readonly ahead: number;
}

/**
 * An implementation under test. Every member is optional: a case whose kind
 * the adapter does not implement is reported as `pending`, never as passed.
 *
 * A method answers; it does not throw. A verifier's work is to judge hostile
 * input, so the suite fails any case on which a method throws, including a
 * negative case: crashing on an attack is not rejecting it. If your
 * implementation signals rejection with an exception, catch that exception
 * (and only that one) in the adapter and return `false`.
 */
export interface ConformanceAdapter {
  /** The implementation's name, for reports. */
  readonly name: string;

  /** `record` cases: whether the value is a well-formed record. */
  recordIsWellFormed?(record: unknown): boolean;

  /**
   * `json` cases: whether the text is JSON within the profile of core
   * Section 1: RFC 8259, valid Unicode, numbers that are integers within
   * the safe range whatever their spelling, and nesting of at most 64.
   */
  jsonIsWithinProfile?(text: string): boolean;

  /** `log` cases: whether the identity log verifies (Layer 1, Section 4). */
  logVerifies?(log: Log, view: VerifierView): boolean;

  /** `countsFor` cases: whether the record counts for the mind (Layer 2, 7.1). */
  countsFor?(record: JsonObject, mind: string, view: VerifierView): Answer;

  /**
   * The lineage of a mind (Layer 1, 8.2): for each parent its genesis names,
   * by the parent's address, whether the parent acknowledges it.
   */
  lineage?(child: string, view: VerifierView): Readonly<Record<string, LineageStatus>>;

  /**
   * The result of resolving an address (Layer 1, 5.2): `didDocument` and
   * `didDocumentMetadata`, from the mind's log alone, with no location record
   * and no verified alias. With `versionId`, the document as of that event
   * (Layer 1, 2.4).
   */
  didDocument?(mind: string, versionId: string | undefined, view: VerifierView): unknown;

  /**
   * How far a copy of a log verifies, and what the event after that is
   * (Layer 1, 4.9). Not a kind of case in the vectors: a question the
   * differential tests ask, so that two implementations are compared on
   * what a verifier may keep of a log, and not only on whether it verifies.
   */
  logIntake?(log: unknown, view: VerifierView): LogIntake;

  /** `sentFor` cases: whether the packet counts as sent on the mind's behalf (Layer 1, 11.2). */
  sentFor?(packet: JsonObject, mind: string, view: VerifierView): boolean;

  /** `status` cases: the status of a record at a time, given the records known (Layer 2, Section 8). */
  status?(of: JsonObject, records: readonly JsonObject[], at: string, view: VerifierView): string;

  /** `assurance` cases: the assurance level of a profile (Layer 0, 1.3). */
  assurance?(profile: JsonObject, view: VerifierView): string;

  /** `feed` cases: how far the entries verify as their author's feed (Layer 1, Section 10). */
  feed?(vectorCase: FeedCase, view: VerifierView): NetworkAnswer<FeedReading>;
  /**
   * `checkpoint` cases (Layer 1, 10.5). The value is the digests of the
   * proofs the checkpoint covers, in order, or `null` if it is not valid.
   */
  checkpoint?(
    vectorCase: CheckpointCase,
    view: VerifierView,
  ): NetworkAnswer<readonly string[] | null>;
  /** `receive` cases (Layer 1, 12.4). The value is `null` for what the receiver rejects. */
  receive?(vectorCase: ReceiveCase, view: VerifierView): NetworkAnswer<Received | null>;
  /**
   * `chain` cases (Layer 1, 14.3). The value is what the receiver holds of
   * each sending chain, by the sender's address, `#`, and the instance (or
   * nothing after the `#` when the chain names none).
   */
  chain?(
    vectorCase: ChainCase,
    view: VerifierView,
  ): NetworkAnswer<Readonly<Record<string, ChainReading>>>;
  /** `hello` cases (Layer 1, 13.3). The value is the mind authenticated, or `null`. */
  hello?(vectorCase: HelloCase, view: VerifierView): NetworkAnswer<string | null>;
  /**
   * `ack` cases (Layer 1, 13.2; core 9.4, item 4). The value is the digests
   * of the proofs the `Ack` is evidence for, in order, or `null` if it does
   * not acknowledge the packet.
   */
  ack?(vectorCase: AckCase, view: VerifierView): NetworkAnswer<readonly string[] | null>;
  /**
   * `location` cases (Layer 1, 15.2). The value is the content ID of the
   * current location record of the record's author, or `null`.
   */
  location?(vectorCase: LocationCase, view: VerifierView): NetworkAnswer<string | null>;
  /**
   * `participant` cases (Layer 1, 16.4). The value is the content ID of the
   * current profile of the record's author, or `null`.
   */
  participant?(vectorCase: ParticipantCase, view: VerifierView): NetworkAnswer<string | null>;
  /** The canonical form of a JSON value, as a string (core Section 2). */
  canonicalize?(value: unknown): string;

  /** The content ID of a record (core 3.1). */
  contentId?(record: JsonObject): string;

  /** The key hash of a Multikey string (core 3.4). */
  keyHash?(multikey: string): string;

  /**
   * A proof on the record, made with an Ed25519 private key (core 5.3). The
   * result is the whole proof object, `proofValue` included. Ed25519 signing
   * is deterministic, so the vectors' proofs reproduce byte for byte.
   */
  createProof?(record: JsonObject, request: ProofRequest, privateKey: Uint8Array): JsonObject;

  /**
   * Whether a proof verifies against a record: its members, its purpose, and
   * its signature under core 4.4 by the key its verification method names
   * (core 5.4). Whether that key may sign for anyone is another question,
   * which `countsFor` answers.
   */
  proofVerifies?(record: JsonObject, proof: unknown): boolean;
}

/** What the creator of a proof chooses (core 5.2). The record's type fixes the purpose. */
export interface ProofRequest {
  readonly verificationMethod: string;
  readonly created: string;
  readonly challenge?: string;
  readonly domain?: string;
  readonly authority?: readonly unknown[];
}

/** The adapter method each kind of case needs. */
export const METHOD_FOR_KIND = {
  log: "logVerifies",
  countsFor: "countsFor",
  sentFor: "sentFor",
  status: "status",
  assurance: "assurance",
  record: "recordIsWellFormed",
  json: "jsonIsWithinProfile",
  feed: "feed",
  checkpoint: "checkpoint",
  receive: "receive",
  chain: "chain",
  hello: "hello",
  ack: "ack",
  location: "location",
  participant: "participant",
} as const satisfies Record<string, keyof ConformanceAdapter>;
