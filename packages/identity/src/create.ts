// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Writing identity-log events (Layer 1, Section 3) and signing them. */

import {
  createProof,
  createProofSync,
  formatControlKeyRef,
  formatKeyRef,
  type Signer,
  type SyncSigner,
  withProofs,
} from "@oip/core";
import type { Fork, Genesis, IdentityEvent, Proof, Retire, Update } from "@oip/schema";

import type { IdentityState } from "./state.ts";

/** An event before it is signed. */
export type Unsigned<T extends IdentityEvent> = Omit<T, "proof">;

// The members a draft and its signing fill in are written out in each type:
// a name for them would be part of the public types without being exported.

/** What the author of a `Genesis` chooses (Layer 1, 3.6). */
export type GenesisFields = Omit<Genesis, "oip" | "type" | "created" | "proof">;
/** What the author of an `Update` chooses (Layer 1, 3.7). The chain members follow from the log. */
export type UpdateFields = Omit<
  Update,
  "oip" | "type" | "created" | "proof" | "mind" | "seq" | "prev"
>;
/** What the author of a `Fork` chooses (Layer 1, 3.8). */
export type ForkFields = Omit<Fork, "oip" | "type" | "created" | "proof" | "mind" | "seq" | "prev">;
/** What the author of a `Retire` chooses (Layer 1, 3.10). */
export type RetireFields = Omit<
  Retire,
  "oip" | "type" | "created" | "proof" | "mind" | "seq" | "prev"
>;

/** What the next event of a log is chained to: the mind, and the position and content ID of the latest event. */
export type LogHead = Pick<IdentityState, "mind" | "seq" | "head">;

/** Layer 1, 3.2: the members that chain an event to the one before it. */
function chained(after: LogHead, created: string) {
  return { oip: "1", mind: after.mind, seq: after.seq + 1, prev: after.head, created } as const;
}

/**
 * A `Genesis`, not yet signed. Its content ID will be the mind's address, so
 * every member chosen here is fixed for good.
 */
export function draftGenesis(created: string, fields: GenesisFields): Unsigned<Genesis> {
  return { ...fields, oip: "1", type: "Genesis", created };
}

/**
 * An `Update` that follows the state `after`, not yet signed.
 *
 * @param after - The state after the latest event of the log, or just its `mind`, `seq` and `head`.
 */
export function draftUpdate(
  after: LogHead,
  created: string,
  fields: UpdateFields = {},
): Unsigned<Update> {
  return { ...fields, ...chained(after, created), type: "Update" };
}

/** A `Fork` that follows the state `after`, not yet signed. It acknowledges `fields.child`. */
export function draftFork(after: LogHead, created: string, fields: ForkFields): Unsigned<Fork> {
  return { ...fields, ...chained(after, created), type: "Fork" };
}

/** A `Retire` that follows the state `after`, not yet signed. No event can follow it. */
export function draftRetire(
  after: LogHead,
  created: string,
  fields: RetireFields = {},
): Unsigned<Retire> {
  return { ...fields, ...chained(after, created), type: "Retire" };
}

/**
 * Who signs an identity event (Layer 1, 3.11): a control key, which signs
 * with its own `control-key-ref`; or a member, with one of its invocation
 * keys, named by a `key-ref` that pins a version of the member's own log.
 *
 * A control key signs one event. Destroy its private part once that event is
 * published (Layer 1, 7.4): a control key that still exists can sign a
 * second event for the same position.
 */
export type EventSigner<S extends Signer = Signer> =
  | { readonly control: S }
  | {
      /** The member's address. */
      readonly member: string;
      /** A version of the member's log at which the key is an invocation key. */
      readonly versionId: string;
      readonly invocation: S;
    };

function methodOf<S extends Signer>(by: EventSigner<S>): [S, string] {
  return "control" in by
    ? [by.control, formatControlKeyRef(by.control.publicKey)]
    : [by.invocation, formatKeyRef(by.member, by.versionId, by.invocation.publicKey)];
}

function atLeastOne(signers: readonly unknown[]): void {
  if (signers.length === 0)
    throw new TypeError("an identity event is signed by at least one signer");
}

/**
 * Signs an event with each signer. Every proof covers the event without its
 * proofs (core 5.3), so their order does not matter.
 *
 * @param created - The `created` of each proof. Default: the event's own.
 * @throws TypeError if there is no signer.
 * @throws OipError if the event is malformed. No signer is asked for anything then.
 */
export async function signEvent<T extends Unsigned<IdentityEvent>>(
  event: T,
  signers: readonly EventSigner[],
  created: string = event.created,
): Promise<T & { proof: Proof[] }> {
  atLeastOne(signers);
  const proofs: Proof[] = [];
  for (const by of signers) {
    const [signer, verificationMethod] = methodOf(by);
    proofs.push(await createProof(event, { verificationMethod, created }, signer));
  }
  return withProofs(event, proofs) as T & { proof: Proof[] };
}

/** `signEvent` for signers that hold their keys in memory and answer at once. */
export function signEventSync<T extends Unsigned<IdentityEvent>>(
  event: T,
  signers: readonly EventSigner<SyncSigner>[],
  created: string = event.created,
): T & { proof: Proof[] } {
  atLeastOne(signers);
  const proofs = signers.map((by) => {
    const [signer, verificationMethod] = methodOf(by);
    return createProofSync(event, { verificationMethod, created }, signer);
  });
  return withProofs(event, proofs) as T & { proof: Proof[] };
}
