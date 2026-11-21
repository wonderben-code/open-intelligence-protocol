// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Writing delegations and revocations (Layer 1, 11.1, 11.4 and 11.5). They are signed with `@oip/core`. */

import { contentId, formatRecordRef, parseTimestamp } from "@oip/core";
import type { Delegation, PolicyStatement, Revocation } from "@oip/schema";

import { covers } from "./command.ts";

/** What the author of a `Delegation` chooses (Layer 1, 11.1). */
export type DelegationFields = Omit<Delegation, "oip" | "type" | "created" | "proof">;

/**
 * A `Delegation`, not yet signed. Sign it with the author's own key and
 * `createProof` of `@oip/core`, which refuses one that is not well formed:
 * a delegate that is its own author, a reserved command, a policy that is
 * none.
 */
export function draftDelegation(
  created: string,
  fields: DelegationFields,
): Omit<Delegation, "proof"> {
  return { ...fields, oip: "1", type: "Delegation", created };
}

/** What a delegate chooses when it passes on what it was given. */
export interface SubDelegationFields {
  /** The mind the authority is passed on to. */
  readonly delegate: string;
  /** 8 to 64 characters, new for each delegation. */
  readonly nonce: string;
  /** A command the parent's covers. Default: the parent's own. */
  readonly command?: string;
  /** Statements added to the parent's, every one of which is kept. */
  readonly policy?: readonly PolicyStatement[];
  readonly notBefore?: string;
  /** No later than the parent's. Default: the parent's own. */
  readonly expires?: string;
}

/**
 * A `Delegation` by which the delegate of `parent` passes on what it was
 * given, or less, not yet signed. It is the next link of a chain (Layer 1,
 * 11.4, item 4): for the same subject, with a command the parent's covers,
 * every statement of the parent's policy, and an expiry no later than the
 * parent's.
 *
 * @throws TypeError if `fields` asks for more than `parent` grants: a
 *   command the parent's does not cover, or a later expiry. A verifier would
 *   not count a proof that relied on such a link.
 */
export function draftSubDelegation(
  parent: Omit<Delegation, "proof">,
  created: string,
  fields: SubDelegationFields,
): Omit<Delegation, "proof"> {
  const command = fields.command ?? parent.command;
  if (!covers(parent.command, command)) {
    throw new TypeError(`the delegation grants ${parent.command}, which does not cover ${command}`);
  }
  const expires = fields.expires ?? parent.expires;
  const [ends, limit] = [parseTimestamp(expires), parseTimestamp(parent.expires)];
  if (ends === undefined || limit === undefined || ends > limit) {
    throw new TypeError("a delegation that passes one on expires no later than it does");
  }
  const policy = [...(parent.policy ?? []), ...(fields.policy ?? [])];
  return {
    oip: "1",
    type: "Delegation",
    author: parent.delegate,
    delegate: fields.delegate,
    subject: parent.subject,
    command,
    ...(policy.length === 0 ? {} : { policy }),
    ...(fields.notBefore === undefined ? {} : { notBefore: fields.notBefore }),
    expires,
    nonce: fields.nonce,
    created,
  };
}

/**
 * A `Revocation` of a delegation by the delegation's author (Layer 1,
 * 11.5), not yet signed. It takes effect from the time a verifier can show
 * the signed revocation existed, so publish it where verifiers look.
 */
export function draftRevocation(
  created: string,
  delegation: Omit<Delegation, "proof">,
): Omit<Revocation, "proof"> {
  const { proof: _proof, ...content } = delegation as Delegation;
  return {
    oip: "1",
    type: "Revocation",
    author: content.author,
    revokes: formatRecordRef(content.author, contentId(content)),
    created,
  };
}

/**
 * Layer 1, 11.6: the `authority` of a proof that relies on a chain of
 * delegations, root first. The delegations are given whole, so that a
 * verifier need not hold them, or by reference.
 */
export function authorityOf(
  chain: readonly Delegation[],
  as: "records" | "references" = "records",
): (Delegation | string)[] {
  return chain.map((delegation) =>
    as === "records" ? delegation : formatRecordRef(delegation.author, contentId(delegation)),
  );
}
