// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Delegation chains (Layer 1, 11.4 and 11.6): whether a proof by one mind
 * counts for another, through the delegations the proof itself lists.
 *
 * The list is checked exactly as it is given, root first. Nothing is
 * searched for: not another order, not a subset, not a delegation the proof
 * does not name. So a proof acts for at most one mind besides its signer,
 * and the signer's choice to act for that mind is itself signed.
 */

import {
  canonicalize,
  CLOCK_SKEW,
  contentId,
  type Instant,
  parseRecordRef,
  parseTimestamp,
  type VerifiedProof,
} from "@oip/core";
import {
  type IdentityView,
  type JudgedRecord,
  type JudgeOptions,
  judgeRecord,
  operationalProofTime,
  ownSignedTime,
} from "@oip/identity";
import type { Delegation, JsonValue, Validation } from "@oip/schema";

import { covers, isDelegableType, signCommand } from "./command.ts";
import { evaluatePolicy } from "./policy.ts";
import type { RecordView } from "./records.ts";
import { no, ok, type Rejection } from "./result.ts";
import { revokedTime } from "./revocation.ts";

/** Layer 1, 11.4 and Section 19: the most delegations in one chain. */
export const MAX_CHAIN = 8;

/** What a delegated proof is judged against. */
export interface DelegationContext {
  /** The identity logs held, and the evidence of time. */
  readonly identity: IdentityView;
  /** The records held: delegations named by reference, and revocations. */
  readonly records: RecordView;
  /** core 8.3: the extension namespaces the caller implements, for delegations given inline. */
  readonly understood?: JudgeOptions["understood"];
}

/** One link of a chain: the delegation, judged, and its content ID. */
interface Link {
  readonly judged: JudgedRecord;
  readonly delegation: Delegation;
  readonly id: string;
}

const at = (index: number) => `/authority/${index}`;

/**
 * Layer 1, 11.6: the delegations a proof lists, each as the record it is.
 * An entry is a delegation given whole, or a reference to one the verifier
 * holds.
 */
function links(proof: VerifiedProof, context: DelegationContext): Validation<readonly Link[]> {
  const listed: unknown = proof.proof.authority;
  if (!Array.isArray(listed) || listed.length < 1 || listed.length > MAX_CHAIN) {
    return no(
      `a proof that relies on delegation lists 1 to ${MAX_CHAIN} delegations`,
      "L1 11.6",
      "/authority",
    );
  }
  const chain: Link[] = [];
  for (const [index, entry] of (listed as readonly unknown[]).entries()) {
    let judged: JudgedRecord | undefined;
    if (typeof entry === "string") {
      const ref = parseRecordRef(entry);
      judged = ref === undefined ? undefined : context.records.record(ref.contentId);
      if (judged === undefined) {
        return no(
          "the verifier does not hold the delegation this entry names",
          "L1 11.6",
          at(index),
        );
      }
    } else {
      const given = judgeRecord(entry, { understood: context.understood ?? [] });
      if (!given.ok) {
        const [first] = given.issues;
        return no(
          `the delegation given here is not valid: ${first.message}`,
          first.clause,
          at(index),
        );
      }
      judged = given.value;
    }
    if (judged.record.type !== "Delegation") {
      return no("an entry of a delegation chain is a Delegation", "L1 11.6", at(index));
    }
    chain.push({ judged, delegation: judged.record as Delegation, id: contentId(judged.record) });
  }
  return ok(chain);
}

/** A timestamp of a validated record, which is one. */
function instant(text: string): Instant {
  return parseTimestamp(text) ?? 0n;
}

/**
 * Layer 1, 11.4, items 1 to 7, for the delegations exactly as listed.
 *
 * @param time - `t(p)`, the evaluation time of the proof that relies on the chain.
 */
function chainHolds(
  chain: readonly Link[],
  judged: JudgedRecord,
  need: string,
  time: Instant,
  principal: string,
  signer: string,
  context: DelegationContext,
): Rejection | undefined {
  const [root] = chain;
  const last = chain.at(-1);
  if (root === undefined || last === undefined)
    return no("the chain is empty", "L1 11.6", "/authority");
  // Items 2 and 3: from the principal, link by link, to the signer.
  if (root.delegation.author !== principal) {
    return no(
      "the first delegation of a chain is by the mind the proof acts for",
      "L1 11.4",
      at(0),
    );
  }
  for (const [index, { delegation }] of chain.entries()) {
    if (delegation.subject !== principal) {
      return no(
        "every delegation of a chain has the principal as its subject",
        "L1 11.4",
        at(index),
      );
    }
    const next = chain[index + 1];
    if (next !== undefined && delegation.delegate !== next.delegation.author) {
      return no("each delegation's delegate is the author of the next", "L1 11.4", at(index + 1));
    }
  }
  if (last.delegation.delegate !== signer) {
    return no(
      "the last delegation of a chain names the signer of the proof",
      "L1 11.4",
      at(chain.length - 1),
    );
  }
  for (const [index, { judged: link, delegation, id }] of chain.entries()) {
    // Item 1: signed by its author's own authority, and not after the proof that uses it.
    const signed = ownSignedTime(link, delegation.author, context.identity);
    if (signed === undefined) {
      return no("the delegation is not signed by its author's own authority", "L1 11.4", at(index));
    }
    if (signed > time) {
      return no(
        "the delegation was signed after the proof that relies on it",
        "L1 11.4",
        at(index),
      );
    }
    // Item 5: within its time, with the tolerance of core 9.1 either way.
    if (delegation.notBefore !== undefined && time < instant(delegation.notBefore) - CLOCK_SKEW) {
      return no(
        "the proof is evaluated more than 300 seconds before the delegation's notBefore",
        "L1 11.4",
        at(index),
      );
    }
    if (time > instant(delegation.expires) + CLOCK_SKEW) {
      return no(
        "the proof is evaluated more than 300 seconds after the delegation expires",
        "L1 11.4",
        at(index),
      );
    }
    // Item 7: not revoked by the time the proof is evaluated.
    const revokedAt = revokedTime(id, delegation.author, context.records, context.identity);
    if (revokedAt !== undefined && revokedAt <= time) {
      return no(
        "the delegation was revoked before the proof that relies on it",
        "L1 11.5",
        at(index),
      );
    }
    // Item 4: each delegation grants no more than the one before it.
    const parent = chain[index - 1]?.delegation;
    if (parent !== undefined) {
      if (!covers(parent.command, delegation.command)) {
        return no(
          "the delegation's command is not covered by the one before it",
          "L1 11.4",
          at(index),
        );
      }
      const kept = new Set((delegation.policy ?? []).map((statement) => canonicalize(statement)));
      if (!(parent.policy ?? []).every((statement) => kept.has(canonicalize(statement)))) {
        return no(
          "the delegation drops a policy statement of the one before it",
          "L1 11.4",
          at(index),
        );
      }
      if (instant(delegation.expires) > instant(parent.expires)) {
        return no("the delegation expires after the one before it", "L1 11.4", at(index));
      }
    }
  }
  // Item 6: the last command covers what the record needs, and every policy holds for it.
  if (!covers(last.delegation.command, need)) {
    return no(`the chain does not grant ${need}`, "L1 11.4", at(chain.length - 1));
  }
  for (const [index, { delegation }] of chain.entries()) {
    const held = evaluatePolicy(delegation.policy, judged.record as unknown as JsonValue);
    if (!held.ok) {
      const [first] = held.issues;
      return no(
        `the delegation's policy does not hold for the record: ${first.message}`,
        first.clause,
        `${at(index)}/policy${first.path}`,
      );
    }
  }
  return undefined;
}

/** What a delegated proof is asked for, when it is not the signing of the record. */
export interface DelegatedOptions {
  /** The command the chain must cover. Default: `/oip/sign/<type>` for the record's type. */
  readonly need?: string;
}

/**
 * Layer 1, 11.4 and 11.6: whether one proof on a record counts for
 * `principal` through the delegation chain it lists, and if so its
 * evaluation time `t(p)`.
 *
 * The proof is by a valid operational key of its signer (Layer 1, 6.1), a
 * mind other than the principal. Its `authority` lists the chain, root
 * first, and the chain is valid for the record at `t(p)`.
 *
 * It answers with the reason when the proof does not count, naming the
 * entry of `authority` at fault. It never throws.
 */
export function delegatedProofTime(
  judged: JudgedRecord,
  proof: VerifiedProof,
  principal: string,
  context: DelegationContext,
  options?: DelegatedOptions,
): Validation<Instant> {
  const type = judged.record.type;
  const need = options?.need ?? (isDelegableType(type) ? signCommand(type) : undefined);
  if (need === undefined) {
    return no(`a ${type} cannot be signed under delegation`, "L1 11.2", "/type");
  }
  const method = proof.method;
  if (method.kind !== "key") {
    return no("a control key signs identity events only", "L1 6.1", "/verificationMethod");
  }
  if (method.mind === principal) {
    return no(
      "a mind does not act for itself through a delegation",
      "L1 11.4",
      "/verificationMethod",
    );
  }
  const chain = links(proof, context);
  if (!chain.ok) return chain;
  const time = operationalProofTime(type, proof, context.identity);
  if (!time.ok) return time;
  const broken = chainHolds(chain.value, judged, need, time.value, principal, method.mind, context);
  return broken ?? ok(time.value);
}

/**
 * Layer 1, 11.6: the earliest evaluation time at which a record is signed
 * for `principal` through a delegation, by any proof on it. `undefined` if
 * it never is. A verdict is a time: compare it with the moment asked about,
 * and with the record's own `expires` (core 9.6), which is not applied here.
 *
 * @param options - `need` as for `delegatedProofTime`; `signer`, to count
 *   only proofs by that mind.
 */
export function delegatedTime(
  judged: JudgedRecord,
  principal: string,
  context: DelegationContext,
  options?: DelegatedOptions & { readonly signer?: string },
): Instant | undefined {
  let earliest: Instant | undefined;
  for (const proof of judged.proofs) {
    if (proof.proof.authority === undefined) continue;
    if (
      options?.signer !== undefined &&
      (proof.method.kind !== "key" || proof.method.mind !== options.signer)
    ) {
      continue;
    }
    const time = delegatedProofTime(judged, proof, principal, context, options);
    if (time.ok && (earliest === undefined || time.value < earliest)) earliest = time.value;
  }
  return earliest;
}
