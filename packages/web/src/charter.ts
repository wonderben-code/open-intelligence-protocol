// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Charters and the roles they give (Layer 2, 6.2 and 7.1 item 4): whether a
 * member's proof counts for its collective because the charter in force
 * lets that member sign such a record.
 */

import { contentId, type Instant, parseRecordRef, type VerifiedProof } from "@oip/core";
import {
  covers,
  type DelegationContext,
  evaluatePolicy,
  isDelegableCommand,
  isDelegableType,
  signCommand,
} from "@oip/delegation";
import {
  type JudgedRecord,
  judgeRecord,
  operationalProofTime,
  ownSignedTime,
  stateAt,
  type VerifiedLog,
} from "@oip/identity";
import type { JsonValue, PolicyStatement, Validation } from "@oip/schema";

import { no, ok } from "./result.ts";

/** A charter, as far as roles are read from it. */
interface Charter {
  readonly author: string;
  readonly roles?: Readonly<
    Record<
      string,
      { readonly powers?: readonly { command: string; policy?: readonly PolicyStatement[] }[] }
    >
  >;
  readonly assignments?: readonly { readonly mind: string; readonly role: string }[];
}

/**
 * Layer 2, 6.2: the charter of a collective in force at a time. It is the
 * one whose signature for the collective was completed most recently at or
 * before that time, and of two completed together, the one with the lower
 * content ID.
 *
 * @param also - A charter given with the question, such as one a proof
 *   carries whole, besides those the verifier holds.
 * @returns The charter's content ID, or `undefined` if none is in force.
 */
export function charterInForce(
  mind: string,
  time: Instant,
  context: DelegationContext,
  also: readonly JudgedRecord[] = [],
): string | undefined {
  const known = new Map<string, JudgedRecord>();
  for (const charter of [...context.records.chartersOf(mind), ...also]) {
    const record = charter.record as { readonly type: string; readonly author?: unknown };
    if (record.type === "Collective" && record.author === mind) {
      known.set(contentId(charter.record), charter);
    }
  }
  let best: { readonly id: string; readonly signed: Instant } | undefined;
  for (const id of [...known.keys()].sort()) {
    const charter = known.get(id);
    const signed = charter && ownSignedTime(charter, mind, context.identity);
    if (signed === undefined || signed > time) continue;
    // Later wins. Of two completed together, the first met: the lower content ID.
    if (best === undefined || signed > best.signed) best = { id, signed };
  }
  return best?.id;
}

/**
 * Layer 2, 7.1 item 4: whether one proof on a record counts for the
 * collective `mind` through a charter role, and if so its evaluation time.
 *
 * The proof is by a valid operational key of a mind that is a member of the
 * collective's state at `t(p)`. Its `authority` names exactly one charter of
 * the collective, by reference or whole, which is the charter in force at
 * `t(p)`. In it the member is assigned to a role with a power whose command
 * covers the signing of the record's type and whose policy holds for the
 * record. A reserved command grants nothing.
 *
 * @param log - The collective's verified log.
 */
export function roleProofTime(
  judged: JudgedRecord,
  proof: VerifiedProof,
  mind: string,
  log: VerifiedLog,
  context: DelegationContext,
): Validation<Instant> {
  const type = judged.record.type;
  if (!isDelegableType(type)) {
    return no(`a ${type} cannot be signed through a charter role`, "L2 7.2", "/type");
  }
  const need = signCommand(type);
  const listed: unknown = proof.proof.authority;
  if (!Array.isArray(listed) || listed.length !== 1) {
    return no("a proof that relies on a role names exactly one charter", "L2 7.1", "/authority");
  }
  const [entry] = listed as readonly unknown[];
  let charter: JudgedRecord | undefined;
  if (typeof entry === "string") {
    const ref = parseRecordRef(entry);
    charter = ref === undefined ? undefined : context.records.record(ref.contentId);
  } else {
    const given = judgeRecord(entry, { understood: context.understood ?? [] });
    charter = given.ok ? given.value : undefined;
  }
  const named = charter?.record as (Charter & { readonly type: string }) | undefined;
  if (charter === undefined || named?.type !== "Collective" || named.author !== mind) {
    return no("the proof does not name a charter of this collective", "L2 7.1", "/authority/0");
  }
  if (proof.method.kind !== "key") {
    return no("a control key signs identity events only", "L1 6.1", "/verificationMethod");
  }
  const member = proof.method.mind;
  const time = operationalProofTime(type, proof, context.identity);
  if (!time.ok) return time;
  const state = stateAt(log, time.value);
  if (
    state === undefined ||
    state.retired ||
    state.controller.kind !== "member" ||
    !state.controller.members.includes(member)
  ) {
    return no(
      "the signer is not a member of the collective at the proof's time",
      "L2 7.1",
      "/verificationMethod",
    );
  }
  if (charterInForce(mind, time.value, context, [charter]) !== contentId(charter.record)) {
    return no(
      "the charter named is not the one in force at the proof's time",
      "L2 6.2",
      "/authority/0",
    );
  }
  const roles = (named.assignments ?? [])
    .filter((assignment) => assignment.mind === member)
    .map((assignment) => assignment.role);
  for (const role of new Set(roles)) {
    const powers = Object.hasOwn(named.roles ?? {}, role)
      ? (named.roles?.[role]?.powers ?? [])
      : [];
    for (const power of powers) {
      if (
        isDelegableCommand(power.command) &&
        covers(power.command, need) &&
        evaluatePolicy(power.policy, judged.record as unknown as JsonValue).ok
      ) {
        return ok(time.value);
      }
    }
  }
  return no(
    "no role of the signer in the charter has a power that covers this record",
    "L2 7.1",
    "/authority/0",
  );
}

/**
 * Layer 2, 7.1 item 4: the earliest evaluation time at which a record is
 * signed for the collective `mind` through a charter role. `undefined` if it
 * never is. The record's own `expires` (core 9.6) is not applied here.
 *
 * @param signer - To count only proofs by that member.
 */
export function roleTime(
  judged: JudgedRecord,
  mind: string,
  log: VerifiedLog,
  context: DelegationContext,
  signer?: string,
): Instant | undefined {
  let earliest: Instant | undefined;
  for (const proof of judged.proofs) {
    if (proof.proof.authority === undefined) continue;
    if (signer !== undefined && (proof.method.kind !== "key" || proof.method.mind !== signer))
      continue;
    const time = roleProofTime(judged, proof, mind, log, context);
    if (time.ok && (earliest === undefined || time.value < earliest)) earliest = time.value;
  }
  return earliest;
}
