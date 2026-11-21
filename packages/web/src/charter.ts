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
  operationalProofEvaluation,
  ownSignedTime,
  stateAt,
  type VerifiedLog,
} from "@oip/identity";
import {
  finding,
  type JsonValue,
  judging,
  type PolicyStatement,
  type Validation,
} from "@oip/schema";

import { referenced, withCopy } from "./records.ts";
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
 * A charter is completed when it is first signed for the collective, judged
 * with the proofs of every copy held, a copy given with the question among
 * them: a copy that leaves out the proofs that completed it early does not
 * make it a later charter. And a charter that another names in `supersedes`
 * is in force at no time from that other's completion on, so that a
 * collective can end a charter for good, whoever signs it later.
 *
 * It answers with a result. Which charter is in force decides who may sign
 * for the collective, and an older charter is in force only for as long as
 * no later one is found: so the answer is never given for a check that
 * could not be made ([ADR-0010](../../../docs/adr/0010-checks-cut-short.md)).
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
): Validation<string | undefined> {
  return judging(() => ok(charterAt(mind, time, context, also)));
}

/** The charter, as `charterInForce` answers when no check is cut short. */
function charterAt(
  mind: string,
  time: Instant,
  context: DelegationContext,
  also: readonly JudgedRecord[],
): string | undefined {
  const known = new Map<string, JudgedRecord>();
  for (const charter of [...context.records.chartersOf(mind), ...also]) {
    const record = charter.record as { readonly type: string; readonly author?: unknown };
    if (record.type !== "Collective" || record.author !== mind) continue;
    const id = contentId(charter.record);
    const held = known.get(id);
    known.set(id, held === undefined ? charter : withCopy(held, charter));
  }
  /** Each charter completed by `time`, with when. */
  const completed = new Map<string, Instant>();
  for (const [id, charter] of known) {
    const signed = ownSignedTime(charter, mind, context.identity);
    if (signed !== undefined && signed <= time) completed.set(id, signed);
  }
  const replaced = new Set<string>();
  for (const id of completed.keys()) {
    const earlier = referenced((known.get(id)?.record as { supersedes?: unknown }).supersedes);
    if (earlier !== undefined) replaced.add(earlier);
  }
  let best: { readonly id: string; readonly signed: Instant } | undefined;
  for (const id of [...completed.keys()].sort()) {
    const signed = completed.get(id);
    if (signed === undefined || replaced.has(id)) continue;
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
  return judging(() => proofTimeByRole(judged, proof, mind, log, context));
}

/** The time, as `roleProofTime` answers when no check is cut short. */
function proofTimeByRole(
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
  const evaluated = operationalProofEvaluation(type, proof, context.identity);
  if (!evaluated.ok) return evaluated;
  const time = evaluated.value.time;
  // core 9.4: who the members are at the proof's time is read from the collective's
  // log, which must be known up to the evidence for the proof. A copy older than
  // that may lack the event that removed the signer.
  if (log.asOf < evaluated.value.evidenced) {
    return no(
      "the collective's log was obtained before the evidence for this proof: it may lack a later event",
      "core 9.4",
      "/verificationMethod",
    );
  }
  // Layer 1, 7.3: from its first conflicting event on, the members of a duplicitous
  // collective are not known, and nobody signs for it.
  for (const tail of log.branchTails) {
    if (time >= tail.time) {
      return no(
        "the collective is duplicitous, and the proof is evaluated at or after its first conflicting event",
        "L1 7.3",
        "/verificationMethod",
      );
    }
  }
  const state = stateAt(log, time);
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
  if (charterAt(mind, time, context, [charter]) !== contentId(charter.record)) {
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
        return ok(time);
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
  // A proof whose check was cut short has not been found not to count: no time is given
  // then, and not the time of another proof as if it were the earliest (ADR-0010).
  return finding(() => {
    let earliest: Instant | undefined;
    for (const proof of judged.proofs) {
      if (proof.proof.authority === undefined) continue;
      if (signer !== undefined && (proof.method.kind !== "key" || proof.method.mind !== signer))
        continue;
      const time = proofTimeByRole(judged, proof, mind, log, context);
      if (time.ok && (earliest === undefined || time.value < earliest)) earliest = time.value;
    }
    return earliest;
  });
}
