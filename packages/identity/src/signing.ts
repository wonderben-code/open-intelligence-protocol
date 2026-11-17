// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Key validity (Layer 1, Section 6) and signing by a mind's own authority:
 * one of its valid operational keys, or for a collective its threshold
 * (Layer 1, 9.5).
 */

import {
  checkSize,
  CLOCK_SKEW,
  type Instant,
  parseTimestamp,
  type PlacedProof,
  type VerifiedProof,
  verifyProofs,
} from "@oip/core";
import {
  type ExtensionRecord,
  isRecordType,
  type OipRecord,
  type Validation,
  validateExtensionRecord,
  validateJson,
  validateRecord,
} from "@oip/schema";

import type { IdentityView } from "./book.ts";
import { proofTime } from "./evidence.ts";
import { isJsonObject, no, ok } from "./result.ts";
import {
  compromisedSince,
  entryAt,
  latestState,
  removalTime,
  stateAt,
  type VerifiedLog,
} from "./state.ts";

/**
 * Layer 1, 6.1: the records that describe a mind's present state. A proof on
 * one counts only while its key is in the latest state the verifier knows.
 */
export const CURRENT_STATE_TYPES: readonly string[] = ["Location", "Participant", "Hello"];

/**
 * A record that is well formed, with the proofs on it that verify (core
 * 5.4). Whether any of them may sign for anyone is what the rest of this
 * module answers. Only `judgeRecord` makes one.
 */
export interface JudgedRecord {
  /** The record, as a validated copy. */
  readonly record: OipRecord | ExtensionRecord;
  /** The proofs that verify, each with its place in the record's `proof`. */
  readonly proofs: readonly PlacedProof[];
  /** The record's `expires`, if it has one. */
  readonly expires: Instant | undefined;
}

/**
 * Validates a record and verifies each proof on it (core 5.4, 5.5). A proof
 * that does not verify is left out: it never counts, and it never makes the
 * record malformed. It never throws.
 */
export function judgeRecord(record: unknown): Validation<JudgedRecord> {
  try {
    const plain = validateJson(record, "container");
    if (!plain.ok) return plain;
    const value = plain.value;
    const type = isJsonObject(value) ? value["type"] : undefined;
    const checked = isRecordType(type) ? validateRecord(value) : validateExtensionRecord(value);
    if (!checked.ok) return checked;
    const [first, ...rest] = checkSize(checked.value);
    if (first !== undefined) return { ok: false, issues: [first, ...rest] };
    const expires = (checked.value as { readonly expires?: string }).expires;
    return ok({
      record: checked.value,
      proofs: verifyProofs(checked.value).verified,
      expires: expires === undefined ? undefined : parseTimestamp(expires),
    });
  } catch {
    return no("the record could not be read as plain JSON data", "core 1.2");
  }
}

/** A proof by a valid operational key of a mind (Layer 1, 6.1), with its evaluation time. */
export interface CountedProof {
  /** The mind whose key it is. */
  readonly mind: string;
  /** `t(p)`, the proof's evaluation time (core 9.3). */
  readonly time: Instant;
  readonly proof: PlacedProof;
}

/**
 * Layer 1, 6.1: whether a proof that verifies is by a valid operational key
 * of the mind its verification method names, and if so its evaluation time.
 *
 * Items 5 and 7, the purpose and the signature, are what made the proof a
 * `VerifiedProof` (core 5.4). The rest is judged here, on evidence of time.
 *
 * @param type - The type of the record the proof is on.
 */
export function operationalProofTime(
  type: string,
  proof: VerifiedProof,
  view: IdentityView,
): Validation<Instant> {
  const method = proof.method;
  if (method.kind !== "key") {
    return no("a control key signs identity events and nothing else", "L1 3.11");
  }
  const held = view.log(method.mind);
  if (!held.ok) return held;
  const log = held.value;
  const evaluated = proofTime(proof.created, view.evidence.proofSeen(proof.digest));
  if (!evaluated.ok) return evaluated;
  const time = evaluated.value;
  // core 9.4 asks for the log as it stood no earlier than the evidence for the
  // proof. The proof is judged at its evaluation time, which can be later, so
  // the log must reach that far: a removal in between would decide it.
  if (log.asOf < time) {
    return no(
      "the signer's log was obtained before this proof's evaluation time: it may lack a later event",
      "core 9.4",
    );
  }
  const pinned = entryAt(log, method.versionId);
  if (pinned === undefined) {
    return no(
      log.duplicitous
        ? "the mind is duplicitous, and the proof is pinned to a version at or after the divergence"
        : "the proof is pinned to a version that is not in the signer's log",
      log.duplicitous ? "L1 7.3" : "L1 6.1",
    );
  }
  if (pinned.entry.state.retired) {
    return no("the proof is pinned to the version that retired the mind", "L1 3.10");
  }
  if (!pinned.entry.state.keys.includes(proof.key)) {
    return no("the key is not an operational key of the mind at the version named", "L1 6.1");
  }
  const removed = removalTime(log, pinned.position, proof.key, "keys");
  if (removed !== undefined && time >= removed) {
    return no(
      "the key was removed, or the mind retired, at or before the proof's evaluation time",
      "L1 6.1",
    );
  }
  const compromised = compromisedSince(log, proof.key);
  if (compromised !== undefined && time >= compromised) {
    return no("the key is declared compromised from before the proof's evaluation time", "L1 6.1");
  }
  if (CURRENT_STATE_TYPES.includes(type)) {
    const latest = latestState(log);
    if (log.duplicitous || latest.retired || !latest.keys.includes(proof.key)) {
      return no(
        `a ${type} describes the present, and the key is not in the latest state known of a mind in good standing`,
        log.duplicitous ? "L1 7.3" : "L1 6.1",
      );
    }
  }
  return ok(time);
}

/** core 9.6: a proof evaluated more than 300 seconds after its record's `expires` does not count. */
function inTime(judged: JudgedRecord, time: Instant): boolean {
  return judged.expires === undefined || time <= judged.expires + CLOCK_SKEW;
}

/**
 * The proofs on a record that are by valid operational keys of `mind`
 * (Layer 1, 6.1), each with its evaluation time, and none of them evaluated
 * after the record expired (core 9.6).
 */
export function operationalProofs(
  judged: JudgedRecord,
  mind: string,
  view: IdentityView,
): CountedProof[] {
  const counted: CountedProof[] = [];
  for (const proof of judged.proofs) {
    if (proof.method.kind !== "key" || proof.method.mind !== mind) continue;
    const time = operationalProofTime(judged.record.type, proof, view);
    if (time.ok && inTime(judged, time.value)) counted.push({ mind, time: time.value, proof });
  }
  return counted;
}

/** Every mind that was ever a member, in any state of the log. */
function membersEver(log: VerifiedLog): Set<string> {
  const members = new Set<string>();
  for (const { state } of log.entries) {
    if (state.controller.kind === "member") {
      for (const member of state.controller.members) members.add(member);
    }
  }
  return members;
}

/**
 * Layer 1, 9.5: the earliest time at which a record is signed by a
 * collective under its threshold, or `undefined` if it never is. That is the
 * earliest `T` at which the members of the collective's state at `T` that
 * have proofs on the record, without `authority` and evaluated at or before
 * `T`, number at least that state's threshold.
 *
 * A record that describes the present (`Location`, `Participant`) needs the
 * threshold of the latest state known, of a collective that is neither
 * retired nor duplicitous.
 *
 * @param log - The collective's verified log.
 */
export function collectiveSignedTime(
  judged: JudgedRecord,
  log: VerifiedLog,
  view: IdentityView,
): Instant | undefined {
  const latest = latestState(log);
  if (latest.controller.kind !== "member") return undefined;
  const type = judged.record.type;
  const current = CURRENT_STATE_TYPES.includes(type);
  if (current && (latest.retired || log.duplicitous)) return undefined;
  const everyone = current ? new Set(latest.controller.members) : membersEver(log);
  const candidates: { readonly time: Instant; readonly member: string }[] = [];
  for (const proof of judged.proofs) {
    const method = proof.method;
    // A proof that names an authority acts for that principal, not under the threshold.
    if (method.kind !== "key" || proof.proof.authority !== undefined) continue;
    if (!everyone.has(method.mind)) continue;
    const time = operationalProofTime(type, proof, view);
    if (time.ok) candidates.push({ time: time.value, member: method.mind });
  }
  candidates.sort((a, b) => (a.time < b.time ? -1 : a.time > b.time ? 1 : 0));
  for (const { time } of candidates) {
    const state = current ? latest : stateAt(log, time);
    if (state === undefined || state.retired || state.controller.kind !== "member") continue;
    const members = state.controller.members;
    const signers = new Set(
      candidates
        .filter((candidate) => candidate.time <= time && members.includes(candidate.member))
        .map((candidate) => candidate.member),
    );
    if (signers.size >= state.controller.threshold) return inTime(judged, time) ? time : undefined;
  }
  return undefined;
}

/**
 * The earliest evaluation time at which a record is signed by a mind's own
 * authority: one of its valid operational keys (Layer 1, 6.1), or for a
 * collective its threshold (Layer 1, 9.5). `undefined` if it never is.
 *
 * Signing through a delegation or a charter role is not judged here; that
 * needs `authority`, and belongs to `@oip/delegation`.
 */
export function ownSignedTime(
  judged: JudgedRecord,
  mind: string,
  view: IdentityView,
): Instant | undefined {
  const times = operationalProofs(judged, mind, view).map((counted) => counted.time);
  const held = view.log(mind);
  if (held.ok) {
    const together = collectiveSignedTime(judged, held.value, view);
    if (together !== undefined) times.push(together);
  }
  return times.length === 0 ? undefined : times.reduce((a, b) => (b < a ? b : a));
}
