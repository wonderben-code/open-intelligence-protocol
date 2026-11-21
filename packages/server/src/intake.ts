// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a copy of a log that someone publishes may add to what a resolver
 * holds (Layer 1, 17.2).
 *
 * A resolver verifies every record before it stores or serves it. So of a
 * copy it takes the events that verify, from the genesis on, and nothing
 * after the first that does not. Whoever sent the copy is no source the
 * resolver trusts to serve a whole log, and what such a source shows is no
 * reason to stop relying on what has verified (Layer 1, 4.9).
 *
 * Of the proofs on an event it takes those that can count, and no others.
 * A verifier that is shown more proofs for one event than a record carries
 * treats the log as not verified (Layer 1, 7.1). A proof costs nothing to
 * make: a resolver that kept and served every proof it was shown would let
 * a stranger put that many on a mind's event, and every client that then
 * merged two resolvers' answers would lose the mind. A proof can count if
 * its signature verifies and its key is one the event's place allows: a
 * control key the event reveals, or an invocation key of a member at the
 * version the proof names.
 *
 * That reading of which proofs can count is this module's own, and
 * `@oip/identity` is the judge. So the copy is verified again with only
 * the proofs kept. If it then verifies less far, the reading was wrong, and
 * every proof whose signature verifies is kept instead.
 *
 * Nothing here is stored or recorded: the clock, the evidence and the logs
 * held are given, and the answer says what to take.
 */

import {
  contentId,
  type Instant,
  type JsonObject,
  verifyProofs,
  type VerifiedProof,
} from "@oip/core";
import {
  entryAt,
  type EvidenceView,
  FirstSeen,
  type IdentityState,
  type VerifiedLog,
  witnessLog,
} from "@oip/identity";
import type { Issue, Proof, Validation } from "@oip/schema";

/** What a resolver holds, as far as judging a copy needs it. */
export interface Held {
  /** The resolver's evidence of when it first saw events and proofs. */
  readonly evidence: EvidenceView;
  /** A member's log, as the resolver holds and verifies it. */
  readonly memberLog: (mind: string) => Validation<VerifiedLog>;
  /** The proofs already kept for an event, by its content ID. */
  readonly proofs: (eventId: string) => readonly Proof[];
  /** core 8.3: the extension namespaces the resolver implements. */
  readonly understood?: Iterable<string>;
}

/** Why the event after those taken was not taken. */
export interface NotTaken {
  /** The position of the event in the copy. */
  readonly position: number;
  readonly issues: readonly [Issue, ...Issue[]];
  /**
   * Layer 1, 4.9: `false` only for an event shown to be invalid. One that
   * is undecided may be the mind's own, and the resolver cannot judge it.
   */
  readonly undecided: boolean;
}

/** What a copy adds. */
export interface Taken {
  /** The events to hold, from the genesis, each with the proofs kept for it. */
  readonly events: readonly JsonObject[];
  /** The copy as far as it verified, judged alone. `undefined` if its genesis did not. */
  readonly log: VerifiedLog | undefined;
  /** The event after them, if the copy has one that was not taken. */
  readonly refused: NotTaken | undefined;
}

/** The most proofs kept for one event: as many as a record carries (core 5.1). */
const MOST_PROOFS = 256;

/** An event with these proofs, and no others. */
function signedBy(event: JsonObject, proofs: readonly Proof[]): JsonObject {
  const { proof: _, ...subject } = event;
  return { ...subject, proof: proofs as unknown as JsonObject[] };
}

/** A value of the copy with the proofs whose signatures verify, those already held first. */
function sound(
  value: unknown,
  held: Held,
): { event: JsonObject; proofs: VerifiedProof[] } | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  const event = value as JsonObject;
  let id: string;
  try {
    id = contentId(event);
  } catch {
    return undefined;
  }
  const kept = new Map<string, VerifiedProof>();
  // Each set by itself: neither is more than a record carries, and the two together may be.
  for (const candidate of [signedBy(event, held.proofs(id)), event]) {
    for (const proof of verifyProofs(candidate).verified) {
      if (kept.size < MOST_PROOFS && !kept.has(proof.digest)) kept.set(proof.digest, proof);
    }
  }
  return { event, proofs: [...kept.values()] };
}

const members = (state: IdentityState | undefined): readonly string[] =>
  state?.controller.kind === "member" ? state.controller.members : [];

/** The names in a member of an event that is a list of text, or none. */
function listed(event: JsonObject, name: "keys" | "members"): readonly string[] {
  const controller = event["controller"];
  if (typeof controller !== "object" || controller === null || Array.isArray(controller)) return [];
  const list = (controller as JsonObject)[name];
  return Array.isArray(list) ? list.filter((item): item is string => typeof item === "string") : [];
}

/**
 * Whether a proof whose signature verifies can count for an event, given
 * the state before it: by its key, and for a member's proof by the
 * member's log. Removals and dates are not looked at: a key that was once
 * the member's is enough here.
 */
function canCount(
  proof: VerifiedProof,
  event: JsonObject,
  before: IdentityState | undefined,
  held: Held,
): boolean {
  const method = proof.method;
  // A control key signs the event that reveals it (Layer 1, 3.4).
  if (method.kind === "control") return listed(event, "keys").includes(proof.key);
  // A member signs for a collective it controls, or the event that makes it one.
  if (!members(before).includes(method.mind) && !listed(event, "members").includes(method.mind)) {
    return false;
  }
  const log = held.memberLog(method.mind);
  if (!log.ok) return false;
  return entryAt(log.value, method.versionId)?.entry.state.invocation.includes(proof.key) === true;
}

/**
 * Layer 1, 17.2: judges a copy of a log that was published.
 *
 * @param copy - The copy: the `log` of a `Bundle`, already read as records.
 * @param now - The present, which stands in for the first sight of an event not seen before.
 */
export function judgeCopy(copy: readonly unknown[], now: Instant, held: Held): Taken {
  const read: { event: JsonObject; proofs: VerifiedProof[] }[] = [];
  for (const value of copy) {
    const event = sound(value, held);
    if (event === undefined) break;
    read.push(event);
  }
  const replay = (events: readonly JsonObject[]) =>
    // What verifies is recorded nowhere yet: the resolver records when it stores.
    witnessLog(events, now, new FirstSeen(), {
      evidence: held.evidence,
      memberLog: held.memberLog,
      ...(held.understood === undefined ? {} : { understood: held.understood }),
    });
  const all = (entry: { event: JsonObject; proofs: VerifiedProof[] }): JsonObject =>
    signedBy(
      entry.event,
      entry.proofs.map(({ proof }) => proof),
    );
  const withAll = read.map(all);
  const first = replay(withAll);
  const verified = first.log?.entries.length ?? 0;
  let refused: NotTaken | undefined;
  if (first.failure !== undefined) {
    refused = { position: verified, issues: first.failure.issues, undecided: first.undecided };
  } else if (copy.length > read.length) {
    refused = {
      position: read.length,
      issues: [
        {
          path: `/${read.length}`,
          message: "the value is no record of the JSON profile",
          clause: "core 1.1",
        },
      ],
      undecided: false,
    };
  }
  if (first.log === undefined) return { events: [], log: undefined, refused };

  const entries = first.log.entries;
  const withKept = read.slice(0, verified).map(({ event, proofs }, position) =>
    signedBy(
      event,
      proofs
        .filter((proof) => canCount(proof, event, entries[position - 1]?.state, held))
        .map(({ proof }) => proof),
    ),
  );
  const second = replay(withKept);
  if (second.log?.entries.length === verified) {
    return { events: withKept, log: second.log, refused };
  }
  // The reading of which proofs can count left out one that does: every sound proof is kept.
  return { events: withAll.slice(0, verified), log: first.log, refused };
}
