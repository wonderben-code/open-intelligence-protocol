// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Verifying an identity log (Layer 1, Section 4): replaying its events, each
 * authorised by the state the one before it left, into the state after each.
 */

import {
  checkSize,
  contentId,
  formatVersionId,
  type Instant,
  isEd25519Multikey,
  isX25519Multikey,
  keyHash,
  mindAddress,
  parseTimestamp,
  type PlacedProof,
  verifyProofs,
} from "@oip/core";
import {
  type Controller,
  type IdentityEvent,
  type Issue,
  type Validation,
  validateJson,
  validateRecord,
} from "@oip/schema";

import { type Evaluation, type EvidenceView, eventTime } from "./evidence.ts";
import { isJsonObject, no, ok, under } from "./result.ts";
import {
  type ControllerState,
  type AcknowledgedChild,
  entryAt,
  type IdentityState,
  type LogEntry,
  removalTime,
  type Revocation,
  type VerifiedLog,
} from "./state.ts";

/** Layer 1, 4.7: a collective's height is at most 4. */
export const MAX_HEIGHT = 4;

/** Layer 1, 4.7: every verifier accepts logs of at least this many events. */
export const MIN_ACCEPTED_LOG_EVENTS = 1000;

/** The longest log this verifier reads unless it is told otherwise (Layer 1, 4.7). */
export const MAX_LOG_EVENTS = 10_000;

const EVENT_TYPES: readonly unknown[] = ["Genesis", "Update", "Fork", "Retire"];

/** What a log is verified with. */
export interface LogContext {
  /** When each event is known to have existed (core 9.5). */
  readonly evidence: EvidenceView;
  /**
   * core 9.4: the time up to which the log is known to be complete: when a
   * witness the verifier trusts served it, or the present for a verifier
   * that follows the log itself.
   */
  readonly asOf: Instant;
  /**
   * The verified log of a member mind (Layer 1, 4.7). A member-controlled
   * log cannot be verified without it. `LogBook` supplies it, and bounds the
   * nesting.
   */
  readonly memberLog?: (mind: string) => Validation<VerifiedLog>;
  /** The longest log to read. Default `MAX_LOG_EVENTS`. A limit below 1,000 is read as 1,000 (Layer 1, 4.7). */
  readonly maxEvents?: number;
}

function maxEventsOf(context: LogContext): number {
  const given: unknown = Object.hasOwn(context, "maxEvents") ? context.maxEvents : undefined;
  return typeof given === "number" && Number.isSafeInteger(given) && given >= 0
    ? Math.max(given, MIN_ACCEPTED_LOG_EVENTS)
    : MAX_LOG_EVENTS;
}

/** The control keys that have a valid proof on an event, each by its own `control-key-ref` (Layer 1, 3.11). */
function controlSigners(proofs: readonly PlacedProof[]): Set<string> {
  const keys = new Set<string>();
  for (const proof of proofs) if (proof.method.kind === "control") keys.add(proof.key);
  return keys;
}

/** The members that signed an event, each with its height, and why the proofs of the others did not count. */
interface MemberSigners {
  readonly signers: Map<string, number>;
  readonly refused: Map<string, Issue>;
}

/**
 * Layer 1, 6.4: whether a proof on an identity event, by a key of a member,
 * counts: the key is an invocation key of the member at the version the
 * proof pins, and no later event of the member's log removed it, or retired
 * the member, at or before the event's evaluation time. Compromise
 * declarations in the member's log do not apply here.
 *
 * @returns The member's height.
 */
function memberProof(
  proof: PlacedProof,
  mind: string,
  versionId: string,
  { seen, time: when }: Evaluation,
  context: LogContext,
): Validation<number> {
  const held = context.memberLog?.(mind) ?? no(`no identity log is held for ${mind}`, "L1 6.3");
  if (!held.ok) return held;
  const log = held.value;
  if (log.asOf < seen) {
    return no(
      "the member's log was obtained before the evidence for this event: it may lack a later event",
      "core 9.4",
    );
  }
  const pinned = entryAt(log, versionId);
  if (pinned === undefined) {
    return no("the proof is pinned to a version that is not in the member's log", "L1 6.4");
  }
  if (pinned.entry.state.retired) {
    return no("the proof is pinned to the version that retired the member", "L1 3.10");
  }
  if (!pinned.entry.state.invocation.includes(proof.key)) {
    return no("the key is not an invocation key of the member at the version named", "L1 6.4");
  }
  const removed = removalTime(log, pinned.position, proof.key, "invocation");
  if (removed !== undefined && when >= removed) {
    return no(
      "the member removed the key, or retired, at or before the event's evaluation time",
      "L1 6.4",
    );
  }
  return ok(log.height);
}

/**
 * The minds among `members` that have a proof on an identity event that
 * counts (Layer 1, 6.4), judged at the event's evaluation time `when`.
 */
function memberSigners(
  proofs: readonly PlacedProof[],
  members: readonly string[],
  when: Evaluation,
  context: LogContext,
): MemberSigners {
  const signers = new Map<string, number>();
  const refused = new Map<string, Issue>();
  for (const proof of proofs) {
    const method = proof.method;
    if (method.kind !== "key" || !members.includes(method.mind) || signers.has(method.mind)) {
      continue;
    }
    const counted = memberProof(proof, method.mind, method.versionId, when, context);
    if (counted.ok) {
      signers.set(method.mind, counted.value);
      refused.delete(method.mind);
    } else if (!refused.has(method.mind)) {
      refused.set(method.mind, {
        ...counted.issues[0],
        path: `/proof/${proof.index}`,
        message: `the proof by member ${method.mind} does not count: ${counted.issues[0].message}`,
      });
    }
  }
  return { signers, refused };
}

/** Why a member that had to sign did not: its proof was refused, or it has none. */
function unsigned(
  member: string,
  refused: MemberSigners["refused"],
  path: string,
  clause: string,
): Validation<never> {
  const issue = refused.get(member);
  return issue === undefined
    ? no(
        `member ${member} has no valid proof on this event by one of its invocation keys`,
        clause,
        `${path}/proof`,
      )
    : { ok: false, issues: [{ ...issue, path: path + issue.path }] };
}

const keysOf = (entries: readonly { readonly key: string }[]): string[] =>
  entries.map((entry) => entry.key);

/**
 * core 4.4: a key that is not a point of order L is rejected wherever it
 * appears, and a schema cannot tell. An agreement key is checked for its
 * form (core 4.2).
 */
function badKey(event: IdentityEvent, path: string): Validation<never> | undefined {
  const sets = [
    ["keys", isEd25519Multikey, "core 4.4"],
    ["invocation", isEd25519Multikey, "core 4.4"],
    ["agreement", isX25519Multikey, "core 4.2"],
  ] as const;
  for (const [set, accepted, clause] of sets) {
    const at = event[set]?.findIndex((entry) => !accepted(entry.key));
    if (at !== undefined && at !== -1) {
      return no(`not a public key this revision accepts`, clause, `${path}/${set}/${at}/key`);
    }
  }
  return undefined;
}

/**
 * The state as an event's own members change it (Layer 1, 4.5).
 *
 * @param revoked - Every key the log has revoked before this event.
 */
function applyFields(
  state: IdentityState,
  event: IdentityEvent,
  revoked: ReadonlySet<string>,
  path: string,
): Validation<IdentityState> {
  const bad = badKey(event, path);
  if (bad !== undefined) return bad;
  const keys = event.keys === undefined ? state.keys : keysOf(event.keys);
  const invocation = event.invocation === undefined ? state.invocation : keysOf(event.invocation);
  const both = keys.find((key) => invocation.includes(key));
  if (both !== undefined) {
    return no(`key ${both} would be both an operational and an invocation key`, "L1 3.5", path);
  }
  const returned = [...keys, ...invocation].find((key) => revoked.has(key));
  if (returned !== undefined) {
    return no(`key ${returned} was revoked and can never be added again`, "L1 4.5", path);
  }
  // A key the event both revokes and keeps was refused with the event (Layer 1, 4.5).
  const gone = new Set(revocationsOf(event, 0).map((revocation) => revocation.key));
  return ok({
    ...state,
    keys: gone.size === 0 ? keys : keys.filter((key) => !gone.has(key)),
    invocation: gone.size === 0 ? invocation : invocation.filter((key) => !gone.has(key)),
    agreement: event.agreement === undefined ? state.agreement : keysOf(event.agreement),
    homes: event.homes ?? state.homes,
    alsoKnownAs: event.alsoKnownAs ?? state.alsoKnownAs,
  });
}

/** What an event revokes. A genesis revokes nothing: there is nothing yet to revoke. */
function revocationsOf(event: IdentityEvent, position: number): Revocation[] {
  if (event.type === "Genesis" || event.revoked === undefined) return [];
  return event.revoked.map((entry) => ({
    position,
    key: entry.key,
    compromisedSince:
      entry.compromisedSince === undefined ? undefined : parseTimestamp(entry.compromisedSince),
  }));
}

function controllerState(controller: Controller): ControllerState {
  return "members" in controller
    ? { kind: "member", members: controller.members, threshold: controller.threshold }
    : {
        kind: "key",
        next: controller.next,
        nextThreshold: controller.next.length === 0 ? 0 : (controller.nextThreshold ?? 1),
      };
}

interface Step {
  readonly state: IdentityState;
  readonly height: number;
}

/** Layer 1, 4.1: the genesis, and the state it founds. */
function found(
  event: IdentityEvent,
  id: string,
  created: Instant,
  proofs: readonly PlacedProof[],
  when: Evaluation,
  context: LogContext,
): Validation<Step> {
  if (event.type !== "Genesis") {
    return no("the first event of a log is a Genesis", "L1 4.1", "/0/type");
  }
  const mind = mindAddress(id);
  const controller = event.controller;
  let height = 0;
  if ("members" in controller) {
    // A genesis cannot list its own address, which is the hash of the genesis.
    const { signers, refused } = memberSigners(proofs, controller.members, when, context);
    // The threshold is for later events: no mind is named a founder without its consent.
    const missing = controller.members.find((member) => !signers.has(member));
    if (missing !== undefined) return unsigned(missing, refused, "/0", "L1 4.1");
    const least = 1 + Math.max(...signers.values());
    height = event.height ?? least;
    if (height < least || height > MAX_HEIGHT) {
      return no(
        `a collective's height is at most ${MAX_HEIGHT} and above every founding member's: here at least ${least}`,
        "L1 4.7",
        event.height === undefined ? "/0" : "/0/height",
      );
    }
  } else {
    const signed = controlSigners(proofs);
    const unsigned = controller.keys.find((key) => !signed.has(key));
    if (unsigned !== undefined) {
      return no(
        `control key ${unsigned} has no valid proof on the genesis with its own control-key-ref`,
        "L1 4.1",
        "/0/proof",
      );
    }
  }
  const state: IdentityState = {
    mind,
    kind: event.kind,
    controller: controllerState(controller),
    keys: [],
    invocation: [],
    agreement: [],
    homes: [],
    alsoKnownAs: [],
    parents: event.parents ?? [],
    seq: 0,
    head: id,
    versionId: formatVersionId(0, id),
    created,
    retired: false,
  };
  return ok({ state, height });
}

/** Layer 1, 4.2 to 4.4: a later event, authorised by the state before it. */
function extend(
  before: Step,
  event: IdentityEvent,
  position: number,
  id: string,
  created: Instant,
  proofs: readonly PlacedProof[],
  when: Evaluation,
  context: LogContext,
): Validation<Step> {
  const path = `/${position}`;
  const state = before.state;
  if (event.type === "Genesis") {
    return no(
      "a Genesis is the first event of a log, and only the first",
      "L1 4.6",
      `${path}/type`,
    );
  }
  if (state.retired) return no("no event follows a Retire", "L1 4.6", path);
  if (event.mind !== state.mind) {
    return no("mind is not the address of this log", "L1 4.2", `${path}/mind`);
  }
  if (event.seq !== state.seq + 1) {
    return no(`seq must be ${state.seq + 1}`, "L1 4.2", `${path}/seq`);
  }
  if (event.prev !== state.head) {
    return no("prev is not the content ID of the event before", "L1 4.2", `${path}/prev`);
  }
  if (created < state.created) {
    return no(
      "created is earlier than the created of the event before",
      "L1 4.2",
      `${path}/created`,
    );
  }
  const given = event.controller;
  let controller = state.controller;
  if (state.controller.kind === "member") {
    if (given !== undefined && !("members" in given)) {
      return no("a member-controlled mind stays member-controlled", "L1 3.4", `${path}/controller`);
    }
    const { signers, refused } = memberSigners(proofs, state.controller.members, when, context);
    if (signers.size < state.controller.threshold) {
      const [first] = refused.values();
      // A member's proof that was refused says more than the count does.
      if (first !== undefined)
        return { ok: false, issues: [{ ...first, path: path + first.path }] };
      return no(
        `${signers.size} of the current members have a valid proof on this event, and the threshold is ${state.controller.threshold}`,
        "L1 4.4",
        `${path}/proof`,
      );
    }
    let added = new Map<string, number>();
    if (given !== undefined) {
      const current = state.controller.members;
      const joining = given.members.filter((member) => !current.includes(member));
      const joined = memberSigners(proofs, joining, when, context);
      added = joined.signers;
      const missing = joining.find((member) => !added.has(member));
      if (missing !== undefined) return unsigned(missing, joined.refused, path, "L1 4.4");
      controller = controllerState(given);
    }
    const tall = [...signers, ...added].find(([, height]) => height >= before.height);
    if (tall !== undefined) {
      return no(
        `member ${tall[0]} has height ${tall[1]}, which is not below the collective's ${before.height}`,
        "L1 4.7",
        `${path}/proof`,
      );
    }
  } else {
    if (given === undefined) {
      return no(
        "a key-controlled mind's event reveals the keys that sign it",
        "L1 3.7",
        `${path}/controller`,
      );
    }
    if ("members" in given) {
      return no("a key-controlled mind stays key-controlled", "L1 3.4", `${path}/controller`);
    }
    const { next, nextThreshold } = state.controller;
    if (next.length === 0) {
      return no(
        "the event before committed to no next keys: the log cannot be extended",
        "L1 4.3",
        path,
      );
    }
    if (given.keys.length < nextThreshold) {
      return no(
        `${given.keys.length} control keys are revealed, and the threshold is ${nextThreshold}`,
        "L1 4.3",
        `${path}/controller/keys`,
      );
    }
    const signed = controlSigners(proofs);
    for (const [i, key] of given.keys.entries()) {
      if (!next.includes(keyHash(key))) {
        return no(
          `control key ${key} was not committed to by the event before`,
          "L1 4.3",
          `${path}/controller/keys/${i}`,
        );
      }
      if (!signed.has(key)) {
        return no(
          `control key ${key} has no valid proof on this event with its own control-key-ref`,
          "L1 4.3",
          `${path}/proof`,
        );
      }
    }
    controller = controllerState(given);
  }
  return ok({
    height: before.height,
    state: {
      ...state,
      controller,
      seq: event.seq,
      head: id,
      versionId: formatVersionId(event.seq, id),
      created,
      retired: event.type === "Retire",
    },
  });
}

/** One event as a well-formed record of an identity log (Layer 1, 4.6 and 4.8). */
function readEvent(raw: unknown, path: string): Validation<IdentityEvent> {
  const plain = validateJson(raw);
  if (!plain.ok) return under(path, plain);
  const value = plain.value;
  if (!isJsonObject(value)) return no("an event is a JSON object", "L1 3.1", path);
  const type = value["type"];
  if (type === "Merge") return no("Merge is reserved in this revision", "L1 3.9", `${path}/type`);
  if (!EVENT_TYPES.includes(type)) {
    return no("an event is a Genesis, an Update, a Fork or a Retire", "L1 4.6", `${path}/type`);
  }
  if (Object.hasOwn(value, "recovery")) {
    return no("recovery is reserved in this revision", "L1 3.12", `${path}/recovery`);
  }
  const record = validateRecord(value);
  if (!record.ok) return under(path, record);
  const [tooLarge] = checkSize(record.value);
  if (tooLarge !== undefined) return under(path, { issues: [tooLarge] });
  return ok(record.value as IdentityEvent);
}

function replay(events: readonly unknown[], context: LogContext): Validation<VerifiedLog> {
  const entries: LogEntry[] = [];
  const children: AcknowledgedChild[] = [];
  const revocations: Revocation[] = [];
  const revoked = new Set<string>();
  let step: Step | undefined;
  for (let i = 0; i < events.length; i++) {
    const path = `/${i}`;
    const read = readEvent(events[i], path);
    if (!read.ok) return read;
    const event = read.value;
    const id = contentId(event);
    // A proof set that cannot be judged has no verified proof, so the event
    // then lacks its authority below.
    const proofs = verifyProofs(event).verified;
    const created = parseTimestamp(event.created);
    if (created === undefined) return no("created is not a timestamp", "core 1.4", path);
    const time = eventTime(created, context.evidence.eventSeen(id), entries.at(-1)?.time);
    if (!time.ok) return under(path, time);
    const when = time.value;
    const next: Validation<Step> =
      step === undefined
        ? found(event, id, created, proofs, when, context)
        : extend(step, event, i, id, created, proofs, when, context);
    if (!next.ok) return next;
    const applied = applyFields(next.value.state, event, revoked, path);
    if (!applied.ok) return applied;
    step = { state: applied.value, height: next.value.height };
    if (event.type === "Fork") children.push({ position: i, child: event.child });
    for (const revocation of revocationsOf(event, i)) {
      revocations.push(revocation);
      revoked.add(revocation.key);
    }
    entries.push({ event, state: step.state, time: when.time });
  }
  const [genesis, ...later] = entries;
  if (genesis === undefined || step === undefined) {
    return no("an identity log is an array of at least one event", "L1 3.1");
  }
  return ok({
    mind: genesis.state.mind,
    entries: [genesis, ...later],
    children,
    revocations,
    height: step.height,
    asOf: context.asOf,
    duplicitous: false,
    branchTails: [],
  });
}

const unreadable: Issue = {
  path: "",
  message: "the log could not be read as plain JSON data",
  clause: "core 1.2",
};

/**
 * Verifies an identity log (Layer 1, Section 4) against the evidence held of
 * when each of its events existed (core 9.5).
 *
 * The result holds the state after each event and each event's evaluation
 * time. A member-controlled log needs its members' logs, which
 * `context.memberLog` supplies; `LogBook` does that, and resolves duplicity.
 *
 * It never throws.
 */
export function verifyLog(events: unknown, context: LogContext): Validation<VerifiedLog> {
  try {
    if (!Array.isArray(events)) {
      return no("an identity log is an array of at least one event", "L1 3.1");
    }
    const most = maxEventsOf(context);
    if (events.length > most) {
      return no(
        `the log has more than ${most} events, the most this verifier was set to read`,
        "implementation limit",
      );
    }
    return replay(events as readonly unknown[], context);
  } catch {
    return { ok: false, issues: [unreadable] };
  }
}
