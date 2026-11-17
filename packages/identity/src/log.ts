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

import { type EvidenceView, eventTime } from "./evidence.ts";
import { isJsonObject, no, ok, under } from "./result.ts";
import {
  type ControllerState,
  type IdentityState,
  positionOf,
  removalTime,
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

/**
 * Layer 1, 6.4: the minds among `members` that have a proof on an identity
 * event by one of their own invocation keys, valid at the event's evaluation
 * time `when`. Compromise declarations in a member's log do not apply here.
 * With each signer comes its height.
 */
function memberSigners(
  proofs: readonly PlacedProof[],
  members: readonly string[],
  seen: Instant,
  when: Instant,
  context: LogContext,
): Map<string, number> {
  const signers = new Map<string, number>();
  for (const proof of proofs) {
    const method = proof.method;
    if (method.kind !== "key" || !members.includes(method.mind) || signers.has(method.mind)) {
      continue;
    }
    const held = context.memberLog?.(method.mind);
    if (held?.ok !== true) continue;
    const log = held.value;
    // core 9.4: the member's log must be known up to the evidence for the event.
    if (log.asOf < seen) continue;
    const position = positionOf(log, method.versionId);
    if (position === undefined) continue;
    if (!(log.states[position] as IdentityState).invocation.includes(proof.key)) continue;
    const removed = removalTime(log, position, proof.key, "invocation");
    if (removed !== undefined && when >= removed) continue;
    signers.set(method.mind, log.height);
  }
  return signers;
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

/** The state as an event's own members change it (Layer 1, 4.5). */
function applyFields(
  state: IdentityState,
  event: IdentityEvent,
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
  const returned = [...keys, ...invocation].find((key) => state.revoked.has(key));
  if (returned !== undefined) {
    return no(`key ${returned} was revoked and can never be added again`, "L1 4.5", path);
  }
  const revoked = new Map(state.revoked);
  let left = { keys, invocation };
  if (event.type !== "Genesis" && event.revoked !== undefined) {
    for (const [i, entry] of event.revoked.entries()) {
      const stated =
        (event.keys !== undefined && keys.includes(entry.key)) ||
        (event.invocation !== undefined && invocation.includes(entry.key));
      if (stated) {
        return no(
          `key ${entry.key} is revoked by this event and must not remain in its keys`,
          "L1 4.5",
          `${path}/revoked/${i}/key`,
        );
      }
      left = {
        keys: left.keys.filter((key) => key !== entry.key),
        invocation: left.invocation.filter((key) => key !== entry.key),
      };
      const since =
        entry.compromisedSince === undefined ? undefined : parseTimestamp(entry.compromisedSince);
      const held = revoked.get(entry.key);
      // The earliest declaration stands if a key is revoked more than once.
      revoked.set(
        entry.key,
        since === undefined ? held : held === undefined || since < held ? since : held,
      );
    }
  }
  return ok({
    ...state,
    ...left,
    agreement: event.agreement === undefined ? state.agreement : keysOf(event.agreement),
    homes: event.homes ?? state.homes,
    alsoKnownAs: event.alsoKnownAs ?? state.alsoKnownAs,
    revoked,
  });
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
  seen: Instant,
  when: Instant,
  context: LogContext,
): Validation<Step> {
  if (event.type !== "Genesis") {
    return no("the first event of a log is a Genesis", "L1 4.1", "/0/type");
  }
  const mind = mindAddress(id);
  const controller = event.controller;
  let height = 0;
  if ("members" in controller) {
    const own = controller.members.indexOf(mind);
    if (own !== -1) {
      return no("a mind is not a member of itself", "L1 3.4", `/0/controller/members/${own}`);
    }
    const signers = memberSigners(proofs, controller.members, seen, when, context);
    const missing = controller.members.find((member) => !signers.has(member));
    if (missing !== undefined) {
      return no(
        `founding member ${missing} has no proof on the genesis by one of its invocation keys, valid at the genesis's evaluation time`,
        "L1 4.1",
        "/0/proof",
      );
    }
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
    children: [],
    revoked: new Map(),
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
  seen: Instant,
  when: Instant,
  context: LogContext,
): Validation<Step> {
  const path = `/${position}`;
  const state = before.state;
  if (event.type === "Genesis") {
    return no("a Genesis is the first event of a log, and only the first", "L1 4.6", `${path}/type`);
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
    return no("created is earlier than the created of the event before", "L1 4.2", `${path}/created`);
  }
  const given = event.controller;
  let controller = state.controller;
  if (state.controller.kind === "member") {
    if (given !== undefined && !("members" in given)) {
      return no(
        "a member-controlled mind stays member-controlled",
        "L1 3.4",
        `${path}/controller`,
      );
    }
    const signers = memberSigners(proofs, state.controller.members, seen, when, context);
    if (signers.size < state.controller.threshold) {
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
      added = memberSigners(proofs, joining, seen, when, context);
      const missing = joining.find((member) => !added.has(member));
      if (missing !== undefined) {
        return no(
          `added member ${missing} has no valid proof on this event`,
          "L1 4.4",
          `${path}/proof`,
        );
      }
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
      return no("the event before committed to no next keys: the log cannot be extended", "L1 4.3", path);
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
      children: event.type === "Fork" ? [...state.children, event.child] : state.children,
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
  const verified: IdentityEvent[] = [];
  const states: IdentityState[] = [];
  const times: Instant[] = [];
  let step: Step | undefined;
  for (let i = 0; i < events.length; i++) {
    const path = `/${i}`;
    const read = readEvent(events[i], path);
    if (!read.ok) return read;
    const event = read.value;
    const id = contentId(event);
    // A proof set that cannot be judged has no verified proof, so the event
    // then lacks its authority below.
    const verdicts = verifyProofs(event);
    // The schema has checked that `created` is a timestamp.
    const created = parseTimestamp(event.created) as Instant;
    const seen = context.evidence.eventSeen(id);
    const time = eventTime(created, seen, times[times.length - 1]);
    if (!time.ok) return under(path, time);
    const when = time.value;
    const next: Validation<Step> =
      step === undefined
        ? found(event, id, created, verdicts.verified, seen as Instant, when, context)
        : extend(step, event, i, id, created, verdicts.verified, seen as Instant, when, context);
    if (!next.ok) return next;
    const applied = applyFields(next.value.state, event, path);
    if (!applied.ok) return applied;
    step = { state: applied.value, height: next.value.height };
    verified.push(event);
    states.push(step.state);
    times.push(when);
  }
  // The caller has checked that there is at least one event.
  const last = step as Step;
  return ok({
    mind: last.state.mind,
    events: verified,
    states,
    times,
    height: last.height,
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
    if (!Array.isArray(events) || events.length === 0) {
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
