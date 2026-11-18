// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Verifying an identity log (Layer 1, Section 4): replaying its events, each
 * authorised by the state the one before it left, into the state after each.
 */

import {
  checkSize,
  CLOCK_SKEW,
  contentId,
  formatVersionId,
  type Instant,
  isEd25519Multikey,
  isX25519Multikey,
  keyHash,
  mindAddress,
  parseTimestamp,
  type PlacedProof,
  unsupportedCritical,
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

import {
  datedBefore,
  type Evaluation,
  type EvidenceView,
  eventTime,
  proofTime,
} from "./evidence.ts";
import { deepFreeze, isJsonObject, no, ok, own, type Rejection, under } from "./result.ts";
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
  /**
   * core 8.3: the extension namespaces the caller implements. An event that
   * lists any other in `critical` may not be treated as valid, so its log is
   * rejected. Default: none.
   */
  readonly understood?: Iterable<string>;
}

/** The longest log to read, from what a caller gave for it. */
export function maxEventsOf(given: unknown): number {
  return typeof given === "number" && Number.isSafeInteger(given) && given >= 0
    ? Math.max(given, MIN_ACCEPTED_LOG_EVENTS)
    : MAX_LOG_EVENTS;
}

/** The namespaces a caller says it implements. One that says nothing readable implements none. */
export function understoodOf(given: unknown): ReadonlySet<string> {
  const understood = new Set<string>();
  try {
    for (const namespace of (given ?? []) as Iterable<unknown>) {
      if (typeof namespace === "string") understood.add(namespace);
    }
  } catch {
    // Not a list of names: nothing more is understood than was read.
  }
  return understood;
}

/** One verification of one log. */
interface Replay {
  readonly context: Omit<LogContext, "asOf">;
  readonly understood: ReadonlySet<string>;
  /**
   * Each member's log, as it was first answered. A log is verified against
   * one answer for each member, and each member is asked for once.
   */
  readonly members: Map<string, Validation<VerifiedLog>>;
}

function memberLog(mind: string, replay: Replay): Validation<VerifiedLog> {
  const known = replay.members.get(mind);
  if (known !== undefined) return known;
  const held =
    replay.context.memberLog?.(mind) ?? no(`no identity log is held for ${mind}`, "L1 6.3");
  replay.members.set(mind, held);
  return held;
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

const DELEGATED: Rejection = deepFreeze({
  ok: false,
  issues: [
    {
      path: "",
      message:
        "a proof that names an authority is made for that principal, not by the member for itself",
      clause: "L1 6.4",
    },
  ],
});

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
  log: VerifiedLog,
  versionId: string,
  { evidenced, time: when }: Evaluation,
): Validation<number> {
  if (proof.proof.authority !== undefined) return DELEGATED;
  // The event takes effect no earlier than the event before it, so the
  // member's log must be known as far as the evidence for either goes.
  if (log.asOf < evidenced) {
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

/** Why a proof by a member does not count, as an issue of the event it is on. */
function refusal(proof: PlacedProof, mind: string, reason: Rejection): Issue {
  return {
    ...reason.issues[0],
    path: `/proof/${proof.index}`,
    message: `the proof by member ${mind} does not count: ${reason.issues[0].message}`,
  };
}

/**
 * The minds among `members` that have a proof on an identity event that
 * counts (Layer 1, 6.4), judged at the event's evaluation time `when`.
 *
 * A rejection if the log of a member with a proof here does not verify.
 * Every member signs the event that makes it one (Layer 1, 4.1, 4.4), so a
 * log is asked for first by an event that cannot stand without it; stopping
 * there keeps the work of a log that fails to one failing member.
 *
 * @param path - The event's place in the log.
 */
function memberSigners(
  proofs: readonly PlacedProof[],
  members: readonly string[],
  when: Evaluation,
  replay: Replay,
  path: string,
): Validation<MemberSigners> {
  const signers = new Map<string, number>();
  const refused = new Map<string, Issue>();
  for (const proof of proofs) {
    const method = proof.method;
    if (method.kind !== "key" || !members.includes(method.mind) || signers.has(method.mind)) {
      continue;
    }
    const held = memberLog(method.mind, replay);
    if (!held.ok) {
      return under(path, { issues: [refusal(proof, method.mind, held)] });
    }
    const counted = memberProof(proof, held.value, method.versionId, when);
    if (counted.ok) {
      signers.set(method.mind, counted.value);
      refused.delete(method.mind);
    } else if (!refused.has(method.mind)) {
      refused.set(method.mind, refusal(proof, method.mind, counted));
    }
  }
  return ok({ signers, refused });
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

/** The operational and invocation keys of a state. */
type KeySets = Pick<IdentityState, "keys" | "invocation">;

const NO_KEYS: KeySets = { keys: [], invocation: [] };

/**
 * Layer 1, 3.5 and 4.5: the operational and invocation keys after an event,
 * or why the event may not set the keys it does. It reads the event and the
 * events before it and nothing else.
 *
 * @param before - The keys of the state before the event; none before a genesis.
 * @param revoked - Every key the log has revoked before this event.
 */
function keysAfter(
  before: KeySets,
  event: IdentityEvent,
  revoked: ReadonlySet<string>,
  path: string,
): Validation<KeySets> {
  const bad = badKey(event, path);
  if (bad !== undefined) return bad;
  const keys = event.keys === undefined ? before.keys : keysOf(event.keys);
  const invocation = event.invocation === undefined ? before.invocation : keysOf(event.invocation);
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
    keys: gone.size === 0 ? keys : keys.filter((key) => !gone.has(key)),
    invocation: gone.size === 0 ? invocation : invocation.filter((key) => !gone.has(key)),
  });
}

/** The state as an event's own members change it (Layer 1, 4.5), with the keys it is left with. */
function applyFields(state: IdentityState, event: IdentityEvent, keys: KeySets): IdentityState {
  return {
    ...state,
    ...keys,
    agreement: event.agreement === undefined ? state.agreement : keysOf(event.agreement),
    homes: event.homes ?? state.homes,
    alsoKnownAs: event.alsoKnownAs ?? state.alsoKnownAs,
  };
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
  replay: Replay,
): Validation<Step> {
  if (event.type !== "Genesis") return FIRST;
  const mind = mindAddress(id);
  const controller = event.controller;
  let height = 0;
  if ("members" in controller) {
    // A genesis cannot list its own address, which is the hash of the genesis.
    const signed = memberSigners(proofs, controller.members, when, replay, "/0");
    if (!signed.ok) return signed;
    const { signers, refused } = signed.value;
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

/**
 * Layer 1, 4.2 and 4.6: whether an event follows the state before it, by its
 * own members alone. Nothing here depends on evidence or on another log.
 */
function follows(
  state: IdentityState,
  event: IdentityEvent,
  path: string,
  created: Instant,
): Rejection | undefined {
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
  if (datedBefore(created, state.created)) {
    return no(
      "created is earlier than the created of the event before",
      "L1 4.2",
      `${path}/created`,
    );
  }
  return undefined;
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
  replay: Replay,
): Validation<Step> {
  const path = `/${position}`;
  const state = before.state;
  // Asked again here so that no caller can extend a log with an event that does not follow.
  const broken = follows(state, event, path, created);
  if (broken !== undefined || event.type === "Genesis") {
    // `follows` refuses a Genesis; the second test tells the compiler so.
    return broken ?? no("a Genesis is the first event of a log", "L1 4.6", `${path}/type`);
  }
  const given = event.controller;
  let controller = state.controller;
  if (state.controller.kind === "member") {
    if (given !== undefined && !("members" in given)) {
      return no("a member-controlled mind stays member-controlled", "L1 3.4", `${path}/controller`);
    }
    const signed = memberSigners(proofs, state.controller.members, when, replay, path);
    if (!signed.ok) return signed;
    const { signers, refused } = signed.value;
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
      const joined = memberSigners(proofs, joining, when, replay, path);
      if (!joined.ok) return joined;
      added = joined.value.signers;
      const missing = joining.find((member) => !added.has(member));
      if (missing !== undefined) return unsigned(missing, joined.value.refused, path, "L1 4.4");
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

/**
 * Layer 1, 4.9: why the proofs on an event of a member-controlled mind could
 * not authorise it, whatever logs and whatever evidence a verifier holds.
 *
 * A member is taken to have signed if a proof on the event verifies under a
 * key reference of that member's and names no authority. Whether such a
 * proof counts is for the member's log and the evidence to say (Layer 1,
 * 6.4), and they differ from one verifier to the next; that such a proof is
 * there at all is a fact about the event.
 *
 * @param before - The state before the event, or `undefined` for a genesis.
 * @param proofs - Every proof on the event that verifies.
 */
function unsignedByMembers(
  event: IdentityEvent,
  before: IdentityState | undefined,
  proofs: readonly PlacedProof[],
  path: string,
): Rejection | undefined {
  const named = new Set<string>();
  /** A member's proof that is made for another, which says more than its absence does. */
  const forAnother = new Map<string, Issue>();
  for (const proof of proofs) {
    if (proof.method.kind !== "key") continue;
    const mind = proof.method.mind;
    if (proof.proof.authority === undefined) named.add(mind);
    else if (!forAnother.has(mind)) forAnother.set(mind, refusal(proof, mind, DELEGATED));
  }
  const lacks = (member: string): boolean => !named.has(member);
  const absent = (members: readonly string[], clause: string): Rejection | undefined => {
    const missing = members.find(lacks);
    if (missing === undefined) return undefined;
    const issue = forAnother.get(missing);
    if (issue !== undefined) return { ok: false, issues: [{ ...issue, path: path + issue.path }] };
    return no(
      `member ${missing} has no proof on this event under a key reference of its own`,
      clause,
      `${path}/proof`,
    );
  };
  const given = event.controller;
  if (before === undefined) {
    return given !== undefined && "members" in given ? absent(given.members, "L1 4.1") : undefined;
  }
  if (before.controller.kind !== "member") return undefined;
  if (given !== undefined && !("members" in given)) {
    return no("a member-controlled mind stays member-controlled", "L1 3.4", `${path}/controller`);
  }
  const current = before.controller.members;
  const signed = current.filter((member) => named.has(member)).length;
  if (signed < before.controller.threshold) {
    const made = current.filter(lacks).flatMap((member) => forAnother.get(member) ?? []);
    if (made[0] !== undefined) {
      return { ok: false, issues: [{ ...made[0], path: path + made[0].path }] };
    }
    return no(
      `${signed} of the current members have a proof on this event, and the threshold is ${before.controller.threshold}`,
      "L1 4.4",
      `${path}/proof`,
    );
  }
  return given === undefined
    ? undefined
    : absent(
        given.members.filter((member) => !current.includes(member)),
        "L1 4.4",
      );
}

/** An event as read, or why it is none, and whether this verifier could read it at all. */
type Read =
  | { readonly event: IdentityEvent }
  | {
      readonly refusal: Rejection;
      /**
       * Whether the verifier cannot read the event (Layer 1, 4.9). Such an
       * event may depend on rules the verifier does not have, so nothing
       * else that is wrong with it is a finding.
       */
      readonly unread: boolean;
    };

/**
 * What a book holds in the place of an event that it could not keep as plain
 * data, and that the verifier cannot read (Layer 1, 4.9): the reason, found
 * when the event was given. It is judged as that event would be.
 */
export class Unread {
  /** Why the event cannot be read, with the path of the event left out. */
  readonly refusal: Rejection;

  constructor(refusal: Rejection) {
    this.refusal = refusal;
  }
}

/**
 * Layer 1, 4.9: why this verifier cannot read an event, if it cannot. The
 * event is of another version of the protocol (core 7); or of a type this
 * revision does not define, `Merge` among them (Layer 1, 3.9, 4.6); or has
 * the reserved member (3.12); or lists in `critical` an extension the
 * verifier does not implement (core 8.3).
 *
 * It is asked before anything else is, of whatever was given. An extension
 * listed in `critical`, like a later revision, may change what makes an
 * event well formed, in its place or signed: that is what `critical` is
 * for. A verifier without it can say nothing about the event, however the
 * event looks.
 *
 * Only members the value holds as data of its own are read.
 */
export function cannotRead(
  value: unknown,
  understood: ReadonlySet<string>,
  path: string,
): Rejection | undefined {
  try {
    if (value instanceof Unread) return under(path, value.refusal);
    if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
    const held = (name: string) => Object.getOwnPropertyDescriptor(value, name);
    const version: unknown = held("oip")?.value;
    if (typeof version === "string" && version !== "1") {
      return no("the event is of another version of the protocol", "core 7", `${path}/oip`);
    }
    const type: unknown = held("type")?.value;
    if (type === "Merge") return no("Merge is reserved in this revision", "L1 3.9", `${path}/type`);
    if (typeof type === "string" && !EVENT_TYPES.includes(type)) {
      // A type that is a string may be one a later revision defines.
      return no(NOT_AN_EVENT, "L1 4.6", `${path}/type`);
    }
    if (held("recovery") !== undefined) {
      return no("recovery is reserved in this revision", "L1 3.12", `${path}/recovery`);
    }
    const [unsupported] = unsupportedCritical({ critical: held("critical")?.value }, understood);
    return unsupported === undefined
      ? undefined
      : no(
          `the event depends on an extension this verifier does not implement: ${unsupported}`,
          "core 8.3",
          `${path}/critical`,
        );
  } catch {
    // What cannot be read at all says nothing of itself.
    return undefined;
  }
}

const NOT_AN_EVENT = "an event is a Genesis, an Update, a Fork or a Retire";

/**
 * One event as a well-formed record of an identity log (Layer 1, 4.6 and
 * 4.8).
 *
 * @param understood - core 8.3: the extension namespaces the verifier implements.
 */
function readEvent(raw: unknown, path: string, understood: ReadonlySet<string>): Read {
  const unread = cannotRead(raw, understood, path);
  if (unread !== undefined) return { refusal: unread, unread: true };
  const wrong = (refusal: Rejection): Read => ({ refusal, unread: false });
  const plain = validateJson(raw);
  if (!plain.ok) return wrong(under(path, plain));
  const value = plain.value;
  // Asked again of the copy that is judged: a value may answer differently the second time.
  const still = cannotRead(value, understood, path);
  if (still !== undefined) return { refusal: still, unread: true };
  if (!isJsonObject(value)) return wrong(no("an event is a JSON object", "L1 3.1", path));
  if (!EVENT_TYPES.includes(value["type"])) {
    return wrong(no(NOT_AN_EVENT, "L1 4.6", `${path}/type`));
  }
  const record = validateRecord(value);
  if (!record.ok) return wrong(under(path, record));
  const [tooLarge] = checkSize(record.value);
  if (tooLarge !== undefined) return wrong(under(path, { issues: [tooLarge] }));
  return { event: record.value as IdentityEvent };
}

/** How far a log verified. */
export interface Replayed {
  /** The events that verified, from the first, as a log. `undefined` if the genesis did not. */
  readonly log: VerifiedLog | undefined;
  /**
   * Why the event after them did not verify, if the log has one that did
   * not, or has more events than this verifier reads.
   */
  readonly failure: Rejection | undefined;
  /**
   * Whether the failure is the verifier's and not shown to be the event's
   * (Layer 1, 4.9): it cannot read the event (another version, a type this
   * revision does not define, the reserved member, a critical extension it
   * does not implement); or it holds no evidence for the event, or evidence
   * under which the event or a proof on it is dated too late or has
   * expired; or a member's proof on it does not count by the member's log
   * as this verifier holds it; or it stopped at the length it reads. It is
   * `false` only for an event shown to be invalid.
   *
   * An event that is invalid is no event, and the log ends before it. One
   * the verifier could not judge may be an event of the log, a removal among
   * them: `log` is then not known to be the whole log, and must not be used
   * as if it were.
   */
  readonly undecided: boolean;
}

/** A time for the checks that read none: the authority of a key-controlled mind's event. */
const UNTIMED: Evaluation = { seen: 0n, time: 0n, evidenced: 0n };

const FIRST: Rejection = deepFreeze({
  ok: false,
  issues: [{ path: "/0/type", message: "the first event of a log is a Genesis", clause: "L1 4.1" }],
});

const EMPTY: Rejection = deepFreeze({
  ok: false,
  issues: [
    { path: "", message: "an identity log is an array of at least one event", clause: "L1 3.1" },
  ],
});

/** Why an event did not verify, and whether that is the verifier's judgement (Layer 1, 4.9). */
export interface Refused {
  readonly failure: Rejection;
  /** `false` only for an event shown to be invalid. */
  readonly undecided: boolean;
}

/** A failure that is the verifier's judgement, and not shown to be a fact about the event. */
const lacking = (failure: Rejection): Refused => ({ failure, undecided: true });

/** A failure that the event and the events before it show, whoever looks and whenever. */
const invalid = (failure: Rejection): Refused => ({ failure, undecided: false });

/**
 * A log under verification, one event after another. A run can be forked,
 * to go on from one state with different events: that is how a book judges
 * the events it holds for one position (Layer 1, 7.3).
 */
export class LogRun {
  readonly #replay: Replay;
  readonly #entries: LogEntry[];
  readonly #children: AcknowledgedChild[];
  readonly #revocations: Revocation[];
  readonly #revoked: Set<string>;
  #step: Step | undefined;
  #before: Evaluation | undefined;

  /**
   * @param context - The evidence and the members' logs. The time the log is
   *   known up to is given when the log is asked for.
   * @param from - The run to go on from. Members' logs are answered once
   *   for a run and everything forked from it.
   */
  constructor(context: Omit<LogContext, "asOf">, from?: LogRun) {
    if (from === undefined) {
      this.#replay = {
        context,
        understood: understoodOf(context.understood),
        members: new Map(),
      };
      this.#entries = [];
      this.#children = [];
      this.#revocations = [];
      this.#revoked = new Set();
      return;
    }
    this.#replay = from.#replay;
    this.#entries = [...from.#entries];
    this.#children = [...from.#children];
    this.#revocations = [...from.#revocations];
    this.#revoked = new Set(from.#revoked);
    this.#step = from.#step;
    this.#before = from.#before;
  }

  /** A run that goes on from where this one is, and leaves this one where it is. */
  fork(): LogRun {
    return new LogRun(this.#replay.context, this);
  }

  /** The events verified so far, with the state after each. */
  get entries(): readonly LogEntry[] {
    return this.#entries;
  }

  /** Every revocation the events verified so far declare. */
  get revocations(): readonly Revocation[] {
    return this.#revocations;
  }

  /**
   * Judges the next event of the log. If it verifies, the run has moved on
   * to it. If it does not, the run is where it was.
   */
  advance(raw: unknown): Refused | undefined {
    const i = this.#entries.length;
    const path = `/${i}`;
    const run = this.#replay;
    const step = this.#step;
    const read = readEvent(raw, path, run.understood);
    if ("refusal" in read) return read.unread ? lacking(read.refusal) : invalid(read.refusal);
    const event = read.event;
    const id = contentId(event);
    const created = parseTimestamp(event.created);
    if (created === undefined) return invalid(no("created is not a timestamp", "core 1.4", path));
    const authorised = (proofs: readonly PlacedProof[], when: Evaluation): Validation<Step> =>
      step === undefined
        ? found(event, id, created, proofs, when, run)
        : extend(step, event, i, id, created, proofs, when, run);

    // First, what the event shows by itself, whoever looks and whenever: its
    // place in the chain, and whether the proofs on it could authorise it at
    // all. For a key-controlled mind that is the whole rule, asked with every
    // proof that verifies and no evidence. For a member-controlled mind it
    // is whether enough members have a proof here; what each proof is worth
    // is asked later, of the member's log. An event that fails here is
    // invalid for every verifier.
    if (step === undefined) {
      if (event.type !== "Genesis") return invalid(FIRST);
    } else {
      const broken = follows(step.state, event, path, created);
      if (broken !== undefined) return invalid(broken);
    }
    const all = verifyProofs(event).verified;
    const byKeys =
      step === undefined
        ? event.type === "Genesis" && !("members" in event.controller)
        : step.state.controller.kind === "key";
    const pure = byKeys ? authorised(all, UNTIMED) : undefined;
    if (pure?.ok === false) return invalid(pure);
    const unsigned = byKeys ? undefined : unsignedByMembers(event, step?.state, all, path);
    if (unsigned !== undefined) return invalid(unsigned);
    const keys = keysAfter(step?.state ?? NO_KEYS, event, this.#revoked, path);
    if (!keys.ok) return invalid(keys);

    // Then, what depends on the evidence this verifier holds. Another
    // verifier may hold other evidence, so a failure from here on is this
    // verifier's judgement, and not a fact about the event (Layer 1, 4.9).
    const time = eventTime(created, run.context.evidence.eventSeen(id), this.#before);
    if (!time.ok) return lacking(under(path, time));
    const when = time.value;
    // core 9.6, for a proof judged at its event's time (core 9.5): past the
    // event's `expires`, no proof on it counts, so nothing authorises it.
    const expires = event.expires === undefined ? undefined : parseTimestamp(event.expires);
    if (expires !== undefined && when.time > expires + CLOCK_SKEW) {
      return lacking(
        no(
          "the event is evaluated more than 300 seconds after it expires, so no proof on it counts",
          "core 9.6",
          `${path}/expires`,
        ),
      );
    }
    // Evidence for an event is evidence for the proofs it stood with (core
    // 9.4), so a proof dated more than 300 seconds after it counts for
    // nothing (core 9.3).
    const proofs = all.filter((proof) => proofTime(proof.created, when.seen).ok);
    // The proofs could authorise the event, by what it shows. If they do not
    // here, it is for a date, a member's log or a member's key as this
    // verifier knows them.
    const next =
      pure !== undefined && proofs.length === all.length ? pure : authorised(proofs, when);
    if (!next.ok) return lacking(next);
    const state = applyFields(next.value.state, event, keys.value);
    this.#step = { state, height: next.value.height };
    if (event.type === "Fork") this.#children.push({ position: i, child: event.child });
    for (const revocation of revocationsOf(event, i)) {
      this.#revocations.push(revocation);
      this.#revoked.add(revocation.key);
    }
    this.#entries.push({ event, state, time: when.time });
    this.#before = when;
    return undefined;
  }

  /**
   * The log as far as it has verified, frozen.
   *
   * @param asOf - core 9.4: the time up to which the log is known to be complete.
   * @returns `undefined` before a first event has verified.
   */
  log(asOf: Instant): VerifiedLog | undefined {
    const [genesis, ...later] = this.#entries;
    if (genesis === undefined || this.#step === undefined) return undefined;
    return deepFreeze({
      mind: genesis.state.mind,
      entries: [genesis, ...later],
      children: [...this.#children],
      revocations: [...this.#revocations],
      height: this.#step.height,
      asOf,
      duplicitous: false,
      branchTails: [],
    });
  }
}

function replay(events: readonly unknown[], context: LogContext): Replayed {
  const run = new LogRun(context);
  let refused: Refused | undefined;
  for (const raw of events) {
    refused = run.advance(raw);
    if (refused !== undefined) break;
  }
  const log = run.log(context.asOf);
  return {
    log,
    failure: refused?.failure ?? (log === undefined ? EMPTY : undefined),
    undecided: refused?.undecided ?? false,
  };
}

const unreadable: Rejection = deepFreeze({
  ok: false,
  issues: [
    { path: "", message: "the log could not be read as plain JSON data", clause: "core 1.2" },
  ],
});

/** A log as it was given, read once: its first events, and whether it has more than may be read. */
interface Opened {
  readonly events: readonly unknown[];
  readonly most: number;
  readonly tooLong: boolean;
}

/**
 * Reads a log's events out of what was given, once, so that nothing that
 * follows depends on the value answering the same way twice.
 */
function open(events: unknown, context: LogContext): Validation<Opened> {
  if (typeof (context.asOf as unknown) !== "bigint") {
    return no("the time up to which the log is known is not a time", "core 9.4");
  }
  if (!Array.isArray(events)) return EMPTY;
  const length: unknown = events.length;
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0) return EMPTY;
  const most = maxEventsOf(own(context, "maxEvents"));
  const taken: unknown[] = [];
  for (let i = 0; i < length && i < most; i++) taken.push(events[i]);
  return ok({ events: taken, most, tooLong: length > most });
}

function tooLong(most: number): Rejection {
  return {
    ok: false,
    issues: [
      {
        path: "",
        message: `the log has more than ${most} events, the most this verifier was set to read`,
        clause: "implementation limit",
      },
    ],
  };
}

/**
 * Verifies an identity log (Layer 1, Section 4) against the evidence held of
 * when each of its events existed (core 9.5).
 *
 * The result holds the state after each event and each event's evaluation
 * time. A member-controlled log needs its members' logs, which
 * `context.memberLog` supplies; `LogBook` does that, and resolves duplicity.
 * The result is frozen.
 *
 * It never throws.
 */
export function verifyLog(events: unknown, context: LogContext): Validation<VerifiedLog> {
  try {
    const opened = open(events, context);
    if (!opened.ok) return opened;
    if (opened.value.tooLong) return tooLong(opened.value.most);
    const { log, failure } = replay(opened.value.events, context);
    return failure ?? (log === undefined ? EMPTY : ok(log));
  } catch {
    return unreadable;
  }
}

/**
 * Verifies an identity log as far as it goes: the events that verify, from
 * the first, why the next one does not, and whether that is the event's
 * fault or something this verifier lacks (Layer 1, 4.9).
 *
 * It never throws.
 */
export function verifyLogPrefix(events: unknown, context: LogContext): Replayed {
  try {
    const opened = open(events, context);
    if (!opened.ok) {
      // What is no array of events is no log. A time that is no time is the caller's.
      return { log: undefined, failure: opened, undecided: opened !== EMPTY };
    }
    const replayed = replay(opened.value.events, context);
    if (replayed.failure !== undefined || !opened.value.tooLong) return replayed;
    return { log: replayed.log, failure: tooLong(opened.value.most), undecided: true };
  } catch {
    return { log: undefined, failure: unreadable, undecided: true };
  }
}
