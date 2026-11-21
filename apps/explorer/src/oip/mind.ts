// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind as the Explorer shows it: what a resolution found, laid out for a
 * page. Nothing here asks the network anything, and nothing here decides
 * anything: every verdict was the client's, made in this browser, and this
 * module only says what it was.
 */

import type { Resolved } from "@oip/client";
import { contentId, formatTimestamp, type Instant } from "@oip/core";
import {
  compromisedSince,
  type IdentityState,
  type LogEntry,
  removalTime,
  type VerifiedLog,
} from "@oip/identity";

/**
 * Something a page says in its own words, with the keys, addresses or
 * origins it speaks of set apart, and what follows them.
 *
 * What is set apart is a stranger's text where it is an alias or a reason,
 * and is shown as any stranger's text is.
 */
export interface Said {
  readonly says: string;
  readonly code?: readonly string[];
  readonly more?: string;
}

/** One event of a mind's identity log. */
export interface EventView {
  /** Its place in the log, from 0. */
  readonly seq: number;
  /** `Genesis`, `Update`, `Fork`, `Retire`. */
  readonly type: string;
  /** Its content ID. */
  readonly id: string;
  /** When its author says it was made. A claim, and no more (core 7). */
  readonly created: string;
  /** Its evaluation time: no earlier than the evidence this browser has of it (core 9.5). */
  readonly evaluated: string;
  /**
   * Who signed it: what Layer 1, Section 4 asks of such an event. The
   * client gives a log only if every event of it met this, so it is said of
   * each event, and not counted from the proofs an event carries: a proof
   * costs nothing to add, and one that verifies nothing is carried as any
   * other.
   */
  readonly signed: Said;
  /** What it changed: the keys it added, removed and revoked, the homes it set, and the rest. */
  readonly changes: readonly Said[];
}

/** How the stretch of a key ended. */
export interface KeyEnd {
  /** When. A proof by the key first seen then, or later, does not count (Layer 1, 6.1, item 3). */
  readonly time: string;
  /**
   * What ended it: an event that removed the key, the event that retired
   * the mind, or an event of another branch of a log that has two (Layer
   * 1, 7.3), which is not among the events shown.
   */
  readonly why: "removed" | "retired" | "branch";
  /** The event, where it is one of the log as shown. */
  readonly event?: number;
}

/** A key of a mind, with the stretch of the log in which it is the mind's. */
export interface KeyView {
  readonly key: string;
  /** What it is for: signing records, signing identity events of a collective, or opening sealed packets. */
  readonly role: "operational" | "invocation" | "agreement";
  /** The event that added it. */
  readonly since: number;
  /** When that event took effect. */
  readonly sinceTime: string;
  /** How its stretch ended, if it has. */
  readonly ended?: KeyEnd;
  /**
   * From when the mind declares the key compromised: no proof by it on a
   * record of the mind's counts from then on, whenever the key was removed
   * (Layer 1, 6.1, item 4; 6.2). Of operational keys only.
   */
  readonly compromisedSince?: string;
  /** Whether that is at or before the key became the mind's: no proof by it counts at any time. */
  readonly never: boolean;
}

/** A mind, as a page shows it. */
export interface MindView {
  readonly address: string;
  readonly kind: string;
  /** `key` for a mind whose control keys extend its log, `member` for a collective. */
  readonly controller: string;
  /** A collective's members, and how many of them must sign an event of its log. */
  readonly members?: { readonly minds: readonly string[]; readonly threshold: number };
  /**
   * For a mind with control keys: how many keys the latest event commits
   * to for the next, and how many of them must sign it. None: the log can
   * never be extended.
   */
  readonly next?: { readonly keys: number; readonly threshold: number };
  readonly retired: boolean;
  /** Whether two valid events were seen at one place of the log (Layer 1, Section 7). */
  readonly duplicitous: boolean;
  readonly events: readonly EventView[];
  readonly keys: readonly KeyView[];
  readonly homes: readonly string[];
  /** Other names the log lists for the mind. Its own word: none is verified here (Layer 1, 5.3). */
  readonly alsoKnownAs: readonly string[];
  /** The DID document, as the resolution gives it. */
  readonly didDocument: object;
  /** The profile's own words, if the mind has a current profile. */
  readonly profile?: { readonly id: string; readonly record: object };
  /** Where the mind is reached, if it has a current location record. */
  readonly location?: { readonly id: string; readonly record: object; readonly stale: boolean };
  /** What each resolver answered. */
  readonly sources: readonly { readonly resolver: string; readonly failure?: string }[];
}

const ROLES = ["operational", "invocation", "agreement"] as const;
type Role = (typeof ROLES)[number];

/** The keys of a state, by role. */
const keysOf = (state: IdentityState): Readonly<Record<Role, readonly string[]>> => ({
  operational: state.keys,
  invocation: state.invocation,
  agreement: state.agreement,
});

const plural = (count: number, one: string, many: string): string =>
  `${String(count)} ${count === 1 ? one : many}`;

/** The most of a reason a mind gives for retiring that a line of the timeline holds. */
const MAX_REASON = 256;

type Controller =
  | { readonly keys: readonly string[]; readonly next?: readonly string[] }
  | { readonly members: readonly string[]; readonly threshold: number };

/** What an event has besides what every record has. Each member is as the schema of its type has it. */
interface EventFields {
  readonly controller?: Controller;
  readonly revoked?: readonly { readonly key: string; readonly compromisedSince?: string }[];
  readonly child?: string;
  readonly successor?: string;
  readonly reason?: string;
}

/** Who signed an event, by what Layer 1, 4.1, 4.3 and 4.4 ask. */
function signedOf(event: EventFields, before: IdentityState | undefined): Said {
  const given = event.controller;
  if (before === undefined) {
    // A genesis: every control key it names, or every founding member (4.1).
    if (given !== undefined && "members" in given) {
      return { says: "Signed by each of its founding members:", code: given.members };
    }
    return { says: "Signed by each control key it names:", code: given?.keys ?? [] };
  }
  if (before.controller.kind === "member") {
    const { members, threshold } = before.controller;
    const joining =
      given !== undefined && "members" in given
        ? given.members.filter((member) => !members.includes(member))
        : [];
    return {
      says:
        `Signed by at least ${String(threshold)} of the ${plural(members.length, "member", "members")} it had before` +
        (joining.length === 0 ? "." : ", and by each member that joins:"),
      ...(joining.length === 0 ? {} : { code: joining }),
    };
  }
  return {
    says: "Signed by each control key it reveals, which the event before had committed to:",
    code: given !== undefined && "keys" in given ? given.keys : [],
  };
}

/** What an event changed, against the state before it. */
function changesOf(
  event: EventFields & { readonly type: string },
  state: IdentityState,
  before: IdentityState | undefined,
): Said[] {
  const changes: Said[] = [];
  const revoked = new Map((event.revoked ?? []).map((entry) => [entry.key, entry]));
  const declared = (key: string): string | undefined => {
    const since = revoked.get(key)?.compromisedSince;
    return since === undefined ? undefined : `, and declares it compromised since ${since}`;
  };
  const told = new Set<string>();
  for (const role of ROLES) {
    const had = before === undefined ? [] : keysOf(before)[role];
    const has = keysOf(state)[role];
    for (const key of has.filter((one) => !had.includes(one))) {
      changes.push({ says: `adds the ${role} key`, code: [key] });
    }
    for (const key of had.filter((one) => !has.includes(one))) {
      const more = declared(key);
      told.add(key);
      changes.push({
        says: revoked.has(key) ? `revokes the ${role} key` : `removes the ${role} key`,
        code: [key],
        ...(more === undefined ? {} : { more }),
      });
    }
  }
  // A key may be revoked that the state before did not have: it can never be added.
  for (const key of revoked.keys()) {
    if (told.has(key)) continue;
    const more = declared(key);
    changes.push({ says: "revokes the key", code: [key], ...(more === undefined ? {} : { more }) });
  }
  if ((before?.homes ?? []).join(" ") !== state.homes.join(" ")) {
    changes.push(
      state.homes.length === 0
        ? { says: "names no home" }
        : { says: "names its homes:", code: state.homes },
    );
  }
  if ((before?.alsoKnownAs ?? []).join(" ") !== state.alsoKnownAs.join(" ")) {
    changes.push(
      state.alsoKnownAs.length === 0
        ? { says: "lists no other name for itself any more" }
        : {
            says: "says it is also known as",
            code: state.alsoKnownAs,
            more: ", which nobody has checked here",
          },
    );
  }
  const { controller } = state;
  if (controller.kind === "member") {
    const was = before?.controller.kind === "member" ? before.controller : undefined;
    if (
      was?.threshold !== controller.threshold ||
      was.members.join(" ") !== controller.members.join(" ")
    ) {
      changes.push({
        says: `has ${plural(controller.members.length, "member", "members")}, of which ${String(controller.threshold)} must sign each later event:`,
        code: controller.members,
      });
    }
  } else if (controller.next.length === 0) {
    changes.push({
      says: "commits to no control key for a next event: the log can never be extended",
    });
  } else {
    changes.push({
      says: `commits to ${plural(controller.next.length, "control key", "control keys")} for the next event, of which ${String(controller.nextThreshold)} must sign it`,
    });
  }
  if (before === undefined) {
    for (const parent of state.parents) {
      changes.push({
        says: "names a parent:",
        code: [parent.mind],
        more: ` at version ${parent.at}`,
      });
    }
  }
  if (event.child !== undefined)
    changes.push({ says: "acknowledges a child:", code: [event.child] });
  if (state.retired && before?.retired !== true) {
    changes.push({ says: "retires the mind: it signs nothing more" });
    if (event.successor !== undefined) {
      changes.push({ says: "names its successor:", code: [event.successor] });
    }
    if (event.reason !== undefined) {
      const reason = Array.from(event.reason);
      changes.push({
        says: "gives as its reason, in its own words:",
        code: [
          reason.length > MAX_REASON ? `${reason.slice(0, MAX_REASON).join("")}…` : event.reason,
        ],
      });
    }
  }
  return changes;
}

/**
 * How the stretch of a signing key ended, by the function the client
 * judges proofs with (`removalTime` of `@oip/identity`): the first later
 * event that removes the key or retires the mind, on the log or on a
 * conflicting branch of it.
 */
function endOf(
  log: VerifiedLog,
  position: number,
  key: string,
  set: "keys" | "invocation",
): KeyEnd | undefined {
  const time = removalTime(log, position, key, set);
  if (time === undefined) return undefined;
  // Which event of the log as shown it was, if it is one of them.
  const on = log.entries
    .slice(position + 1)
    .find(({ state }) => state.retired || !state[set].includes(key));
  if (on?.time !== time) return { time: formatTimestamp(time), why: "branch" };
  return {
    time: formatTimestamp(time),
    why: on.state[set].includes(key) ? "retired" : "removed",
    event: on.state.seq,
  };
}

/** How the stretch of an agreement key ended. It signs nothing: this is the state, laid out. */
function agreementEnd(
  entries: readonly LogEntry[],
  position: number,
  key: string,
): KeyEnd | undefined {
  const on = entries
    .slice(position + 1)
    .find(({ state }) => state.retired || !state.agreement.includes(key));
  if (on === undefined) return undefined;
  return {
    time: formatTimestamp(on.time),
    why: on.state.agreement.includes(key) ? "retired" : "removed",
    event: on.state.seq,
  };
}

/** Lays a resolution out for a page. */
export function mindView(resolved: Resolved): MindView {
  const { log } = resolved;
  const events: EventView[] = [];
  const keys: KeyView[] = [];
  let before: IdentityState | undefined;
  for (const [position, { event, state, time }] of log.entries.entries()) {
    const fields = event as EventFields & { readonly type: string };
    for (const role of ROLES) {
      const had = before === undefined ? [] : keysOf(before)[role];
      for (const key of keysOf(state)[role].filter((one) => !had.includes(one))) {
        const ended =
          role === "agreement"
            ? agreementEnd(log.entries, position, key)
            : endOf(log, position, key, role === "operational" ? "keys" : "invocation");
        // A member's declaration reaches its own records, and no other mind's events (6.2, 6.4).
        const compromised: Instant | undefined =
          role === "operational" ? compromisedSince(log, key) : undefined;
        keys.push({
          key,
          role,
          since: state.seq,
          sinceTime: formatTimestamp(time),
          ...(ended === undefined ? {} : { ended }),
          ...(compromised === undefined ? {} : { compromisedSince: formatTimestamp(compromised) }),
          never: compromised !== undefined && compromised <= time,
        });
      }
    }
    events.push({
      seq: state.seq,
      type: event.type,
      id: contentId(event),
      created: event.created,
      evaluated: formatTimestamp(time),
      signed: signedOf(fields, before),
      changes: changesOf(fields, state, before),
    });
    before = state;
  }
  const { state, participant, location } = resolved;
  const { controller } = state;
  return {
    address: resolved.mind,
    kind: state.kind,
    controller: controller.kind,
    ...(controller.kind === "member"
      ? { members: { minds: controller.members, threshold: controller.threshold } }
      : { next: { keys: controller.next.length, threshold: controller.nextThreshold } }),
    retired: state.retired,
    duplicitous: resolved.duplicitous,
    events,
    keys,
    homes: state.homes,
    alsoKnownAs: state.alsoKnownAs,
    didDocument: resolved.did.didDocument,
    ...(participant === undefined
      ? {}
      : { profile: { id: participant.id, record: participant.record } }),
    ...(location === undefined
      ? {}
      : { location: { id: location.id, record: location.record, stale: resolved.stale } }),
    sources: resolved.sources.map((source) => {
      const { resolver, failure } = source as { resolver: string; failure?: string };
      return { resolver, ...(failure === undefined ? {} : { failure }) };
    }),
  };
}
