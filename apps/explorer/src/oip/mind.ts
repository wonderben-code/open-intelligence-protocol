// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind as the Explorer shows it: what a resolution found, laid out for a
 * page. Nothing here asks the network anything, and nothing here decides
 * anything: every verdict was the client's, made in this browser, and this
 * module only says what it was.
 */

import type { Resolved } from "@oip/client";
import { contentId, formatTimestamp } from "@oip/core";

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
  /** How many proofs it carries. */
  readonly proofs: number;
  /** What it changed, in words: the keys it added and removed, the homes it set. */
  readonly changes: readonly string[];
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
  /** The event that removed it, if one did. */
  readonly until?: number;
  /** When that event took effect. A proof first seen later does not count (core 9.3). */
  readonly untilTime?: string;
}

/** A mind, as a page shows it. */
export interface MindView {
  readonly address: string;
  readonly kind: string;
  /** `key` for a mind whose control keys extend its log, `member` for a collective. */
  readonly controller: string;
  readonly retired: boolean;
  /** Whether two valid events were seen at one place of the log (Layer 1, Section 7). */
  readonly duplicitous: boolean;
  readonly events: readonly EventView[];
  readonly keys: readonly KeyView[];
  readonly homes: readonly string[];
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

/** The keys of a state, by role. */
const keysOf = (
  state: Resolved["state"],
): Readonly<Record<(typeof ROLES)[number], readonly string[]>> => ({
  operational: state.keys,
  invocation: state.invocation,
  agreement: state.agreement,
});

/** Lays a resolution out for a page. */
export function mindView(resolved: Resolved): MindView {
  const events: EventView[] = [];
  const keys: {
    key: string;
    role: KeyView["role"];
    since: number;
    sinceTime: string;
    until?: number;
    untilTime?: string;
  }[] = [];
  let before: Resolved["state"] | undefined;
  for (const { event, state, time } of resolved.log.entries) {
    const at = formatTimestamp(time);
    const changes: string[] = [];
    for (const role of ROLES) {
      const had = before === undefined ? [] : keysOf(before)[role];
      const has = keysOf(state)[role];
      for (const key of has.filter((one) => !had.includes(one))) {
        keys.push({ key, role, since: state.seq, sinceTime: at });
        changes.push(`adds the ${role} key ${key}`);
      }
      for (const key of had.filter((one) => !has.includes(one))) {
        const open = keys.find(
          (one) => one.key === key && one.role === role && one.until === undefined,
        );
        if (open !== undefined) {
          open.until = state.seq;
          open.untilTime = at;
        }
        changes.push(`removes the ${role} key ${key}`);
      }
    }
    const homes = state.homes.join(", ");
    if (before === undefined ? state.homes.length > 0 : homes !== before.homes.join(", ")) {
      changes.push(homes === "" ? "names no home" : `names its homes: ${homes}`);
    }
    if (state.retired && before?.retired !== true) changes.push("retires the mind");
    const proof: unknown = (event as { proof?: unknown }).proof;
    events.push({
      seq: state.seq,
      type: event.type,
      id: contentId(event),
      created: event.created,
      evaluated: at,
      proofs: Array.isArray(proof) ? proof.length : 0,
      changes,
    });
    before = state;
  }
  const { state, participant, location } = resolved;
  return {
    address: resolved.mind,
    kind: state.kind,
    controller: state.controller.kind,
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
