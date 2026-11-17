// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The containers: unsigned records that carry other records (core 1.6; Layer 1, 13.1 and 17.1). */

import { type Static, Type } from "typebox";

import { containerRecord } from "../common.ts";
import { meta, ref } from "../naming.ts";
import { Count, MindAddress, patterns } from "../primitives.ts";
import { Fork, Genesis, type IdentityEvent, Retire, Update } from "./identity.ts";
import { Entry, Location, Participant } from "./net.ts";

/** Any identity event. `Merge` is reserved and has no schema (Layer 1, 3.9). */
const Event = Type.Union([ref(Genesis), ref(Update), ref(Fork), ref(Retire)]);

/**
 * Layer 1, 13.1: first-seen times, keyed by the content ID of an identity
 * event or by the digest of a proof.
 */
export const FirstSeen = Type.Unsafe<Readonly<Record<string, string>>>({
  type: "object",
  propertyNames: {
    anyOf: [{ pattern: patterns.contentId }, { pattern: patterns.sha256Digest }],
  },
  additionalProperties: { type: "string", pattern: patterns.timestamp, maxLength: 30 },
});

export const Bundle = Type.Object(
  {
    ...containerRecord,
    type: Type.Literal("Bundle"),
    mind: MindAddress,
    log: Type.Array(Event),
    location: Type.Optional(ref(Location)),
    participant: Type.Optional(ref(Participant)),
    firstSeen: Type.Optional(FirstSeen),
  },
  meta(
    "Bundle",
    "A mind's identity log with its current location record and profile (Layer 1, 13.1).",
  ),
);
export type Bundle = Static<typeof Bundle>;

export const LogPage = Type.Object(
  {
    ...containerRecord,
    type: Type.Literal("LogPage"),
    mind: MindAddress,
    events: Type.Array(Event),
    next: Type.Optional(Count),
    firstSeen: Type.Optional(FirstSeen),
  },
  meta("LogPage", "One page of an identity log that is too long for a Bundle (Layer 1, 13.1)."),
);
export type LogPage = Static<typeof LogPage>;

export const FeedPage = Type.Object(
  {
    ...containerRecord,
    type: Type.Literal("FeedPage"),
    mind: MindAddress,
    entries: Type.Array(ref(Entry)),
    next: Type.Optional(Count),
  },
  meta("FeedPage", "One page of a mind's public feed (Layer 1, 13.1)."),
);
export type FeedPage = Static<typeof FeedPage>;

export const DuplicityEvidence = Type.Object(
  {
    ...containerRecord,
    type: Type.Literal("DuplicityEvidence"),
    mind: MindAddress,
    pairs: Type.Array(
      Type.Unsafe<[IdentityEvent, IdentityEvent]>({
        type: "array",
        prefixItems: [Event, Event],
        items: false,
        minItems: 2,
        maxItems: 2,
      }),
    ),
  },
  meta(
    "DuplicityEvidence",
    "Pairs of conflicting identity events at the same position of one log (Layer 1, 17.1).",
  ),
);
export type DuplicityEvidence = Static<typeof DuplicityEvidence>;
