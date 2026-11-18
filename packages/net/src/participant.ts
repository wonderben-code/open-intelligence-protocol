// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Participant profiles (Layer 1, Section 16): what a mind says it is and
 * can do, and which of its profiles is current.
 */

import { contentId, type Instant } from "@oip/core";
import { type IdentityView, type JudgedRecord, latestState, ownSignedTime } from "@oip/identity";
import type { Participant, Validation } from "@oip/schema";

import { oneOfEach } from "./copies.ts";
import type { VerifiedFeed } from "./feed.ts";
import type { HeldLocation } from "./location.ts";
import { finding, judging, no, ok } from "./result.ts";

/** A profile that counts for its mind. */
export interface HeldParticipant {
  /** The record's content ID. */
  readonly id: string;
  /** The record. */
  readonly record: Participant;
  /** The evaluation time of its author's signature. */
  readonly time: Instant;
}

/**
 * Layer 1, 16.1: whether a profile counts for the mind it describes.
 *
 * It is signed by its author's own authority under the current-state rule
 * (6.1, item 6; for a collective 9.5), and its `kind` is the kind in the
 * mind's identity state. That no two of its capabilities share an `id`
 * (16.2) is part of the record being well formed, which `judgeRecord` has
 * checked.
 *
 * @param judged - The record, from `judgeRecord`.
 */
export function verifyParticipant(
  judged: JudgedRecord,
  view: IdentityView,
): Validation<HeldParticipant> {
  return judging(() => participantOf(judged, view));
}

/** The profile, as `verifyParticipant` answers when no check is cut short. */
function participantOf(judged: JudgedRecord, view: IdentityView): Validation<HeldParticipant> {
  if (judged.record.type !== "Participant") {
    return no("the record is not a Participant", "L1 16.1", "/type");
  }
  const record = judged.record as Participant;
  const log = view.log(record.author);
  if (!log.ok) return log;
  if (record.kind !== latestState(log.value).kind) {
    return no("`kind` is not the kind in the mind's identity state", "L1 16.1", "/kind");
  }
  const time = ownSignedTime(judged, record.author, view);
  if (time === undefined) {
    return no(
      "the profile is not signed by its author's own authority under the current-state rule",
      "L1 16.1",
      "/proof",
    );
  }
  return ok({ id: contentId(record), record, time });
}

/** What a verifier holds that tells which profile is current. */
export interface ProfileSources {
  /** The mind's current location record, from `currentLocation`. */
  readonly location?: HeldLocation | undefined;
  /** The mind's feed, from `verifyFeed`. */
  readonly feed?: VerifiedFeed | undefined;
}

/**
 * Layer 1, 16.4: the current profile of a mind, among those held. It is the
 * one the current location record names in `participant`. Failing that,
 * because there is no such record, it names none, or the one it names is
 * not held or does not count, it is the most recent profile that counts
 * among those the mind's feed publishes.
 *
 * @param profiles - The records held, from `judgeRecord`. Those that are no
 *   profile of this mind are passed over.
 * @returns `undefined` if neither names a profile that is held and counts.
 */
export function currentParticipant(
  profiles: Iterable<JudgedRecord>,
  mind: string,
  view: IdentityView,
  sources: ProfileSources,
): HeldParticipant | undefined {
  return finding(() => participantAmong(profiles, mind, view, sources));
}

/** The current profile, as `currentParticipant` answers when no check is cut short. */
function participantAmong(
  profiles: Iterable<JudgedRecord>,
  mind: string,
  view: IdentityView,
  sources: ProfileSources,
): HeldParticipant | undefined {
  // A profile held in several copies is one profile, with the proofs of them all (core 3.1).
  const held = oneOfEach(profiles, (record) => {
    const { type, author } = record as { type: string; author?: unknown };
    return type === "Participant" && author === mind;
  });
  /** The profile with this content ID, if it is held and counts. */
  const counted = (id: string | undefined): HeldParticipant | undefined => {
    const judged = id === undefined ? undefined : held.get(id);
    const verified = judged && participantOf(judged, view);
    return verified?.ok === true ? verified.value : undefined;
  };
  const { location, feed } = sources;
  const named = location?.record.author === mind ? counted(location.record.participant) : undefined;
  if (named !== undefined) return named;
  if (feed?.author !== mind) return undefined;
  for (const { entry } of feed.entries.toReversed()) {
    if (entry.objectType !== "Participant") continue;
    const published = counted(entry.object);
    if (published !== undefined) return published;
  }
  return undefined;
}
