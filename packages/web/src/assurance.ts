// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Assurance levels (Layer 0, 1.3): whether a gateway has declared that it
 * acts for a mind, and whether that has been shown.
 *
 * A gateway represents a system that is not on the network with a
 * **bridged mind**, whose keys the gateway holds. It says so in three
 * places (Layer 0, 1.2): in the mind's `Genesis`, in the mind's profile,
 * and in an entry of its own feed that names the `Genesis`. The third is
 * the gateway's own word, signed with its own key: the first two are
 * written by whoever made the mind, and anyone can name a gateway there.
 */

import { contentId, parseRecordRef } from "@oip/core";
import type { DelegationContext } from "@oip/delegation";
import type { JudgedRecord } from "@oip/identity";
import { finding } from "@oip/schema";

import { countsFor } from "./counts.ts";

/**
 * How far a mind is what its records say (Layer 0, 1.3).
 *
 * - `native`: no gateway has declared the mind bridged. It is the default,
 *   and means no more than that: a gateway that omits the declaration is
 *   not found out by it.
 * - `bridged`: a gateway acts for an external system, and attests it.
 * - `claimed`: an assertion nobody has verified.
 */
export type Assurance = "native" | "bridged" | "claimed";

/** The extension block in which a bridged mind names its gateway (Layer 0, 1.2). */
export const BRIDGE_BLOCK = "oip.bridge";

/**
 * The bridge block of a record, or `undefined` if it has none. A record
 * that was judged has objects for its extension blocks (core 8.1).
 */
function blockOf(record: {
  readonly ext?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
}): Readonly<Record<string, unknown>> | undefined {
  const { ext } = record;
  return ext !== undefined && Object.hasOwn(ext, BRIDGE_BLOCK) ? ext[BRIDGE_BLOCK] : undefined;
}

/** The level, as `assuranceOf` answers when no check is cut short. */
function levelOf(profile: JudgedRecord, context: DelegationContext): Assurance {
  const { record } = profile;
  const block = blockOf(record);
  const mind = (record as { readonly author?: unknown }).author;
  const log = typeof mind === "string" ? context.identity.log(mind) : undefined;
  const genesis = log?.ok === true ? log.value.entries[0].event : undefined;
  const declared = genesis === undefined ? undefined : blockOf(genesis);
  // No block in the profile, and none in the genesis this verifier holds: nothing was declared.
  // A genesis that names a gateway is a declaration, whatever the profile leaves out.
  if (block === undefined) return declared === undefined ? "native" : "claimed";
  const { gateway } = block;
  if (typeof mind !== "string" || typeof gateway !== "string" || genesis === undefined) {
    return "claimed";
  }
  // The profile is the mind's own, and so is what it names.
  if (!countsFor(profile, mind, context)) return "claimed";
  // The mind was made as a bridged mind of this gateway: a profile cannot make it one later.
  if (declared?.["gateway"] !== gateway) return "claimed";
  // The gateway says so itself: an entry of its feed, for this genesis, that counts for it.
  // The profile names the entry by its reference. One carried in its place names none.
  const named = parseRecordRef(block["attestation"]);
  const entry = named === undefined ? undefined : context.records.record(named.contentId);
  if (entry === undefined) return "claimed";
  const attested = entry.record as {
    readonly type: string;
    readonly author?: unknown;
    readonly object?: unknown;
    readonly objectType?: unknown;
  };
  if (
    attested.type !== "Entry" ||
    attested.author !== gateway ||
    attested.objectType !== "Genesis" ||
    attested.object !== contentId(genesis)
  ) {
    return "claimed";
  }
  return countsFor(entry, gateway, context) ? "bridged" : "claimed";
}

/**
 * Layer 0, 1.3: the assurance level of the mind a profile describes.
 *
 * Where neither the profile nor the mind's `Genesis` has an `oip.bridge`
 * block, the mind is `native`. Where the `Genesis` has one and the profile
 * has none, it is `claimed`: a gateway was named, and nothing shows it.
 * Where the profile has one, the mind is `bridged` only if all of this
 * holds, and `claimed` otherwise:
 *
 * - the profile counts for the mind (Layer 2, 7.1);
 * - the mind's `Genesis` names the same gateway in its own block;
 * - the profile's `attestation` is the `record-ref` of an `Entry` this
 *   verifier holds, whose author is that gateway, whose `object` is the
 *   content ID of the mind's `Genesis` and whose `objectType` is `Genesis`;
 * - that entry counts for the gateway.
 *
 * The mind's log is the verifier's to hold. A verifier that holds none
 * cannot see the `Genesis`: for a profile without a block it answers
 * `native`, which is the default of 1.3, and for a profile with one,
 * `claimed`. A caller that wants the answer of 1.3 resolves the mind first,
 * as `Lookup.assurance` of `@oip/client` does.
 *
 * Where a check was cut short the answer is `claimed`: nothing was shown.
 * A caller that keeps answers compares `cutShortCount()`, as for any
 * function that answers with a value (ADR-0010).
 *
 * @param profile - A `Participant`, from `judgeRecord`.
 * @param context - The logs and the records the verifier holds, with its
 *   evidence of time. The entry the profile names is looked for among the
 *   records, by its content ID.
 */
export function assuranceOf(profile: JudgedRecord, context: DelegationContext): Assurance {
  return finding(() => levelOf(profile, context)) ?? "claimed";
}
