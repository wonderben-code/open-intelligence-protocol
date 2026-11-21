// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Status (Layer 2, Section 8): the state of an Intent, an Offer, a
 * Commitment or a charter, from the records a verifier holds and a time.
 * Two verifiers that hold other records answer differently, and so does one
 * verifier later.
 */

import { contentId, type Instant, parseTimestamp } from "@oip/core";
import { disregardingCompromise, type JudgedRecord, latestState } from "@oip/identity";
import {
  type Commitment,
  type Intent,
  judging,
  type Offer,
  type Receipt,
  type Validation,
} from "@oip/schema";

import { actsFor, countsFor } from "./counts.ts";
import { referenced, type WebContext, withHeldAs } from "./records.ts";
import { no, ok } from "./result.ts";

/** Layer 2, 8.1. */
export type IntentStatus = "open" | "withdrawn" | "satisfied" | "superseded" | "expired";
/** Layer 2, 8.2. */
export type OfferStatus = "open" | "withdrawn" | "superseded" | "expired" | "exhausted";
/** Layer 2, 8.3. */
export type CommitmentStatus =
  | "proposed"
  | "disputed"
  | "accepted"
  | "cancelled"
  | "fulfilled"
  | "claimed-fulfilled"
  | "broken"
  | "overdue";
/** Layer 2, 8.4. */
export type CharterStatus = "active" | "dissolved";

/**
 * Layer 2, 7.3: whether a Commitment is accepted. It counts for its
 * `author`; its author is a party, or signs for one through a delegation or
 * a charter role (5.2); and it counts for every party with `required` true.
 */
export function commitmentAccepted(given: JudgedRecord, context: WebContext): boolean {
  if (given.record.type !== "Commitment") return false;
  return accepted(given, contentId(given.record), context);
}

/** As `commitmentAccepted`, for a Commitment whose content ID is worked out already. */
function accepted(given: JudgedRecord, id: string, context: WebContext): boolean {
  // Every check below answers no for a check that was cut short (ADR-0010), so it is yes
  // only where each signature it needs was judged.
  // Section 2: with the proofs of every copy held, the one asked about among them.
  const judged = withHeldAs(given, id, context.records);
  const { author, parties } = judged.record as Commitment;
  if (!countsFor(judged, author, context)) return false;
  const signsForAParty =
    parties.some((party) => party.mind === author) ||
    parties.some((party) => actsFor(judged, author, party.mind, context));
  if (!signsForAParty) return false;
  return parties.every(
    (party) => party.required !== true || countsFor(judged, party.mind, context),
  );
}

/** A record of another type, or a time that is none, is a mistake in the calling program (ADR-0007). */
function expect(judged: JudgedRecord, type: string, at: Instant): void {
  if (judged.record.type !== type) throw new TypeError(`the record is not ${type}`);
  if (typeof (at as unknown) !== "bigint")
    throw new TypeError("the time of computation is not a time");
}

/** In the order of their standing: Layer 2, Section 8. */
const STANDING = ["satisfied", "withdrawn", "superseded"] as const;

/**
 * Layer 2, Section 8: what supersession makes of a record. A superseding
 * record that carries `status` has that status itself. Otherwise the valid
 * superseding records by the record's own author decide: `satisfied` before
 * `withdrawn`, and `withdrawn` before an edit.
 *
 * @param id - The record's content ID.
 * @param allowed - The values of `status` that mean something for this type.
 */
function supersession(
  judged: JudgedRecord,
  id: string,
  allowed: readonly string[],
  context: WebContext,
): (typeof STANDING)[number] | undefined {
  const record = judged.record as Intent | Offer;
  if (record.supersedes !== undefined && allowed.includes(record.status ?? "")) {
    return record.status as (typeof STANDING)[number];
  }
  const found = new Set<string>();
  for (const other of context.records.supersedersOf(id)) {
    const later = other.record as Intent | Offer;
    // Whatever the view answers with: of the same type, by the same author, and naming this record.
    if (later.type !== record.type || later.author !== record.author) continue;
    if (referenced(later.supersedes) !== id) continue;
    if (!countsFor(other, later.author, context)) continue;
    if (later.status === undefined) found.add("superseded");
    else if (allowed.includes(later.status)) found.add(later.status);
  }
  return STANDING.find((status) => found.has(status));
}

/**
 * The accepted Commitments held that list a record in `resolves` and also
 * count for that record's author (8.1, 8.2).
 */
function resolving(
  id: string,
  author: string,
  context: WebContext,
  only: (commitment: Commitment) => boolean = () => true,
): number {
  let count = 0;
  for (const other of context.records.resolversOf(id)) {
    // Whatever the view answers with: a Commitment that lists this record in `resolves`.
    if (other.record.type !== "Commitment" || !only(other.record as Commitment)) continue;
    const resolved = (other.record as Commitment).resolves ?? [];
    if (!resolved.some((ref) => referenced(ref) === id)) continue;
    if (commitmentAccepted(other, context) && countsFor(other, author, context)) count++;
  }
  return count;
}

/**
 * Layer 2, 8.1: the status of an Intent at a time. Other minds cannot close
 * someone's Intent by committing among themselves: only an accepted
 * Commitment that also counts for the Intent's author satisfies it.
 *
 * @param at - The time of computation. It is the caller's: nothing here reads a clock.
 */
export function intentStatus(
  judged: JudgedRecord,
  at: Instant,
  context: WebContext,
): Validation<IntentStatus> {
  return judging(() => ok(statusOfIntent(judged, at, context)));
}

/** The status, as `intentStatus` answers when no check is cut short. */
function statusOfIntent(judged: JudgedRecord, at: Instant, context: WebContext): IntentStatus {
  expect(judged, "Intent", at);
  const intent = judged.record as Intent;
  // Worked out once: it is most of what the status of a record costs.
  const id = contentId(intent);
  const superseded = supersession(judged, id, ["satisfied", "withdrawn"], context);
  if (superseded !== undefined) return superseded;
  const closing = (commitment: Commitment): boolean => commitment.closesIntent === true;
  if (resolving(id, intent.author, context, closing) > 0) return "satisfied";
  if (judged.expires !== undefined && at > judged.expires) return "expired";
  return "open";
}

/** Layer 2, 8.2: the status of an Offer at a time. */
export function offerStatus(
  judged: JudgedRecord,
  at: Instant,
  context: WebContext,
): Validation<OfferStatus> {
  return judging(() => ok(statusOfOffer(judged, at, context)));
}

/** The status, as `offerStatus` answers when no check is cut short. */
function statusOfOffer(judged: JudgedRecord, at: Instant, context: WebContext): OfferStatus {
  expect(judged, "Offer", at);
  const offer = judged.record as Offer;
  const id = contentId(offer);
  const superseded = supersession(judged, id, ["withdrawn"], context);
  // An Offer is never `satisfied`: that value of `status` means nothing on one.
  if (superseded === "withdrawn" || superseded === "superseded") return superseded;
  if (judged.expires !== undefined && at > judged.expires) return "expired";
  const quantity = offer.terms.quantity;
  if (quantity !== undefined && resolving(id, offer.author, context) >= quantity) {
    return "exhausted";
  }
  return "open";
}

/**
 * Layer 2, 8.3: the status of a Commitment at a time.
 *
 * A `broken` status is a claim by the authors of the `broken` Receipts, and
 * not a finding: show who made it.
 */
export function commitmentStatus(
  judged: JudgedRecord,
  at: Instant,
  context: WebContext,
): Validation<CommitmentStatus> {
  return judging(() => ok(statusOfCommitment(judged, at, context)));
}

/** The status, as `commitmentStatus` answers when no check is cut short. */
function statusOfCommitment(
  judged: JudgedRecord,
  at: Instant,
  context: WebContext,
): CommitmentStatus {
  expect(judged, "Commitment", at);
  const commitment = judged.record as Commitment;
  const id = contentId(commitment);
  // Item 1.
  if (!accepted(judged, id, context)) {
    const lenient = { ...context, identity: disregardingCompromise(context.identity) };
    return accepted(judged, id, lenient) ? "disputed" : "proposed";
  }
  const parties = new Set(commitment.parties.map((party) => party.mind));
  const receipts = context.records.receiptsAbout(id).filter((receipt) => {
    // Whatever the view answers with, only a Receipt about this Commitment is one.
    if (receipt.record.type !== "Receipt") return false;
    const { author, about } = receipt.record as Receipt;
    if (referenced(about) !== id) return false;
    return parties.has(author) && countsFor(receipt, author, context);
  });
  // `R`: without the Receipts that another Receipt about this Commitment, of the same author,
  // supersedes, and without the revoked.
  const ids = new Map(receipts.map((receipt) => [receipt, contentId(receipt.record)]));
  const authors = new Map(
    receipts.map((receipt) => [ids.get(receipt), (receipt.record as Receipt).author]),
  );
  const superseded = new Set<string>();
  for (const receipt of receipts) {
    const { supersedes, author } = receipt.record as Receipt;
    const earlier = referenced(supersedes);
    if (earlier !== undefined && authors.get(earlier) === author) superseded.add(earlier);
  }
  const standing = receipts.filter((receipt) => {
    const own = ids.get(receipt);
    return (
      own !== undefined && !superseded.has(own) && (receipt.record as Receipt).outcome !== "revoked"
    );
  });
  const withOutcome = (outcome: string): JudgedRecord[] =>
    standing.filter((receipt) => (receipt.record as Receipt).outcome === outcome);
  const countFor = (among: readonly JudgedRecord[], mind: string): boolean =>
    among.some((receipt) => countsFor(receipt, mind, context));
  // Item 2.
  const cancelled = withOutcome("cancelled");
  const required = commitment.parties.filter((party) => party.required === true);
  if (cancelled.length > 0 && required.every((party) => countFor(cancelled, party.mind))) {
    return "cancelled";
  }
  // Item 3.
  const fulfilled = withOutcome("fulfilled");
  const creditors = commitment.parties.filter((party) => party.role === "creditor");
  const candidate =
    fulfilled.length === 0
      ? "accepted"
      : commitment.terms.selfReport === true ||
          creditors.some((party) => countFor(fulfilled, party.mind))
        ? "fulfilled"
        : "claimed-fulfilled";
  // Items 4 to 6.
  const broken = withOutcome("broken").length > 0;
  const disputed = withOutcome("disputed").length > 0;
  if (candidate !== "accepted") return broken || disputed ? "disputed" : candidate;
  if (broken) return "broken";
  if (disputed) return "disputed";
  // Items 7 and 8.
  const deadline =
    commitment.terms.deadline === undefined ? undefined : parseTimestamp(commitment.terms.deadline);
  return deadline !== undefined && at > deadline ? "overdue" : "accepted";
}

/**
 * Layer 2, 8.4: the status of a collective's charter. It is `dissolved` if
 * the collective's identity log is retired, and `active` otherwise.
 *
 * @returns The status, or why the collective's log is not known.
 */
export function charterStatus(collective: string, context: WebContext): Validation<CharterStatus> {
  return judging(() => statusOfCharter(collective, context));
}

/** The status, as `charterStatus` answers when no check is cut short. */
function statusOfCharter(collective: string, context: WebContext): Validation<CharterStatus> {
  const log = context.identity.log(collective);
  if (!log.ok) return log;
  return ok(latestState(log.value).retired ? "dissolved" : "active");
}

/** Every status of Layer 2, Section 8. */
export type Status = IntentStatus | OfferStatus | CommitmentStatus | CharterStatus;

/**
 * Layer 2, Section 8: the status of a record at a time, by its type.
 *
 * @returns The status. Or a rejection: the record is of a type that has no
 *   status, or it is a charter and the collective's log is not known.
 */
export function status(judged: JudgedRecord, at: Instant, context: WebContext): Validation<Status> {
  return judging(() => {
    const record = judged.record;
    switch (record.type) {
      case "Intent":
        return ok(statusOfIntent(judged, at, context));
      case "Offer":
        return ok(statusOfOffer(judged, at, context));
      case "Commitment":
        return ok(statusOfCommitment(judged, at, context));
      case "Collective":
        return statusOfCharter((record as { readonly author: string }).author, context);
      default:
        return no(`a record of type ${record.type} has no status`, "L2 8");
    }
  });
}
