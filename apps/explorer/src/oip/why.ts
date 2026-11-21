// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Why the Explorer says what it says: for each thing a page shows, what
 * was checked in this browser, and the clauses of the specification that
 * ask for the check.
 *
 * The clauses are those of `spec/clauses.json`, which is made from the
 * specifications themselves. A reason that named a clause the
 * specifications do not have would fail the tests.
 */

import list from "../../../../spec/clauses.json" with { type: "json" };

/** A clause of the specification, as a page refers to it. */
export interface ClauseRef {
  /** Its name: `core 9.3`, `L1 15.2`. */
  readonly id: string;
  /** The title of the section it is in. */
  readonly section: string;
  /** How it begins. */
  readonly summary: string;
  /** Where it can be read. */
  readonly href: string;
}

/** What a page says of one of the things it shows. */
export interface Reason {
  /** What was checked, and what follows from it. */
  readonly says: string;
  /** The clauses that ask for it. */
  readonly clauses: readonly ClauseRef[];
}

const SPEC = "https://github.com/wonderben-code/open-intelligence-protocol/blob/main/spec/";
const FILES: Readonly<Record<string, string>> = {
  core: "core.md",
  L0: "layer-0-bridge.md",
  L1: "layer-1-mind-network.md",
  L2: "layer-2-mind-web.md",
};

/** The fragment a heading has on the page that shows the specification. */
export function anchorOf(number: string, section: string): string {
  const words = `${number} ${section}`
    .toLowerCase()
    .replace(/[^a-z0-9 -]/gu, "")
    .replace(/ /gu, "-");
  return `#${words}`;
}

const known = new Map(list.clauses.map((clause) => [clause.id, clause]));

/**
 * A clause, by its name.
 *
 * @returns `undefined` for a name the specifications do not have: a
 *   failure may cite a limit of this implementation, which is no clause.
 */
export function clauseOf(id: string): ClauseRef | undefined {
  const found = known.get(id);
  if (found === undefined) return undefined;
  const [, place = ""] = id.split(" ");
  const [number = ""] = place.split(".");
  return {
    id,
    section: found.section,
    summary: found.summary,
    href: `${SPEC}${FILES[found.document] ?? ""}${anchorOf(number, found.section)}`,
  };
}

const reason = (says: string, ...ids: string[]): Reason => ({
  says,
  clauses: ids.flatMap((id) => {
    const clause = clauseOf(id);
    return clause === undefined ? [] : [clause];
  }),
});

/** The things a page shows, each with why it shows it so. */
export const WHY = {
  address: reason(
    "The address is did:oip: and the content ID of the mind's own genesis event. This browser hashed the event it was served, and the two agree.",
    "L1 2.2",
    "core 3.1",
  ),
  log: reason(
    "Each event of the log was checked here: the genesis by the keys it commits to, and each later event by its place in the chain and by the control keys that the event before it committed to. Every signature was verified in this browser.",
    "L1 4.1",
    "L1 4.2",
    "core 5.2",
    "core 4.4",
  ),
  time: reason(
    "An event takes effect at its evaluation time: the later of the date it carries and the earliest moment this browser has evidence of it. The date an event carries is its author's claim, and is never evidence.",
    "core 9.5",
    "core 9.4",
  ),
  keys: reason(
    "A key signs for the mind from the event that adds it. Once the log removes a key, a proof by it counts only where there is evidence that the proof was made before.",
    "L1 6.1",
    "L1 6.2",
    "core 9.3",
  ),
  duplicity: reason(
    "Two valid events at one place of a log are duplicity: the mind's controller signed both. A verifier does not choose between them by length or by which arrived first, and the log is taken as far as the place before.",
    "L1 7.1",
    "L1 7.3",
  ),
  didDocument: reason(
    "The DID document is worked out from the log by replaying it. Nothing in it is taken on a resolver's word.",
    "L1 5.1",
  ),
  location: reason(
    "The location record shown is the one with the highest seq whose proof counts now. It says where the mind is at present, so one that a key since removed signed is not shown.",
    "L1 15.1",
    "L1 15.2",
  ),
  profile: reason(
    "The profile shown is the one the current location record names, or else the latest the mind's feed publishes, with a proof by the mind that counts now.",
    "L1 16.1",
    "L1 16.4",
  ),
  resolver: reason(
    "A resolver serves records. It is asked, and not believed: everything it served was verified here before any of it was shown.",
    "L1 17.1",
  ),
  feed: reason(
    "A feed is a chain of entries that the mind signed, each naming the one before it. It is read from the mind's homes, which its verified log names. An entry that does not continue the chain is not listed.",
    "L1 10.1",
    "L1 10.3",
    "L1 13.1",
  ),
  record: reason(
    "Each record was fetched by its content ID and hashed here: it is the record its entry names, with its proofs verified.",
    "core 3.1",
    "L1 10.2",
  ),
  countsFor: reason(
    "A record counts for a mind by a proof of that mind's own key, or by a delegate's proof that carries a chain of delegations covering the record.",
    "L2 7.1",
    "L2 7.2",
  ),
  Intent: reason(
    "An Intent is open until its author withdraws or replaces it, it expires, or an accepted Commitment that closes it counts for its author too. Other minds cannot close it by committing among themselves.",
    "L2 8.1",
  ),
  Offer: reason(
    "An Offer is open until its author withdraws or replaces it, it expires, or as many accepted Commitments as it allows have taken it up.",
    "L2 8.2",
  ),
  Commitment: reason(
    "A Commitment is accepted once it counts for its author and for every party that must sign. After that it stands as the Receipts about it say: fulfilled by the word of a party that was owed, and only claimed to be by the word of the one that owed.",
    "L2 7.3",
    "L2 8.3",
  ),
  listing: reason(
    "An indexer's listing is an answer it signed, and each profile in it was verified here as any profile is. An indexer can rank badly. It cannot forge a capability.",
    "L1 18.2",
    "L1 18.3",
  ),
} as const satisfies Readonly<Record<string, Reason>>;
