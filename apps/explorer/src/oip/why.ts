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
    "Each event of the log was checked here. The genesis is signed by every control key it names. Each later event has its place in the chain, reveals control keys that the event before it had committed to, and is signed by each of them. Every signature was verified in this browser.",
    "L1 4.1",
    "L1 4.2",
    "L1 4.3",
    "core 5.2",
    "core 4.4",
  ),
  collectiveLog: reason(
    "Each event of the log was checked here. A collective has no key of its own for this. Its genesis is signed by every founding member, and each later event by as many of the members it had before as its threshold asks, and by each member that joins. A member signs with an invocation key of its own log, which was fetched and verified here too. Every signature was verified in this browser.",
    "L1 4.1",
    "L1 4.2",
    "L1 4.4",
    "L1 6.4",
    "core 4.4",
  ),
  standing: reason(
    "A mind is retired by a Retire event, which is the last of its log. No event follows it, and no key of the mind signs anything that counts from then on.",
    "L1 3.10",
    "L1 6.1",
  ),
  time: reason(
    "An event takes effect at its evaluation time: the later of the date it carries and the earliest moment there is evidence of it. The date an event carries is its author's claim, and is never evidence. The evidence here is the time at which a resolver you chose says it first saw the event. No signature covers that. A resolver is a witness: it is taken at its word for when, and for nothing else. Choose more than one, and the earliest that any of them gives is what counts.",
    "core 9.5",
    "core 9.4",
  ),
  keys: reason(
    "A key signs for the mind from the event that adds it. It stops when a later event removes it or retires the mind: a proof by it counts after that only where there is evidence that the proof was made before. A key the mind declares compromised signs nothing that counts from the time the mind names, whenever it was removed. Where a log has two branches, what either removes is removed. The stretches shown are worked out by the same functions that judge a proof.",
    "L1 6.1",
    "L1 6.2",
    "L1 3.10",
    "L1 7.3",
    "core 9.3",
  ),
  duplicity: reason(
    "Two valid events at one place of a log are duplicity: the mind's controller signed both. A verifier does not choose between them by length or by which arrived first, and the log is taken as far as the place before.",
    "L1 7.1",
    "L1 7.3",
  ),
  didDocument: reason(
    "The DID document is worked out from the log by replaying it. Nothing in it is a resolver's own word.",
    "L1 5.2",
    "L1 5.1",
  ),
  location: reason(
    "The location record shown is the one with the highest seq whose proof counts now. It says where the mind is at present, so one that a key since removed signed is not shown.",
    "L1 15.1",
    "L1 15.2",
  ),
  profile: reason(
    "The profile shown is the one the mind's current location record names, with a proof by the mind that counts now. A mind whose location record names none may publish one on its feed all the same: this page has not looked there.",
    "L1 16.1",
    "L1 16.4",
  ),
  aliases: reason(
    "An alias is verified only when it points back to the mind: another address whose own record names this one, or a web address that serves a statement of it. This page has not looked, and so shows each as the mind's own word and as nothing more.",
    "L1 5.3",
    "L0 4.2",
  ),
  resolver: reason(
    "A resolver serves records. It is asked, and not believed: every signature in what it served was verified here before any of it was shown. It is believed for one thing, which no signature gives: when it first saw each event.",
    "L1 17.1",
    "L1 17.2",
    "core 9.4",
  ),
  feed: reason(
    "A feed is a chain of entries that the mind signed, each naming the one before it. It is read from the mind's homes, which its verified log names. An entry that does not continue the chain is not listed.",
    "L1 10.1",
    "L1 10.3",
    "L1 13.1",
  ),
  checkpoint: reason(
    "A checkpoint is the mind's signed word on its feed up to an entry: how many entries, the last of them, and the Merkle root of them all. This browser worked the root out from the entries it verified. A checkpoint the mind published or anchored elsewhere says the same of this feed, or the mind has shown two feeds.",
    "L1 10.5",
    "L1 10.6",
  ),
  record: reason(
    "Each record was fetched by its content ID and hashed here: it is the record its entry names. Whether its author signed it is another question, and is answered beside it.",
    "core 3.1",
    "L1 10.2",
  ),
  countsFor: reason(
    "A record counts for a mind by a proof of that mind's own key, or by a delegate's proof that carries a chain of delegations covering the record. A record that does not count for its author is nobody's word: it is shown as what was published, and is given no status.",
    "L2 2",
    "L2 7.1",
    "L2 7.2",
  ),
  judged: reason(
    "A status is worked out from the records this page has read, and from nothing else. A Receipt, a withdrawal or a later Commitment that stands on a feed which was not read here is not counted. Read the feeds of the other parties, and the status is judged again with what they published.",
    "L2 8.3",
    "core 9.7",
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
  Collective: reason(
    "A charter is active until the identity log of its collective is retired, and dissolved from then on.",
    "L2 8.4",
    "L2 6.2",
  ),
  listing: reason(
    "An indexer's listing is an answer it signed. Each profile it names was fetched and verified here as its author's own before it was listed, and what could not be verified is not listed. An indexer can rank badly, or leave a mind out. It cannot forge a capability.",
    "L1 18.4",
    "L1 18.3",
  ),
} as const satisfies Readonly<Record<string, Reason>>;
