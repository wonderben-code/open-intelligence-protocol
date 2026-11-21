// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the functions of this package and of `@oip/delegation` answer with
 * the call stack all but spent. `spent-stack.test.ts` runs it in a process
 * of its own (`inNode` says why) and reads what it prints.
 *
 * Each case is one where leaving out a record whose check could not be
 * finished gives the answer that record was there to change: a withdrawal,
 * a `broken` Receipt, a revocation, a charter that supersedes another.
 */

import { contentId, formatRecordRef, proofDigest } from "@oip/core";
import { delegatedTime, revokedTime } from "@oip/delegation";
import { FirstSeen, judgeRecord, LogBook } from "@oip/identity";
import { type JsonObject, tally, withStackSpent } from "@oip/testkit";
import { at, Collective, intentBy, KeyMind, LATER, type Mind, T } from "@oip/testkit/minds";

import {
  charterInForce,
  commitmentStatus,
  countsFor,
  status,
  type WebContext,
  WebRecordSet,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

const ann = new KeyMind("ann");
const bo = new KeyMind("bo");
const club = new Collective("club", [ann, bo], 2, 5);
const minds: Mind[] = [ann, bo, club];

const ref = (record: object) =>
  formatRecordRef((record as { author: string }).author, contentId(record));

function judged(record: object) {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

/** What a verifier holds, each proof seen when it was made. The book has verified nothing yet. */
function holding(records: readonly Signed[]): WebContext {
  const evidence = new FirstSeen();
  const instant = (created: unknown) => BigInt(Date.parse(String(created))) * 1_000_000n;
  for (const mind of minds) {
    for (const event of mind.events) evidence.sawEvent(contentId(event), instant(event.created));
  }
  const set = new WebRecordSet();
  for (const record of records) {
    for (const proof of record.proof) {
      evidence.sawProof(proofDigest(proof), instant(proof["created"]));
    }
    const added = set.add(record);
    if (!added.ok) throw new Error(JSON.stringify(added.issues));
  }
  const identity = new LogBook(evidence);
  for (const mind of minds) identity.hold(mind.events, LATER);
  return { identity, records: set };
}

/** The value of a result, or the clause it was refused with. */
const told = (
  answer: { ok: true; value: unknown } | { ok: false; issues: readonly { clause: string }[] },
) => (answer.ok ? String(answer.value) : (answer.issues[0]?.clause ?? "refused"));

function withdrawn(): unknown {
  const intent = ann.sign(intentBy(ann, 10)) as Signed;
  const withdrawal = ann.sign(
    intentBy(ann, 20, { supersedes: ref(intent), status: "withdrawn" }),
  ) as Signed;
  // What is held is taken in before, with room: a record whose taking in was refused for
  // want of room is not held, and a status without it would be a right answer to another
  // question.
  const context = holding([intent, withdrawal]);
  const asked = () => told(status(judged(intent), at(50), context));
  return { status: tally(withStackSpent(asked), (answer) => answer), after: asked() };
}

function broken(): unknown {
  const commitment = ann.sign(
    bo.sign({
      oip: "1",
      type: "Commitment",
      author: bo.address,
      created: T(10),
      parties: [
        { mind: bo.address, role: "debtor", required: true },
        { mind: ann.address, role: "creditor", required: true },
      ],
      promise: "Translate the lease.",
      terms: {},
    }),
  ) as Signed;
  const receipt = ann.sign({
    oip: "1",
    type: "Receipt",
    author: ann.address,
    created: T(30),
    about: ref(commitment),
    outcome: "broken",
  }) as Signed;
  const context = holding([commitment, receipt]);
  const asked = () => told(commitmentStatus(judged(commitment), at(50), context));
  return { status: tally(withStackSpent(asked), (answer) => answer), after: asked() };
}

function revoked(): unknown {
  const grant = ann.sign({
    oip: "1",
    type: "Delegation",
    author: ann.address,
    delegate: bo.address,
    subject: ann.address,
    command: "/oip/sign/Intent",
    expires: T(10_000),
    nonce: "nonce-0001",
    created: T(10),
  }) as Signed;
  const revocation = ann.sign({
    oip: "1",
    type: "Revocation",
    author: ann.address,
    revokes: ref(grant),
    created: T(30),
  }) as Signed;
  const late = bo.sign(intentBy(ann, 50), { more: { authority: [ref(grant)] } }) as Signed;
  const context = holding([grant, revocation, late]);
  const record = judged(late);
  const counts = () =>
    `${String(delegatedTime(record, ann.address, context))}, ${String(countsFor(record, ann.address, context))}`;
  const time = () =>
    told(revokedTime(contentId(grant), ann.address, context.records, context.identity));
  return {
    counts: tally(withStackSpent(counts), (answer) => answer),
    revoked: tally(withStackSpent(time), (answer) => answer),
    after: [counts(), time()],
  };
}

function superseded(): unknown {
  const charter = (seconds: number, more: JsonObject = {}): Signed =>
    club.sign(
      {
        oip: "1",
        type: "Collective",
        author: club.address,
        name: "The club",
        purpose: "To translate leases.",
        roles: { clerk: { purpose: "Posts requests.", powers: [{ command: "/oip/sign/Intent" }] } },
        assignments: [{ mind: ann.address, role: "clerk" }],
        created: T(seconds),
        ...more,
      },
      { position: 0 },
    );
  const first = charter(10);
  const second = charter(30, { supersedes: ref(first), assignments: [] });
  const posted = ann.sign(intentBy(club, 50), { more: { authority: [ref(first)] } }) as Signed;
  const context = holding([first, second, posted]);
  const record = judged(posted);
  const names = new Map([
    [contentId(first), "the first"],
    [contentId(second), "the second"],
  ]);
  const inForce = () => {
    const answer = charterInForce(club.address, at(50), context);
    return answer.ok ? (names.get(answer.value ?? "") ?? "none") : (answer.issues[0]?.clause ?? "");
  };
  const counts = () => String(countsFor(record, club.address, context));
  return {
    inForce: tally(withStackSpent(inForce), (answer) => answer),
    counts: tally(withStackSpent(counts), (answer) => answer),
    after: [inForce(), counts()],
  };
}

process.stdout.write(
  JSON.stringify({
    withdrawn: withdrawn(),
    broken: broken(),
    revoked: revoked(),
    superseded: superseded(),
  }),
);
