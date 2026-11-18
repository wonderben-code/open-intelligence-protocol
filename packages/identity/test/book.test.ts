// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, proofDigest } from "@oip/core";
import type { Proof } from "@oip/schema";
import { clause, copy, type JsonObject } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  divergence,
  draftGenesis,
  draftUpdate,
  type EvidenceView,
  FirstSeen,
  judgeRecord,
  latestState,
  LogBook,
  ownSignedTime,
  signEventSync,
} from "../src/index.ts";
import {
  at,
  bookOf as bookOfMinds,
  Collective,
  intentBy,
  KeyMind,
  LATER,
  locationBy,
  rawSign,
  signer,
  T,
  unchecked,
  witness,
} from "@oip/testkit/minds";

type Events = KeyMind["events"];

/**
 * A mind whose control key signed twice: two logs that share a genesis and
 * part at position 1. `left` removes operational key 0; `right` keeps it.
 */
function twoBranches() {
  const left = new KeyMind("ada").update(20, { keys: [] });
  const right = new KeyMind("ada").update(20, { homes: ["https://ada.example"] });
  return { left, right, mind: left.address };
}

/** A book that holds branches, each event seen at the time given for it, or when it was made. */
function bookOf(branches: readonly Events[], seenAt: ReadonlyMap<object, number> = new Map()) {
  const evidence = new FirstSeen();
  const made = witness(branches);
  for (const events of branches) {
    for (const event of events) {
      const id = contentId(event);
      const seconds = seenAt.get(event);
      evidence.sawEvent(id, seconds === undefined ? made.eventSeen(id)! : at(seconds));
    }
  }
  const book = new LogBook(evidence);
  for (const events of branches) book.holdBranch(events, LATER);
  return { book, evidence };
}

const heads = (book: LogBook, mind: string) => {
  const log = book.log(mind);
  if (!log.ok) throw new Error(JSON.stringify(log.issues));
  return { log: log.value, heads: log.value.entries.map((entry) => entry.state.head) };
};

describe(`${clause("L1 7.1")} duplicity`, () => {
  it("is two different events at one position, each valid against the same predecessor", () => {
    const { left, right, mind } = twoBranches();
    expect(contentId(left.events[1])).not.toBe(contentId(right.events[1]));
    const { book } = bookOf([left.events, right.events]);
    const { log } = heads(book, mind);
    expect(log.duplicitous).toBe(true);
    expect(log.entries).toHaveLength(1);
    expect(log.branchTails.map((tail) => tail.state.head).sort()).toEqual(
      [contentId(left.events[1]), contentId(right.events[1])].sort(),
    );
  });

  it("is not the same event with another set of proofs", () => {
    const keys = [signer("ada/a"), signer("ada/b"), signer("ada/c")];
    const draft = draftGenesis(T(0), {
      kind: "agent",
      controller: { keys: keys.map((key) => key.publicKey), next: [] },
    });
    const control = keys.map((key) => ({ control: key }));
    const one = signEventSync(draft, control);
    const other = signEventSync(draft, [...control].reverse());
    expect(one.proof).not.toEqual(other.proof);
    const { book } = bookOf([[one], [other]] as never);
    expect(heads(book, `did:oip:${contentId(one)}`).log.duplicitous).toBe(false);
  });

  it("is not a shorter copy of the same log, nor a branch that does not verify", () => {
    const ada = new KeyMind("ada").update(20).update(30);
    const { book } = bookOf([ada.events.slice(0, 2), ada.events, ada.events.slice(0, 1)]);
    const whole = heads(book, ada.address);
    expect(whole.log.duplicitous).toBe(false);
    expect(whole.heads).toEqual(ada.events.map((event) => contentId(event)));

    // A second event for position 1 that its control key never signed is no event at all.
    const forged = new KeyMind("ada");
    const head = { mind: forged.address, seq: 0, head: contentId(forged.events[0]) };
    const unsigned = signEventSync(
      draftUpdate(head, T(20), { controller: forged.controller(1), homes: [] }),
      [{ control: signer("someone else") }],
    );
    const withForgery = bookOf([ada.events, [forged.events[0], unsigned] as never]);
    expect(heads(withForgery.book, ada.address).log.duplicitous).toBe(false);
    expect(heads(withForgery.book, ada.address).heads).toHaveLength(3);
  });
});

describe(`${clause("L1 7.1")} finding where two logs part`, () => {
  const verifiedAlone = (events: Events) => {
    const { book } = bookOf([events]);
    return heads(book, `did:oip:${contentId(events[0])}`).log;
  };

  it("gives the position and the two events, in the order the logs were given", () => {
    const { left, right } = twoBranches();
    right.update(30);
    const [a, b] = [verifiedAlone(left.events), verifiedAlone(right.events)];
    const found = divergence(a, b);
    expect(found?.position).toBe(1);
    expect(found?.events.map((event) => contentId(event))).toEqual([
      contentId(left.events[1]),
      contentId(right.events[1]),
    ]);
    expect(divergence(b, a)?.events.map((event) => contentId(event))).toEqual([
      contentId(right.events[1]),
      contentId(left.events[1]),
    ]);
    // A later parting is found where it is.
    const one = new KeyMind("ada").update(20).update(30, { homes: [] });
    const two = new KeyMind("ada").update(20).update(30, { keys: [] });
    expect(divergence(verifiedAlone(one.events), verifiedAlone(two.events))?.position).toBe(2);
  });

  it("finds none in a log and its own beginning, in one log twice, or in the logs of two minds", () => {
    const ada = new KeyMind("ada").update(20).update(30);
    const whole = verifiedAlone(ada.events);
    const start = verifiedAlone(ada.events.slice(0, 2));
    expect(divergence(whole, start)).toBeUndefined();
    expect(divergence(start, whole)).toBeUndefined();
    expect(divergence(whole, whole)).toBeUndefined();
    const bea = verifiedAlone(new KeyMind("bea").update(20).events);
    expect(divergence(whole, bea)).toBeUndefined();
  });
});

describe(`${clause("L1 7.3")} resolving duplicity`, () => {
  it("takes the branch whose event at the divergence has the earlier evidence", () => {
    const { left, right, mind } = twoBranches();
    for (const [first, second] of [
      [left, right],
      [right, left],
    ] as const) {
      const seenAt = new Map<object, number>([
        [first.events[1] as object, 21],
        [second.events[1] as object, 22],
      ]);
      for (const order of [
        [left.events, right.events],
        [right.events, left.events],
      ]) {
        const { log, heads: found } = heads(bookOf(order, seenAt).book, mind);
        expect(log.duplicitous).toBe(false);
        expect(found[1]).toBe(contentId(first.events[1]));
        expect(log.branchTails).toEqual([]);
      }
    }
  });

  it("never chooses by length or by which is more recent", () => {
    const { left, right, mind } = twoBranches();
    right.update(30).update(40).update(50);
    const earlier = new Map<object, number>([
      [left.events[1] as object, 21],
      [right.events[1] as object, 22],
    ]);
    const { heads: found } = heads(bookOf([right.events, left.events], earlier).book, mind);
    expect(found).toEqual(left.events.map((event) => contentId(event)));
    // And with nothing to separate them, the longer branch does not win either.
    const { log } = heads(bookOf([right.events, left.events]).book, mind);
    expect(log.duplicitous).toBe(true);
    expect(log.entries).toHaveLength(1);
    expect(log.branchTails).toHaveLength(5);
  });

  it("resolves a later divergence the same way, among the branches still standing", () => {
    const base = () => new KeyMind("ada").update(20);
    const one = base().update(30, { homes: ["https://one.example"] });
    const two = base().update(30, { homes: ["https://two.example"] });
    const three = new KeyMind("ada").update(20, { homes: ["https://three.example"] });
    const seenAt = new Map<object, number>([
      [one.events[2] as object, 35],
      [two.events[2] as object, 34],
      [three.events[1] as object, 25],
    ]);
    const { log, heads: found } = heads(
      bookOf([one.events, two.events, three.events], seenAt).book,
      one.address,
    );
    // `three` lost at position 1, where the other two agree and were seen first.
    expect(log.duplicitous).toBe(false);
    expect(found).toEqual(two.events.map((event) => contentId(event)));
    const tied = heads(bookOf([one.events, two.events, three.events]).book, one.address);
    expect(tied.log.duplicitous).toBe(true);
    expect(tied.log.entries).toHaveLength(1);
  });

  describe("a duplicitous mind", () => {
    const { left, right, mind } = twoBranches();
    const ada = left;
    const records = {
      before: ada.sign(intentBy(ada, 10), { position: 0 }),
      after: ada.sign(intentBy(ada, 25), { position: 0 }),
      onLeft: left.sign(intentBy(ada, 25), { position: 1, by: ada.operational() }),
      onRight: right.sign(intentBy(ada, 25), { position: 1 }),
      present: ada.sign(locationBy(ada, 10), { position: 0 }),
    };
    const { book: logs, evidence } = bookOf([left.events, right.events]);
    for (const record of Object.values(records)) {
      for (const proof of record.proof) evidence.sawProof(proofDigest(proof), at(0));
    }
    const view = (seen: Readonly<Record<string, number>>): LogBook => {
      const times: EvidenceView = {
        eventSeen: (id) => evidence.eventSeen(id),
        proofSeen: (digest) => {
          const name = Object.entries(records).find(([, record]) =>
            record.proof.some((proof: Proof) => proofDigest(proof) === digest),
          )?.[0];
          return name === undefined || seen[name] === undefined ? undefined : at(seen[name]);
        },
      };
      const book = new LogBook(times);
      book.holdBranch(left.events, LATER);
      book.holdBranch(right.events, LATER);
      return book;
    };
    const counts = (name: keyof typeof records, seconds: number) => {
      const judged = judgeRecord(records[name]);
      if (!judged.ok) throw new Error("the record is not well formed");
      return ownSignedTime(judged.value, mind, view({ [name]: seconds })) !== undefined;
    };

    it("keeps records pinned to versions before the divergence", () => {
      expect(heads(logs, mind).log.duplicitous).toBe(true);
      expect(counts("before", 10)).toBe(true);
    });

    it("loses records pinned to versions at or after the divergence, on either branch", () => {
      expect(counts("onLeft", 25)).toBe(false);
      expect(counts("onRight", 25)).toBe(false);
    });

    it("loses records that describe the present", () => {
      expect(counts("present", 10)).toBe(false);
    });

    it("applies the removals of every branch, so duplicity never revives a key", () => {
      // The left branch removed key 0 at 20. The right branch kept it. It is removed.
      expect(counts("after", 25)).toBe(false);
      expect(counts("after", 19)).toBe(false);
      expect(counts("before", 19)).toBe(true);
      expect(counts("before", 20)).toBe(false);
    });
  });

  it("applies the earliest removal among the branches, whichever branch is held first", () => {
    // One branch removes key 0 at 30, the other at 20.
    const slow = new KeyMind("ada").update(20, { homes: [] }).update(30, { keys: [] });
    const fast = new KeyMind("ada").update(20, { keys: [] });
    const intent = slow.sign(intentBy(slow, 25), { position: 0 });
    for (const order of [
      [slow.events, fast.events],
      [fast.events, slow.events],
    ]) {
      const { book, evidence } = bookOf(order);
      expect(heads(book, slow.address).log.duplicitous).toBe(true);
      evidence.sawProof(proofDigest(intent.proof[0]!), at(25));
      const judged = judgeRecord(intent);
      expect(judged.ok && ownSignedTime(judged.value, slow.address, book)).toBeUndefined();
    }
  });

  it("applies the earliest compromise declaration among the branches", () => {
    const key = new KeyMind("ada").operational().publicKey;
    const late = new KeyMind("ada").update(20, { revoked: [{ key, compromisedSince: T(15) }] });
    const early = new KeyMind("ada").update(20, { revoked: [{ key, compromisedSince: T(5) }] });
    const none = new KeyMind("ada").update(20, { revoked: [{ key }] });
    const intent = late.sign(intentBy(late, 10), { position: 0 });
    for (const order of [
      [late.events, early.events, none.events],
      [none.events, early.events, late.events],
      [early.events, none.events, late.events],
    ]) {
      const { book, evidence } = bookOf(order);
      evidence.sawProof(proofDigest(intent.proof[0]!), at(10));
      const judged = judgeRecord(intent);
      expect(judged.ok && ownSignedTime(judged.value, late.address, book)).toBeUndefined();
    }
    // Without the early declaration, the proof at 10 stands: 15 is after it.
    const { book, evidence } = bookOf([late.events, none.events]);
    evidence.sawProof(proofDigest(intent.proof[0]!), at(10));
    const judged = judgeRecord(intent);
    expect(judged.ok && ownSignedTime(judged.value, late.address, book)).toBe(at(10));
  });

  it("applies the compromise declarations of every branch", () => {
    const left = new KeyMind("ada");
    const key = left.operational().publicKey;
    left.update(20, { revoked: [{ key, compromisedSince: T(5) }] });
    const right = new KeyMind("ada").update(20, { homes: [] });
    const { book: logs, evidence } = bookOf([left.events, right.events]);
    expect(heads(logs, left.address).log.duplicitous).toBe(true);
    const early = left.sign(intentBy(left, 4), { position: 0 });
    const late = left.sign(intentBy(left, 6), { position: 0 });
    for (const record of [early, late]) {
      evidence.sawProof(proofDigest(record.proof[0]!), at(6));
    }
    evidence.sawProof(proofDigest(early.proof[0]!), at(4));
    const signed = (record: object) => {
      const judged = judgeRecord(record);
      return judged.ok && ownSignedTime(judged.value, left.address, logs) !== undefined;
    };
    expect(signed(early)).toBe(true);
    expect(signed(late)).toBe(false);
  });
});

describe("the logs a verifier holds", () => {
  it("answers for a mind it holds no log of, and for one whose log does not verify", () => {
    const ada = new KeyMind("ada");
    const book = new LogBook(witness([ada.events]));
    expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 6.3" }] });
    expect(book.hold(ada.events, LATER)).toEqual({ ok: true, value: ada.address });
    expect(book.log(ada.address).ok).toBe(true);
    const broken = new KeyMind("bea").raw(10, "Update", { seq: 9 });
    const blind = new LogBook(witness([broken.events]));
    blind.hold(broken.events, LATER);
    expect(blind.log(broken.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 4.2" }] });
    // Asked again, the answer is the same one.
    expect(blind.log(broken.address)).toBe(blind.log(broken.address));
  });

  it("replaces a log by one that continues it, and forgets what it verified before", () => {
    const ada = new KeyMind("ada");
    const short = [...ada.events];
    ada.update(10).update(20);
    const book = new LogBook(witness([ada.events]));
    book.hold(short, LATER);
    expect(heads(book, ada.address).heads).toHaveLength(1);
    book.hold(ada.events, LATER);
    expect(heads(book, ada.address).heads).toHaveLength(3);
  });

  it(`${clause("L1 4.9")} does not replace a log by an earlier state of itself`, () => {
    // A source that lags, or lies, must not undo a removal the verifier knows of.
    const ada = new KeyMind("ada");
    const genesis = [...ada.events];
    ada.update(10).update(20, { keys: [] });
    const middle = ada.events.slice(0, 2);
    const book = new LogBook(witness([ada.events]));
    book.hold(ada.events, at(50));
    for (const earlier of [genesis, middle]) {
      expect(book.hold(earlier, at(90))).toMatchObject({
        ok: false,
        issues: [{ path: "", clause: "L1 4.9" }],
      });
      expect(heads(book, ada.address).heads).toHaveLength(3);
      // The time the log is known up to is not moved by a copy that was refused.
      expect(heads(book, ada.address).log.asOf).toBe(at(50));
      // As a branch it adds nothing, and is not held.
      expect(book.holdBranch(earlier, at(90))).toStrictEqual({ ok: true, value: ada.address });
      expect(heads(book, ada.address).heads).toHaveLength(3);
      expect(heads(book, ada.address).log.asOf).toBe(at(50));
    }
    // The same log, served again later, is known up to the later time.
    expect(book.hold(ada.events, at(90)).ok).toBe(true);
    expect(heads(book, ada.address).log.asOf).toBe(at(90));
    // To go back all the same, the caller says so.
    expect(book.drop(ada.address)).toBe(true);
    expect(book.drop(ada.address)).toBe(false);
    expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 6.3" }] });
    expect(book.hold(genesis, at(95))).toStrictEqual({ ok: true, value: ada.address });
    expect(heads(book, ada.address).heads).toHaveLength(1);
  });

  it("replaces a branch by one that continues it, and keeps the branch it conflicts with", () => {
    const { left, right, mind } = twoBranches();
    const longer = new KeyMind("ada").update(20, { keys: [] }).update(30);
    const evidence = witness([left.events, right.events, longer.events]);
    const book = new LogBook(evidence);
    book.holdBranch(left.events, LATER);
    book.holdBranch(right.events, LATER);
    expect(heads(book, mind).log.branchTails).toHaveLength(2);
    book.holdBranch(longer.events, LATER);
    // Still two branches: the longer one stands where the one it continues stood.
    const log = heads(book, mind).log;
    expect(log.duplicitous).toBe(true);
    expect(log.branchTails.map((entry) => entry.state.seq).sort()).toStrictEqual([1, 1, 2]);
  });

  it("knows a duplicitous log up to the earliest time any of its branches was known", () => {
    const { left, right, mind } = twoBranches();
    const evidence = witness([left.events, right.events]);
    for (const [first, second, asOf] of [
      [100, 200, 100],
      [200, 100, 100],
    ] as const) {
      const book = new LogBook(evidence);
      book.holdBranch(left.events, at(first));
      book.holdBranch(right.events, at(second));
      expect(heads(book, mind).log.asOf).toBe(at(asOf));
    }
    const book = new LogBook(evidence);
    book.hold(left.events, at(100));
    book.hold(left.events, at(300));
    expect(heads(book, mind).log.asOf).toBe(at(300));
  });

  it("knows a log that evidence decided up to the time its own branch was known", () => {
    const { left, right, mind } = twoBranches();
    const seenAt = new Map<object, number>([
      [left.events[1] as object, 30],
      [right.events[1] as object, 40],
    ]);
    for (const [leftAsOf, rightAsOf] of [
      [100, 200],
      [200, 100],
    ] as const) {
      const { evidence } = bookOf([left.events, right.events], seenAt);
      const book = new LogBook(evidence);
      book.holdBranch(left.events, at(leftAsOf));
      book.holdBranch(right.events, at(rightAsOf));
      const { log, heads: found } = heads(book, mind);
      // The branch seen first is the log, and what is known of the other says nothing about it.
      expect(found[1]).toBe(contentId(left.events[1]));
      expect(log.asOf).toBe(at(leftAsOf));
    }
  });

  it("gives the reasons of the first branch when none verifies", () => {
    const one = new KeyMind("ada").raw(10, "Update", { seq: 9 });
    const two = new KeyMind("ada").raw(10, "Merge");
    const book = new LogBook(witness([one.events, two.events]));
    book.holdBranch(one.events, LATER);
    book.holdBranch(two.events, LATER);
    expect(book.log(one.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 4.2" }] });
  });

  it("does not let a branch win whose evidence is gone", () => {
    const { left, right, mind } = twoBranches();
    const made = witness([left.events, right.events]);
    const lost = contentId(left.events[1]);
    let asked = 0;
    // The evidence for one event is there while the branch is verified, and gone when the branches are compared.
    const fading: EvidenceView = {
      proofSeen: () => undefined,
      eventSeen: (id) => (id === lost && asked++ > 0 ? undefined : made.eventSeen(id)),
    };
    const book = new LogBook(fading);
    book.holdBranch(left.events, LATER);
    book.holdBranch(right.events, LATER);
    const { log, heads: found } = heads(book, mind);
    expect(log.duplicitous).toBe(false);
    expect(found[1]).toBe(contentId(right.events[1]));
    expect(latestState(log).homes).toEqual(["https://ada.example"]);
    // With no evidence for either, nothing separates them.
    const none: EvidenceView = {
      proofSeen: () => undefined,
      eventSeen: (id) =>
        [lost, contentId(right.events[1])].includes(id) && asked++ > 3
          ? undefined
          : made.eventSeen(id),
    };
    asked = 0;
    const dark = new LogBook(none);
    dark.holdBranch(left.events, LATER);
    dark.holdBranch(right.events, LATER);
    expect(heads(dark, mind).log.duplicitous).toBe(true);
  });
});

describe(`${clause("L1 7.3")} a branch that this verifier cannot read to its end`, () => {
  // The honest branch removes key 0 at position 1, and was seen first. The other keeps the key.
  function scene() {
    const honest = new KeyMind("ada").update(20, { keys: [] });
    const other = new KeyMind("ada").update(20, { homes: ["https://ada.example"] });
    const seenAt = new Map<object, number>([
      [honest.events[1] as object, 20],
      [other.events[1] as object, 40],
    ]);
    return { honest, other, seenAt, mind: honest.address };
  }

  it("still takes part with the events it has that verify, so the other does not win by default", () => {
    const { honest, other, seenAt, mind } = scene();
    const junk = new KeyMind("ada").update(20, { keys: [] }).raw(30, "Merge");
    const { book } = bookOf([junk.events, other.events], seenAt);
    // The honest event was seen first. What follows it does not verify, so the log's end is not known.
    expect(book.log(mind)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 3.9", path: "/2/type" }],
    });
    // A record pinned to the other branch's event counts for nothing.
    const pinned = other.sign(intentBy(other, 50));
    const judged = judgeRecord(pinned);
    expect(judged.ok && ownSignedTime(judged.value, mind, book)).toBeUndefined();
    // Held as far as it verifies, the honest branch is the log.
    expect(book.drop(mind)).toBe(true);
    book.holdBranch(honest.events, LATER);
    book.holdBranch(other.events, LATER);
    expect(heads(book, mind).heads[1]).toBe(contentId(honest.events[1]));
    // The order in which the branches are held changes nothing.
    const { book: reversed } = bookOf([other.events, junk.events], seenAt);
    expect(reversed.log(mind)).toMatchObject({ ok: false, issues: [{ clause: "L1 3.9" }] });
  });

  it("is no obstacle where it lost: what follows a losing event does not matter", () => {
    const { honest, seenAt, mind } = scene();
    const lostAndBroken = new KeyMind("ada")
      .update(20, { homes: ["https://ada.example"] })
      .raw(30, "Merge");
    seenAt.set(lostAndBroken.events[1] as object, 40);
    const { book } = bookOf([honest.events, lostAndBroken.events], seenAt);
    expect(heads(book, mind).heads).toStrictEqual(honest.events.map((event) => contentId(event)));
  });

  it("is not passed over for being longer than this verifier reads", { timeout: 120_000 }, () => {
    const { other, mind } = scene();
    const long = unchecked(() => {
      const ada = new KeyMind("ada").update(20, { keys: [] });
      for (let n = 1; n < 1000; n++) ada.update(20 + n);
      return ada;
    });
    expect(long.events).toHaveLength(1001);
    const evidence = witness([long.events, other.events]);
    evidence.sawEvent(contentId(other.events[1]), at(40));
    const book = new LogBook(
      {
        proofSeen: (digest) => evidence.proofSeen(digest),
        // The other branch's event was seen later than the long branch's.
        eventSeen: (id) => (id === contentId(other.events[1]) ? at(40) : evidence.eventSeen(id)),
      },
      { maxEvents: 1000 },
    );
    book.holdBranch(long.events, LATER);
    book.holdBranch(other.events, LATER);
    expect(book.log(mind)).toMatchObject({
      ok: false,
      issues: [{ clause: "implementation limit", path: "" }],
    });
    // Alone, the other branch is a log like any other.
    book.drop(mind);
    book.holdBranch(other.events, LATER);
    expect(book.log(mind).ok).toBe(true);
  });

  it("makes a duplicitous mind's log one that is not known, if a tied branch ends in an event that does not verify", () => {
    const left = new KeyMind("ada").update(20, { keys: [] }).raw(30, "Merge");
    const right = new KeyMind("ada").update(20, { homes: ["https://ada.example"] });
    const { book } = bookOf([left.events, right.events]);
    // Every branch's removals apply to a duplicitous mind, and here one branch's are not all known.
    expect(book.log(left.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 3.9" }] });
  });
});

describe(`${clause("L1 7.3")} three events at one position`, () => {
  it("gives the position to the earliest, whatever ties there are among the later ones", () => {
    const branch = (home: string) => new KeyMind("ada").update(20, { homes: [home] });
    const [first, second, third] = ["one", "two", "three"].map((name) =>
      branch(`https://${name}.example`),
    ) as [KeyMind, KeyMind, KeyMind];
    for (const order of [
      [first, second, third],
      [second, third, first],
      [third, first, second],
    ]) {
      const seenAt = new Map<object, number>([
        [first.events[1] as object, 25],
        [second.events[1] as object, 30],
        [third.events[1] as object, 30],
      ]);
      const { log, heads: found } = heads(
        bookOf(
          order.map((mind) => mind.events),
          seenAt,
        ).book,
        first.address,
      );
      expect(log.duplicitous).toBe(false);
      expect(found[1]).toBe(contentId(first.events[1]));
    }
    // A tie for the earliest is duplicity, whatever came later.
    const tied = new Map<object, number>([
      [first.events[1] as object, 25],
      [second.events[1] as object, 25],
      [third.events[1] as object, 30],
    ]);
    const { log } = heads(
      bookOf([third.events, first.events, second.events], tied).book,
      first.address,
    );
    expect(log.duplicitous).toBe(true);
    expect(log.branchTails).toHaveLength(3);
  });
});

describe("what a book keeps, and for how long", () => {
  /** Evidence that counts how often each event's time is asked for: once for each time its log is verified. */
  function counting(logs: readonly Events[]) {
    const made = witness(logs);
    const asked = new Map<string, number>();
    const evidence: EvidenceView = {
      proofSeen: (digest) => made.proofSeen(digest),
      eventSeen: (id) => {
        asked.set(id, (asked.get(id) ?? 0) + 1);
        return made.eventSeen(id);
      },
    };
    const verifications = (mind: { events: Events }) => asked.get(contentId(mind.events[0])) ?? 0;
    return { evidence, made, verifications };
  }

  it("keeps a verdict until a log it rests on changes, and then forgets no more than rests on that", () => {
    const [a, b, other] = [new KeyMind("a"), new KeyMind("b"), new KeyMind("other")];
    const club = new Collective("club", [a, b], 2);
    const longer = new KeyMind("a").update(10);
    const { evidence, verifications } = counting([
      a.events,
      b.events,
      other.events,
      club.events,
      longer.events,
    ]);
    const book = new LogBook(evidence);
    for (const mind of [a, b, club]) book.hold(mind.events, LATER);
    const first = book.log(club.address);
    expect(first.ok).toBe(true);
    expect([club, a, b].map(verifications)).toStrictEqual([1, 1, 1]);
    // A log nothing rests on is held: every verdict stands.
    book.hold(other.events, LATER);
    expect(book.log(club.address)).toBe(first);
    expect(book.log(a.address).ok).toBe(true);
    expect([club, a, b].map(verifications)).toStrictEqual([1, 1, 1]);
    // A member's log changes: its verdict and the collective's are made again, and the other member's stands.
    book.hold(longer.events, LATER);
    const second = book.log(club.address);
    expect(second.ok).toBe(true);
    expect(second).not.toBe(first);
    expect([club, a, b].map(verifications)).toStrictEqual([2, 2, 1]);
    // A member's log is dropped: the collective no longer verifies.
    expect(book.drop(b.address)).toBe(true);
    expect(book.log(club.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 6.3" }] });
    // Held again, it does: a verdict that failed for want of a log is forgotten when the log comes.
    book.hold(b.events, LATER);
    expect(book.log(club.address).ok).toBe(true);
  });

  it("verifies a log that fails once, however many collectives ask for it", () => {
    const bad = new KeyMind("bad").raw(10, "Merge");
    const clubs = ["one", "two", "three"].map((name) => new Collective(name, [bad], 1));
    const { evidence, verifications } = counting([bad.events, ...clubs.map((club) => club.events)]);
    const book = new LogBook(evidence);
    for (const mind of [bad, ...clubs]) book.hold(mind.events, LATER);
    for (const club of clubs) {
      expect(book.log(club.address)).toMatchObject({
        ok: false,
        issues: [{ clause: "L1 3.9", path: "/0/proof/0" }],
      });
    }
    expect(verifications(bad)).toBe(1);
    expect(clubs.map(verifications)).toStrictEqual([1, 1, 1]);
    expect(book.log(bad.address).ok).toBe(false);
    expect(verifications(bad)).toBe(1);
  });

  it("does one verification for each log, however many proofs name a member whose log fails", () => {
    // Four collectives, each the one member of the next, over a log that does
    // not verify. Each genesis carries eight proofs by its member. Judging
    // every proof against a log that fails cost 4,681 verifications here.
    const bad = new KeyMind("bad").raw(10, "Merge");
    const levels: (KeyMind | Collective)[] = [bad];
    for (let n = 1; n <= 4; n++) {
      const member = levels[n - 1]!;
      const level = new Collective(`level ${n}`, [member], 1, n);
      level.events[0] = rawSign(
        level.events[0]!,
        Array.from({ length: 8 }, () => member.asMember()),
      );
      levels.push(level);
    }
    const made = witness(levels.map((mind) => mind.events));
    let verified = 0;
    const book = new LogBook({
      proofSeen: (digest) => made.proofSeen(digest),
      eventSeen: (id) => {
        verified++;
        return made.eventSeen(id);
      },
    });
    for (const mind of levels) book.hold(mind.events, LATER);
    const top = levels[4]!;
    expect(book.log(top.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 3.9" }] });
    // One event of each of the five logs was reached, once.
    expect(verified).toBe(5);
    expect(book.log(top.address).ok).toBe(false);
    expect(verified).toBe(5);
  });

  it(`${clause("L1 4.7")} does not keep a failure that came from where a log was asked from`, () => {
    // Five collectives, each the one member of the next. Four is as deep as they nest.
    const key = new KeyMind("key");
    const levels: (KeyMind | Collective)[] = [key];
    for (let n = 1; n <= 5; n++) {
      levels.push(new Collective(`level ${n}`, [levels[n - 1]!], 1, n));
    }
    const book = bookOfMinds(levels);
    const fifth = levels[5]!;
    expect(book.log(fifth.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 4.7" }] });
    // Under the fifth, each log below was too deep. Asked for itself, each verifies.
    for (const inner of levels.slice(0, 5).reverse()) {
      expect(book.log(inner.address).ok, inner.name).toBe(true);
    }
    expect(book.log(fifth.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 4.7" }] });
    // And in the other order.
    const again = bookOfMinds(levels);
    for (const inner of levels.slice(0, 5)) expect(again.log(inner.address).ok).toBe(true);
    expect(again.log(fifth.address).ok).toBe(false);
  });

  it("holds its own copy of a log: what its giver does to the log afterwards changes nothing", () => {
    const ada = new KeyMind("ada").update(10);
    const given = copy(ada.events) as unknown as JsonObject[];
    const book = new LogBook(witness([ada.events]));
    expect(book.hold(given, LATER)).toStrictEqual({ ok: true, value: ada.address });
    (given[1] as { created: string }).created = T(99);
    given.push({ junk: true });
    expect(heads(book, ada.address).heads).toHaveLength(2);
    // Even when the log is verified anew.
    book.forget();
    const { log } = heads(book, ada.address);
    expect(log.entries.map((entry) => entry.event.created)).toStrictEqual([T(0), T(10)]);
  });

  it("takes a mind's address from the copy it verifies, never from a second reading", () => {
    const [ada, bea] = [new KeyMind("ada"), new KeyMind("bea")];
    // A value that reads as one genesis while it is being held, and as another afterwards.
    let now: object = ada.events[0]!;
    const shifting = new Proxy(
      {},
      {
        ownKeys: () => Reflect.ownKeys(now),
        getOwnPropertyDescriptor: (_, name) => Reflect.getOwnPropertyDescriptor(now, name),
        get: (_, name) => Reflect.get(now, name) as unknown,
        has: (_, name) => Reflect.has(now, name),
      },
    );
    const book = new LogBook(witness([ada.events, bea.events]));
    const held = book.hold([shifting], LATER);
    expect(held).toStrictEqual({ ok: true, value: ada.address });
    now = bea.events[0]!;
    const log = book.log(ada.address);
    expect(log.ok && log.value.mind).toBe(ada.address);
    expect(book.log(bea.address).ok).toBe(false);
  });

  it("keeps the times it was first given, until it is told to forget", () => {
    const ada = new KeyMind("ada").update(10);
    const [genesis, update] = ada.events.map((event) => contentId(event));
    const seen = new FirstSeen();
    seen.sawEvent(genesis!, at(50));
    seen.sawEvent(update!, at(50));
    const book = new LogBook(seen);
    book.hold(ada.events, LATER);
    const times = () => heads(book, ada.address).log.entries.map((entry) => entry.time);
    expect(times()).toStrictEqual([at(50), at(50)]);
    // A witness's earlier times arrive.
    seen.sawEvent(genesis!, at(1));
    seen.sawEvent(update!, at(11));
    expect(times()).toStrictEqual([at(50), at(50)]);
    book.forget();
    expect(times()).toStrictEqual([at(1), at(11)]);
  });

  it("answers and does not throw for what is no address, no log and no time", () => {
    const ada = new KeyMind("ada");
    const book = new LogBook(witness([ada.events]), null as never);
    for (const notAddress of [Symbol("mind"), 5, null, undefined, {}, ["did:oip:x"]]) {
      expect(book.log(notAddress as never)).toMatchObject({
        ok: false,
        issues: [{ clause: "L1 2.2" }],
      });
    }
    expect(book.drop(Symbol("mind") as never)).toBe(false);
    for (const notLog of [undefined, null, 5, "log", {}, [], [5], [[]], [{ n: 0.5 }]]) {
      expect(book.hold(notLog, LATER)).toMatchObject({ ok: false, issues: [{ clause: "L1 3.1" }] });
      expect(book.holdBranch(notLog, LATER).ok).toBe(false);
    }
    // Whatever has a content ID can be held. It is judged when it is asked for.
    const empty = book.hold([{}], LATER);
    expect(empty.ok && book.log(empty.value).ok).toBe(false);
    expect(book.hold(ada.events, LATER).ok).toBe(true);
    expect(book.log(ada.address).ok).toBe(true);
  });

  it("gives out a duplicitous log frozen, like any other", () => {
    const { left, right, mind } = twoBranches();
    const { log } = heads(bookOf([left.events, right.events]).book, mind);
    expect(log.duplicitous).toBe(true);
    const frozen = (value: unknown): boolean =>
      typeof value !== "object" ||
      value === null ||
      (Object.isFrozen(value) && Object.values(value).every(frozen));
    expect(frozen(log)).toBe(true);
  });
});

describe("an answer that depends on where a log was asked from", () => {
  /** A collective whose genesis names a member, with a proof by a key that is not the member's. */
  function hollow(name: string, member: { address: string; versionId(): string }, seconds: number) {
    const event = rawSign(
      draftGenesis(T(seconds), {
        kind: "collective",
        controller: { members: [member.address], threshold: 1 },
      }),
      [
        {
          member: member.address,
          versionId: member.versionId(),
          invocation: signer(`${name}/key`),
        },
      ],
    );
    return {
      events: [event],
      address: `did:oip:${contentId(event)}`,
      versionId: () => `0-${contentId(event)}`,
    };
  }

  it("is not kept, even when it is a log that verified", () => {
    const [a, b, n1] = [new KeyMind("a"), new KeyMind("b"), new KeyMind("n1")];
    const n = new Collective("n", [n1], 1, 1);
    const x = () => new Collective("x", [a, b], 2, 2, { height: 2 });
    // Two events for position 1 of x. The one seen first admits the collective n.
    const first = x().update(20, [a, b, n], {
      controller: { members: [a.address, b.address, n.address], threshold: 2 },
    });
    const second = x().update(20, [a, b], { homes: ["https://later.example"] });
    // Three logs that do not verify, each naming the next as its member, and the last naming x.
    const c2 = hollow("c2", second, 50);
    const c1 = hollow("c1", c2, 51);
    const top = hollow("top", c1, 52);
    const made = witness([
      ...[a, b, n1, n, first, second].map((mind) => mind.events),
      ...[c2, c1, top].map((fake) => fake.events as never),
    ]);
    const evidence: EvidenceView = {
      proofSeen: (digest) => made.proofSeen(digest),
      eventSeen: (id) => (id === contentId(second.events[1]) ? at(40) : made.eventSeen(id)),
    };
    const filled = () => {
      const book = new LogBook(evidence);
      for (const mind of [a, b, n1, n]) book.hold(mind.events, LATER);
      book.holdBranch(second.events, LATER);
      book.holdBranch(first.events, LATER);
      for (const fake of [c2, c1, top]) book.hold(fake.events, LATER);
      return book;
    };
    const asked = filled();
    // Under `top`, x is three levels down, and the collective its first event
    // admits would be a fifth: refused for the depth. Down there x looks like
    // its other branch.
    expect(asked.log(top.address).ok).toBe(false);
    // Asked for itself, x is the branch that was seen first, as in a book nobody asked before.
    const fresh = filled();
    for (const book of [asked, fresh]) {
      const { log, heads: found } = heads(book, first.address);
      expect(log.duplicitous).toBe(false);
      expect(found[1]).toBe(contentId(first.events[1]));
    }
  });

  it("is worked out once for each path, however many copies of each log are held", () => {
    // Five collectives, each the one member of the next: one too many. Each is
    // held in several copies, which differ in something that follows the genesis
    // and is no event. Judging every copy against every copy below it cost
    // 9,330 lookups for six copies of each.
    const key = new KeyMind("key");
    const levels: (KeyMind | Collective)[] = [key];
    for (let n = 1; n <= 5; n++) levels.push(new Collective(`level ${n}`, [levels[n - 1]!], 1, n));
    const made = witness(levels.map((mind) => mind.events));
    const lookups = (copies: number): number => {
      let asked = 0;
      const book = new LogBook({
        proofSeen: (digest) => made.proofSeen(digest),
        eventSeen: (id) => {
          asked++;
          return made.eventSeen(id);
        },
      });
      book.hold(key.events, LATER);
      for (const level of levels.slice(1)) {
        for (let j = 0; j < copies; j++) book.holdBranch([...level.events, { junk: j }], LATER);
      }
      expect(book.log(levels[5]!.address).ok).toBe(false);
      return asked;
    };
    const [two, six] = [lookups(2), lookups(6)];
    // The work grows with the number of copies, and not with a power of it.
    expect(two).toBeLessThanOrEqual(5 * 2 + 1);
    expect(six).toBeLessThanOrEqual(5 * 6 + 1);
  });
});

describe("a copy that does not verify, and the copy that takes its place", () => {
  const clean = () => new KeyMind("ada").update(10).update(20, { keys: [] });

  it("gives way to a clean copy of the same log, when a junk event follows what verifies", () => {
    const ada = clean();
    const junked = [...ada.events, { junk: true }];
    const book = new LogBook(witness([ada.events]));
    book.hold(junked, LATER);
    expect(book.log(ada.address).ok).toBe(false);
    // The clean log is no earlier state of it: both verify as far as each other.
    expect(book.hold(ada.events, LATER)).toStrictEqual({ ok: true, value: ada.address });
    expect(heads(book, ada.address).heads).toHaveLength(3);
    // But the genesis alone is: the copy held verifies further, junk and all.
    const again = new LogBook(witness([ada.events]));
    again.hold(junked, LATER);
    expect(again.hold(ada.events.slice(0, 1), LATER)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 4.9" }],
    });
  });

  it("does not take the place of a clean copy when it is the same events with their proofs lost", () => {
    const ada = clean();
    const stripped = ada.events.map((event, i) =>
      i === 0 ? event : { ...event, proof: [{ ...event.proof[0], proofValue: "z1111" }] },
    );
    expect(stripped.map((event) => contentId(event))).toStrictEqual(
      ada.events.map((event) => contentId(event)),
    );
    for (const how of ["hold", "holdBranch"] as const) {
      const book = new LogBook(witness([ada.events]));
      book.hold(ada.events, LATER);
      const taken = book[how](stripped, LATER);
      // As a log in its place it is refused; as a branch it adds nothing.
      expect(taken.ok).toBe(how === "holdBranch");
      expect(heads(book, ada.address).heads).toHaveLength(3);
    }
    // And a clean copy takes the place of one that lost its proofs.
    const book = new LogBook(witness([ada.events]));
    book.hold(stripped, LATER);
    expect(book.log(ada.address).ok).toBe(false);
    expect(book.holdBranch(ada.events, LATER).ok).toBe(true);
    expect(heads(book, ada.address).heads).toHaveLength(3);
  });

  it("keeps nothing of an event that was not plain data when it was held", () => {
    const ada = clean();
    const odd: Record<string, unknown> = { ...ada.events[2], extra: undefined };
    const given = [ada.events[0], ada.events[1], odd];
    const book = new LogBook(witness([ada.events]));
    book.hold(given, LATER);
    expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ path: "/2" }] });
    // The giver mends its copy afterwards. The book's copy is not the giver's.
    delete odd["extra"];
    book.forget();
    expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ path: "/2" }] });
  });
});

describe("what a book answers with", () => {
  it("is frozen, a rejection as much as a log, and the same answer each time", () => {
    const ada = new KeyMind("ada");
    const bad = new KeyMind("bad").raw(10, "Merge");
    const book = new LogBook(witness([ada.events, bad.events]));
    book.hold(ada.events, LATER);
    book.hold(bad.events, LATER);
    const frozen = (value: unknown): boolean =>
      typeof value !== "object" ||
      value === null ||
      (Object.isFrozen(value) && Object.values(value).every(frozen));
    for (const mind of [ada, bad]) {
      const answer = book.log(mind.address);
      expect(book.log(mind.address)).toBe(answer);
      expect(frozen(answer)).toBe(true);
    }
    // A rejection cannot be turned into another mind's log by whoever was given it.
    const refused = book.log(bad.address) as { ok: boolean; value?: unknown };
    const taken = book.log(ada.address);
    expect(() => {
      refused.ok = true;
    }).toThrow(TypeError);
    expect(() => {
      refused.value = taken.ok ? taken.value : undefined;
    }).toThrow(TypeError);
    expect(book.log(bad.address).ok).toBe(false);
  });

  it("reads its options as the caller's own members, and nothing from one that cannot be read", () => {
    const ada = new KeyMind("ada");
    const unreadable = new Proxy(
      {},
      {
        getOwnPropertyDescriptor() {
          throw new Error("boom");
        },
      },
    );
    const book = new LogBook(witness([ada.events]), unreadable);
    book.hold(ada.events, LATER);
    expect(book.log(ada.address).ok).toBe(true);
  });
});
