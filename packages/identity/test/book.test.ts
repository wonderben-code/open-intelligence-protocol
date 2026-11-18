// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, proofDigest } from "@oip/core";
import type { Proof } from "@oip/schema";
import { clause, copy, type JsonObject } from "@oip/testkit";
import fc from "fast-check";
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
  witnessLog,
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
  for (const events of branches) book.hold(events, LATER);
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
      book.hold(left.events, LATER);
      book.hold(right.events, LATER);
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
  it("answers for a mind it holds no log of, and for one whose log it cannot judge", () => {
    const ada = new KeyMind("ada");
    const book = new LogBook(witness([ada.events]));
    expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 6.3" }] });
    expect(book.hold(ada.events, LATER)).toEqual({ ok: true, value: ada.address });
    expect(book.log(ada.address).ok).toBe(true);
    const unread = new KeyMind("bea").raw(10, "Merge");
    const blind = new LogBook(witness([unread.events]));
    blind.hold(unread.events, LATER);
    expect(blind.log(unread.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 3.9" }] });
    // Asked again, the answer is the same one.
    expect(blind.log(unread.address)).toBe(blind.log(unread.address));
    // An invalid event is no event: the log is the events before it (Layer 1, 4.9).
    const broken = new KeyMind("cy").raw(10, "Update", { seq: 9 });
    const partial = new LogBook(witness([broken.events]));
    partial.hold(broken.events, LATER);
    expect(heads(partial, broken.address).heads).toHaveLength(1);
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

  it(`${clause("L1 4.9")} loses nothing to an earlier state of a log it holds`, () => {
    // A source that lags, or lies, must not undo a removal the verifier knows of.
    const ada = new KeyMind("ada");
    const genesis = [...ada.events];
    ada.update(10).update(20, { keys: [] });
    const middle = ada.events.slice(0, 2);
    const book = new LogBook(witness([ada.events]));
    book.hold(ada.events, at(50));
    for (const earlier of [genesis, middle]) {
      expect(book.hold(earlier, at(90))).toStrictEqual({ ok: true, value: ada.address });
      expect(heads(book, ada.address).heads).toHaveLength(3);
      // The time the log is known up to is not moved by a copy that ends before the log does.
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
    book.hold(left.events, LATER);
    book.hold(right.events, LATER);
    expect(heads(book, mind).log.branchTails).toHaveLength(2);
    book.hold(longer.events, LATER);
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
      book.hold(left.events, at(first));
      book.hold(right.events, at(second));
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
      book.hold(left.events, at(leftAsOf));
      book.hold(right.events, at(rightAsOf));
      const { log, heads: found } = heads(book, mind);
      // The branch seen first is the log, and what is known of the other says nothing about it.
      expect(found[1]).toBe(contentId(left.events[1]));
      expect(log.asOf).toBe(at(leftAsOf));
    }
  });

  it("gives the reason of the first event it holds at a position that it cannot judge", () => {
    const one = new KeyMind("ada").raw(10, "Merge");
    const two = new KeyMind("ada").raw(10, "Rename");
    const invalid = new KeyMind("ada").raw(10, "Update", { seq: 9 });
    const book = new LogBook(witness([one.events, two.events, invalid.events]));
    // An invalid event is no event: the log is its genesis.
    book.hold(invalid.events, LATER);
    expect(heads(book, one.address).heads).toHaveLength(1);
    book.hold(one.events, LATER);
    expect(book.log(one.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 3.9" }] });
    // Two events at one position that cannot be judged: either stops the log.
    book.hold(two.events, LATER);
    expect(book.log(one.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 3.9" }] });
  });

  it("does not let a branch win whose evidence is gone", () => {
    const { left, right, mind } = twoBranches();
    const made = witness([left.events, right.events]);
    const lost = contentId(left.events[1]);
    let asked = 0;
    // The evidence for one event is there while the event is verified, and gone when the
    // two are compared.
    const fading: EvidenceView = {
      proofSeen: () => undefined,
      eventSeen: (id) => (id === lost && asked++ > 0 ? undefined : made.eventSeen(id)),
    };
    const book = new LogBook(fading);
    book.hold(left.events, LATER);
    book.hold(right.events, LATER);
    const { log, heads: found } = heads(book, mind);
    expect(log.duplicitous).toBe(false);
    expect(found[1]).toBe(contentId(right.events[1]));
    expect(latestState(log).homes).toEqual(["https://ada.example"]);
    // With no evidence for either, nothing separates them.
    const none: EvidenceView = {
      proofSeen: () => undefined,
      eventSeen: (id) =>
        [lost, contentId(right.events[1])].includes(id) && asked++ > 1
          ? undefined
          : made.eventSeen(id),
    };
    asked = 0;
    const dark = new LogBook(none);
    dark.hold(left.events, LATER);
    dark.hold(right.events, LATER);
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
    book.hold(honest.events, LATER);
    book.hold(other.events, LATER);
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
    book.hold(long.events, LATER);
    book.hold(other.events, LATER);
    expect(book.log(mind)).toMatchObject({
      ok: false,
      issues: [{ clause: "implementation limit", path: "" }],
    });
    // Alone, the other branch is a log like any other.
    book.drop(mind);
    book.hold(other.events, LATER);
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
      expect(book.hold(notLog, LATER).ok).toBe(false);
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
      book.hold(second.events, LATER);
      book.hold(first.events, LATER);
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

  it("costs no more for copies that show nothing more: they are one copy", () => {
    // Five collectives, each the one member of the next: one too many. Each is
    // given in several copies, which differ in something that follows the genesis
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
        for (let j = 0; j < copies; j++) book.hold([...level.events, { junk: j }], LATER);
      }
      asked = 0;
      expect(book.log(levels[5]!.address).ok).toBe(false);
      return asked;
    };
    // One copy is verified when it is asked for; several were weighed as they came, and
    // the answer was kept.
    expect(lookups(1)).toBeLessThanOrEqual(5);
    expect(lookups(6)).toBeLessThanOrEqual(lookups(1));
  });

  it("is not kept when a log below was refused for being a mind already under verification", () => {
    // x is founded by m, and m admits y. y has a second copy that lost its position and goes on
    // with an event that asks for x: beneath y, m is then refused, and x with it.
    const k = new KeyMind("k");
    const y = new Collective("y", [k], 1, 5);
    const m = new Collective("m", [k], 1, 5, { height: 2 }).update(20, [k, y], {
      controller: { members: [k.address, y.address], threshold: 2 },
    });
    const x = new Collective("x", [m], 1, 30, { height: 3 });
    const won = rawSign(draftUpdate(y.head, T(40)), [k.asMember()]);
    const lost = rawSign(draftUpdate(y.head, T(40), { homes: ["https://y.example"] }), [
      k.asMember(),
    ]);
    const asks = rawSign(
      draftUpdate({ mind: y.address, seq: 1, head: contentId(lost) }, T(50), {
        controller: { members: [k.address, x.address], threshold: 2 },
      }),
      [k.asMember(), { member: x.address, versionId: x.versionId(0), invocation: signer("x") }],
    );
    const copies = [
      [y.events[0], won],
      [y.events[0], lost, asks],
    ];
    const filled = () => {
      const evidence = witness([k.events, m.events, x.events, ...copies] as never);
      evidence.sawEvent(contentId(won), at(39));
      const book = new LogBook(evidence);
      for (const mind of [k, m, x]) book.hold(mind.events, LATER);
      for (const events of copies) book.hold(events, LATER);
      return book;
    };
    // Asked for by itself, x verifies.
    expect(filled().log(x.address).ok).toBe(true);
    // Asked for after y, it is the same log: what was refused beneath y was not x's own answer.
    const asked = filled();
    expect(heads(asked, y.address).heads[1]).toBe(contentId(won));
    expect(asked.log(x.address).ok).toBe(true);
  });

  it(`${clause("L1 4.7")} verifies each log once, whatever is held after an event that lost its position`, () => {
    // Three levels of collectives under a top one, each level a member of every collective
    // above it. Every collective of the lowest level has a second event for its first
    // position, which lost it, and after that one an event that asks for the top mind's
    // log. Judged beneath the top, that event is refused, and an answer that rested on the
    // refusal could be kept nowhere: it was worked out again along every path, the cube of
    // the fan-out. What follows an event that lost is not judged at all.
    const set = (fan: number, hostile: boolean) =>
      unchecked(() => {
        const k = new KeyMind("k");
        const most = Math.floor(fan / 2) + 1;
        const several = <T>(make: (n: number) => T) =>
          Array.from({ length: fan }, (_, n) => make(n));
        const lowest = several((n) => new Collective(`p${n}`, [k], 1, 5));
        const middle = several((n) => new Collective(`c${n}`, lowest, most, 6));
        const upper = several((n) => new Collective(`b${n}`, middle, most, 7));
        const top = new Collective("top", upper, most, 8);
        const logs: (readonly unknown[])[] = [k, top, ...upper, ...middle].map(
          (mind) => mind.events,
        );
        const seen = new FirstSeen();
        for (const p of lowest) {
          const won = rawSign(draftUpdate(p.head, T(20)), [k.asMember()]);
          const lost = rawSign(draftUpdate(p.head, T(20), { homes: ["https://p.example"] }), [
            k.asMember(),
          ]);
          const after = rawSign(
            draftUpdate({ mind: p.address, seq: 1, head: contentId(lost) }, T(30), {
              controller: { members: [k.address, top.address], threshold: 2 },
            }),
            [
              k.asMember(),
              { member: top.address, versionId: top.versionId(), invocation: signer("x") },
            ],
          );
          logs.push([p.events[0], won]);
          if (hostile) logs.push([p.events[0], lost, after]);
          seen.sawEvent(contentId(won), at(20));
          seen.sawEvent(contentId(lost), at(21));
          seen.sawEvent(contentId(after), at(30));
        }
        return { top, logs, seen };
      });
    const question = (fan: number, hostile: boolean) => {
      const { top, logs, seen } = set(fan, hostile);
      const made = witness(logs as never);
      let asked = 0;
      const book = new LogBook({
        proofSeen: () => undefined,
        eventSeen: (id) => {
          asked++;
          return seen.eventSeen(id) ?? made.eventSeen(id);
        },
      });
      for (const log of logs) book.hold(log, LATER);
      asked = 0;
      const answer = book.log(top.address);
      return { ok: answer.ok, asked };
    };
    for (const fan of [4, 6]) {
      const sound = question(fan, false);
      const hostile = question(fan, true);
      expect(sound.ok).toBe(true);
      expect(hostile.ok).toBe(true);
      // Each of the lowest collectives has one more event to judge, and one more to compare.
      expect(hostile.asked).toBeLessThanOrEqual(sound.asked + 3 * fan);
    }
  });
});

describe(`${clause("L1 4.9")} an event held that is invalid`, () => {
  const clean = () => new KeyMind("ada").update(10).update(20, { keys: [] });

  it("is no event: the log is the events before it, whichever copy came first", () => {
    const ada = clean();
    const junked = [...ada.events, { junk: true }];
    for (const order of [[junked, ada.events], [ada.events, junked], [junked]]) {
      const book = new LogBook(witness([ada.events]));
      for (const events of order) {
        expect(book.hold(events, LATER)).toStrictEqual({ ok: true, value: ada.address });
        expect(heads(book, ada.address).heads).toHaveLength(3);
      }
      // An earlier state of the log takes nothing away.
      book.hold(ada.events.slice(0, 1), LATER);
      expect(heads(book, ada.address).heads).toHaveLength(3);
    }
  });

  it("is an event again when its proofs arrive: every proof of an event is held, from whichever copy", () => {
    const ada = clean();
    const stripped = ada.events.map((event, i) =>
      i === 0 ? event : { ...event, proof: [{ ...event.proof[0], proofValue: "z1111" }] },
    );
    expect(stripped.map((event) => contentId(event))).toStrictEqual(
      ada.events.map((event) => contentId(event)),
    );
    // The same events with their proofs lost: nothing after the genesis is signed.
    const book = new LogBook(witness([ada.events]));
    book.hold(stripped, LATER);
    expect(heads(book, ada.address).heads).toHaveLength(1);
    // The log itself brings the proofs, to the events already held.
    book.hold(ada.events, LATER);
    expect(heads(book, ada.address).heads).toHaveLength(3);
    // The other way round, the copy without them takes nothing away.
    const sound = new LogBook(witness([ada.events]));
    sound.hold(ada.events, LATER);
    sound.hold(stripped, LATER);
    expect(heads(sound, ada.address).heads).toHaveLength(3);
  });

  it(`${clause("L1 7.1")} judges an event with the proofs of every copy of it`, () => {
    // A collective of two, threshold two. Each copy of its second event has one member's proof.
    const [a, b] = [new KeyMind("a"), new KeyMind("b")];
    const club = new Collective("club", [a, b], 2, 5);
    const change = draftUpdate(club.head, T(10), { homes: ["https://club.example"] });
    const half = (member: KeyMind) => [...club.events, rawSign(change, [member.asMember()])];
    const made = witness([a.events, b.events, club.events]);
    made.sawEvent(contentId(change), at(10));
    const filled = (...copies: unknown[][]) => {
      const book = new LogBook(made);
      for (const mind of [a, b]) book.hold(mind.events, LATER);
      for (const events of copies) book.hold(events, LATER);
      return heads(book, club.address).heads.length;
    };
    expect(filled(half(a))).toBe(1);
    expect(filled(half(b))).toBe(1);
    expect(filled(half(a), half(b))).toBe(2);
    expect(filled(half(b), half(a))).toBe(2);
  });

  it("keeps nothing of a value that was not plain data when it was held", () => {
    const ada = clean();
    const odd: Record<string, unknown> = { ...ada.events[2], extra: undefined };
    const given = [ada.events[0], ada.events[1], odd];
    const book = new LogBook(witness([ada.events]));
    book.hold(given, LATER);
    expect(heads(book, ada.address).heads).toHaveLength(2);
    // The giver mends its copy afterwards. The book's copy is not the giver's.
    delete odd["extra"];
    book.forget();
    expect(heads(book, ada.address).heads).toHaveLength(2);
  });
});

describe(`${clause("L1 7.1")} a copy of an event that is not well formed`, () => {
  // ada removes her operational key at 20. A record signed with it at 25 counts
  // if, and only if, that event is passed over.
  const ada = new KeyMind("ada").update(10).update(20, { keys: [] });
  const [genesis, update, removal] = ada.events as unknown as [JsonObject, JsonObject, JsonObject];
  const good = (removal["proof"] as JsonObject[])[0]!;
  const late = judgeRecord(ada.sign(intentBy(ada, 25), { position: 1 }));
  if (!late.ok) throw new Error("the record is well formed");
  const evidence = () => {
    const seen = witness([ada.events]);
    for (const proof of late.value.proofs) seen.sawProof(proof.digest, at(26));
    return seen;
  };
  const removedKeyCounts = (book: LogBook) =>
    ownSignedTime(late.value, ada.address, book) !== undefined;
  const withProof = (event: JsonObject, proof: unknown): Record<string, unknown> => ({
    ...event,
    proof,
  });
  const bare = (event: JsonObject) =>
    Object.fromEntries(Object.entries(event).filter(([name]) => name !== "proof"));

  /** What a `proof` that core 5.1 or core 1.6 does not allow looks like. */
  const spoiled: readonly (readonly [string, (event: JsonObject) => unknown])[] = [
    ["an entry that is a string, beside its proof", (e) => withProof(e, [...proofsOn(e), "junk"])],
    ["an entry that is a number, before its proof", (e) => withProof(e, [7, ...proofsOn(e)])],
    ["an entry that is null, beside its proof", (e) => withProof(e, [...proofsOn(e), null])],
    ["an entry that is a list, beside its proof", (e) => withProof(e, [...proofsOn(e), []])],
    ["one entry, a string", (e) => withProof(e, ["junk"])],
    ["no entry", (e) => withProof(e, [])],
    ["a `proof` that is its proof and no list", (e) => withProof(e, proofsOn(e)[0])],
    ["no `proof`", bare],
    [
      "257 entries, its proof among them",
      (e) =>
        withProof(e, [
          ...proofsOn(e),
          ...Array.from({ length: 256 }, (_, n) => ({ ...proofsOn(e)[0], n })),
        ]),
    ],
    [
      "an entry that makes it larger than a record may be, beside its proof",
      (e) => withProof(e, [...proofsOn(e), { ...proofsOn(e)[0], pad: "x".repeat(2 ** 20) }]),
    ],
  ];
  function proofsOn(event: JsonObject): JsonObject[] {
    return event["proof"] as JsonObject[];
  }

  it.each(spoiled)(
    "takes no proof away from the event, and adds none: %s",
    (_, spoil) => {
      const copy = [genesis, update, spoil(removal)];
      expect(contentId(copy[2] as object)).toBe(contentId(removal));
      // Anyone can make such a copy of any event. Held beside the log, in either order, it changes nothing.
      for (const copies of [
        [ada.events, copy],
        [copy, ada.events],
      ]) {
        const book = new LogBook(evidence());
        for (const events of copies) {
          expect(book.hold(events, LATER)).toStrictEqual({ ok: true, value: ada.address });
        }
        expect(heads(book, ada.address).heads).toHaveLength(3);
        expect(removedKeyCounts(book)).toBe(false);
      }
      // Alone, it is the event with no proof: invalid, as `witnessLog` says of the copy.
      const alone = new LogBook(evidence());
      alone.hold(copy, LATER);
      expect(heads(alone, ada.address).heads).toHaveLength(2);
      expect(witnessLog(copy, LATER, evidence())).toMatchObject({ undecided: false });
      expect(witnessLog(copy, LATER, evidence()).log?.entries).toHaveLength(2);
    },
    60_000,
  );

  it.each(spoiled)(
    "keeps its place, so what follows it in its copy is held: %s",
    (_, spoil) => {
      // A later copy of the log, with the removal, whose event before it is spoiled.
      const copy = [genesis, spoil(update), removal];
      const earlier = [genesis, update];
      for (const copies of [
        [earlier, copy],
        [copy, earlier],
      ]) {
        const book = new LogBook(evidence());
        for (const events of copies) book.hold(events, LATER);
        expect(heads(book, ada.address).heads).toHaveLength(3);
        expect(removedKeyCounts(book)).toBe(false);
      }
      // Alone, the copy shows nothing after its genesis.
      const alone = new LogBook(evidence());
      alone.hold(copy, LATER);
      expect(heads(alone, ada.address).heads).toHaveLength(1);
    },
    60_000,
  );

  it("is the genesis as much as any other event", () => {
    const copy = [withProof(genesis, [...proofsOn(genesis), "junk"]), update, removal];
    const book = new LogBook(evidence());
    expect(book.hold(copy, LATER)).toStrictEqual({ ok: true, value: ada.address });
    // No copy held shows the genesis with a proof, so nothing is known of the mind.
    expect(book.log(ada.address)).toMatchObject({ ok: false });
    book.hold([genesis], LATER);
    expect(heads(book, ada.address).heads).toHaveLength(3);
  });

  it("counts the proofs of an event wherever in a copy the event stands", () => {
    // One copy has the removal in its place, with a proof that does not verify. Another has
    // it out of place, with its proof. It is one event, and the proof is a proof of it.
    const unsigned = [genesis, update, withProof(removal, [{ ...good, proofValue: "z1111" }])];
    const misplaced = [genesis, removal];
    for (const copies of [
      [unsigned, misplaced],
      [misplaced, unsigned],
    ]) {
      const book = new LogBook(evidence());
      for (const events of copies) book.hold(events, LATER);
      expect(heads(book, ada.address).heads).toHaveLength(3);
    }
    const without = new LogBook(evidence());
    without.hold(unsigned, LATER);
    expect(heads(without, ada.address).heads).toHaveLength(2);
  });

  it(`${clause("L1 4.9")} does not judge by its proofs an event the verifier cannot read`, () => {
    // An event of a type this revision does not define may have other rules for `proof`,
    // and for its size. Whatever it calls itself, it is held, and stops the log.
    for (const [type, refused] of [
      ["Merge", "L1 3.9"],
      ["Bundle", "L1 4.6"],
      ["Sealed", "L1 4.6"],
      ["LogPage", "L1 4.6"],
    ] as const) {
      const unread = { ...bare(removal), type, proof: ["junk"] };
      const book = new LogBook(evidence());
      expect(book.hold([genesis, update, unread], LATER).ok).toBe(true);
      expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ clause: refused }] });
      // With well-formed proofs from two copies, it is still one event that cannot be read.
      for (const n of [1, 2]) {
        book.hold([genesis, update, { ...unread, proof: [{ ...good, n }] }], LATER);
      }
      expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ clause: refused }] });
    }
  });

  it("answers for a mind no longer, once it was shown more proofs for one event than one record carries", () => {
    const limit = { ok: false, issues: [{ clause: "implementation limit" }] };
    const copyWith = (proofs: unknown[]) => [genesis, update, withProof(removal, proofs)];
    // core 5.1: 256 proofs. Each copy is well formed; the proofs of all are one more.
    const numbered = (from: number, count: number) =>
      Array.from({ length: count }, (_, n) => ({ ...good, n: from + n }));
    const counted = new LogBook(evidence());
    counted.hold(ada.events, LATER);
    expect(counted.hold(copyWith(numbered(0, 255)), LATER).ok).toBe(true);
    expect(heads(counted, ada.address).heads).toHaveLength(3);
    expect(counted.hold(copyWith(numbered(255, 1)), LATER)).toMatchObject(limit);
    expect(counted.log(ada.address)).toMatchObject(limit);
    // core 1.6: 1 MiB with the event. Each copy is within it; the proofs of all are not.
    const padded = (tag: string) => copyWith([{ ...good, pad: tag.repeat(600_000) }]);
    const sized = new LogBook(evidence());
    sized.hold(ada.events, LATER);
    expect(sized.hold(padded("a"), LATER).ok).toBe(true);
    expect(heads(sized, ada.address).heads).toHaveLength(3);
    expect(sized.hold(padded("b"), LATER)).toMatchObject(limit);
    expect(sized.log(ada.address)).toMatchObject(limit);
    // The book cannot tell which proofs to leave out. The caller can: it drops the mind.
    sized.drop(ada.address);
    sized.hold(ada.events, LATER);
    expect(heads(sized, ada.address).heads).toHaveLength(3);
    expect(removedKeyCounts(sized)).toBe(false);
  });
});

describe(`${clause("L1 4.9")} what a book has been shown, it keeps`, () => {
  const critical = {
    ext: { "com.example.recovery": { v: 1 } },
    critical: ["com.example.recovery"],
  };
  const MERGE = { oip: "1", type: "Merge" };

  /**
   * At 20 ada replaces her operational key, in an event of her own that
   * depends on an extension. The key she removed signs at 25.
   */
  function removal() {
    const ada = new KeyMind("ada").update(10);
    const whole = new KeyMind("ada").update(10).raw(20, "Update", {
      keys: [{ key: ada.operational(1).publicKey }],
      ...critical,
    }).events;
    const seen = new FirstSeen();
    const judged = judgeRecord(ada.sign(intentBy(ada, 25), { position: 1 }));
    if (!judged.ok) throw new Error(JSON.stringify(judged.issues));
    for (const proof of judged.value.proofs) seen.sawProof(proof.digest, at(26));
    const counts = (book: LogBook) => ownSignedTime(judged.value, ada.address, book) !== undefined;
    return { ada, whole, seen, counts };
  }

  it("does not give up an event it cannot judge for an earlier state of the log", () => {
    const { ada, whole, seen, counts } = removal();
    const book = new LogBook(seen);
    // A source it trusts serves the whole log at 30.
    expect(book.hold(witnessLog(whole, at(30), seen).toHold, at(30)).ok).toBe(true);
    expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ clause: "core 8.3" }] });
    expect(counts(book)).toBe(false);
    // A source that lags serves the log without that event, or less of it.
    for (const earlier of [ada.events, ada.events.slice(0, 1)]) {
      const held = witnessLog(earlier, at(40), seen).toHold;
      expect(book.hold(held, at(40))).toStrictEqual({ ok: true, value: ada.address });
      expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ clause: "core 8.3" }] });
      // The key the event removed does not come back.
      expect(counts(book)).toBe(false);
    }
    // The same copy, served again, is held again.
    expect(book.hold(whole, at(50)).ok).toBe(true);
    // The caller may say it means to go back.
    book.drop(ada.address);
    expect(book.hold(ada.events, at(60)).ok).toBe(true);
    expect(counts(book)).toBe(true);
  });

  it("verifies the event once the verifier can judge it, and then the log goes on from there", () => {
    const { ada, whole, seen, counts } = removal();
    // A witness saw each event when it was made: the removal at 20, before the key signed.
    const made = witness([whole]);
    const evidence: EvidenceView = {
      proofSeen: (digest) => seen.proofSeen(digest),
      eventSeen: (id) => made.eventSeen(id),
    };
    const able = new LogBook(evidence, { understood: ["com.example.recovery"] });
    able.hold(whole, at(30));
    expect(heads(able, ada.address).heads).toHaveLength(3);
    expect(counts(able)).toBe(false);
    able.hold(ada.events, at(40));
    expect(heads(able, ada.address).heads).toHaveLength(3);
    expect(counts(able)).toBe(false);
  });

  it("keeps what follows an event it cannot judge yet: a member's log that arrives later", () => {
    // A collective's second event is signed with a key its member added in an event the
    // verifier does not have yet. Its third removes the collective's own operational key.
    const [a, b] = [new KeyMind("a"), new KeyMind("b")];
    const newer = new KeyMind("b").update(8, {
      invocation: [0, 1].map((n) => ({ key: b.invocation(n).publicKey })),
    });
    const club = () => new Collective("club", [a, b], 2, 5);
    const second = rawSign(draftUpdate(club().head, T(10)), [
      a.asMember(),
      { member: newer.address, versionId: newer.versionId(), invocation: newer.invocation(1) },
    ]);
    const third = rawSign(
      draftUpdate({ mind: club().address, seq: 1, head: contentId(second) }, T(20), {
        keys: [],
      }),
      [a.asMember(), b.asMember()],
    );
    const whole = [...club().events, second, third];
    const judged = judgeRecord(club().sign(intentBy(club(), 25)));
    if (!judged.ok) throw new Error(JSON.stringify(judged.issues));
    const seen = new FirstSeen();
    const book = new LogBook(seen);
    /** What a source the verifier trusts serves at a time: the members' logs, and the collective's. */
    const served = (seconds: number, bLog: KeyMind, log: readonly unknown[]) => {
      const memberLog = (mind: string) => book.log(mind);
      for (const events of [a.events, bLog.events, log]) {
        const witnessed = witnessLog(events, at(seconds), seen, { memberLog });
        book.hold(witnessed.toHold, at(seconds));
      }
    };
    // The whole log arrives: its second event waits on the member's newer log.
    served(40, b, whole);
    expect(book.log(club().address)).toMatchObject({ ok: false, issues: [{ path: "/1" }] });
    // A resolver that lags serves the log without its third event.
    served(50, b, whole.slice(0, 2));
    expect(book.log(club().address)).toMatchObject({ ok: false, issues: [{ path: "/1" }] });
    // The member's newer log arrives, and the second event verifies. The third was shown
    // at 40 and is still held: the log does not end before it.
    served(60, newer, whole.slice(0, 2));
    expect(book.log(club().address)).toMatchObject({ ok: false, issues: [{ path: "/2" }] });
    served(80, newer, whole);
    expect(heads(book, club().address).heads).toHaveLength(3);
    // So the key it removed signs nothing that is first seen after the removal.
    for (const proof of judged.value.proofs) seen.sawProof(proof.digest, at(90));
    served(100, newer, whole);
    expect(ownSignedTime(judged.value, club().address, book)).toBeUndefined();
  });

  it("keeps what follows an event it has no evidence for yet", () => {
    const ada = new KeyMind("ada").update(10).update(20, { keys: [] });
    const judged = judgeRecord(ada.sign(intentBy(ada, 25), { position: 1 }));
    if (!judged.ok) throw new Error(JSON.stringify(judged.issues));
    const seen = new FirstSeen();
    for (const proof of judged.value.proofs) seen.sawProof(proof.digest, at(26));
    seen.sawEvent(contentId(ada.events[0]), at(0));
    const book = new LogBook(seen);
    // The logs come before the witness's times for their events do: first the whole log,
    // then earlier states of it.
    for (const length of [3, 2, 1]) {
      book.hold(ada.events.slice(0, length), at(30 + length));
      expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ clause: "core 9.5" }] });
    }
    for (const event of ada.events.slice(1)) seen.sawEvent(contentId(event), at(22));
    book.forget();
    expect(heads(book, ada.address).heads).toHaveLength(3);
    expect(ownSignedTime(judged.value, ada.address, book)).toBeUndefined();
  });

  it("does not roll a verified log back through a copy that ends in an event it cannot judge", () => {
    const ada = new KeyMind("ada").update(10).update(20, { keys: [] });
    const seen = new FirstSeen();
    const book = new LogBook(seen);
    book.hold(witnessLog(ada.events, at(30), seen).toHold, at(30));
    expect(heads(book, ada.address).heads).toHaveLength(3);
    // An earlier state with a `Merge` after it, which anybody can write: held beside the log,
    // because it may be an event of the log. The mind is refused, and nothing is forgotten.
    const junk = witnessLog([...ada.events.slice(0, 2), MERGE], at(40), seen);
    expect(junk.undecided).toBe(true);
    expect(book.hold(junk.toHold, at(40)).ok).toBe(true);
    expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 3.9" }] });
    // Neither the earlier state alone nor the whole log takes that event away.
    book.hold(ada.events.slice(0, 2), at(50));
    book.hold(ada.events, at(60));
    expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 3.9" }] });
    // Dropping the mind is how the caller says the copy was wrong.
    book.drop(ada.address);
    book.hold(ada.events, at(70));
    expect(heads(book, ada.address).heads).toHaveLength(3);
  });

  it("holds an event it cannot read, when the event is not plain data of this version", () => {
    const ada = new KeyMind("ada").update(10);
    // A later version may write what this one calls no JSON at all.
    for (const later of [
      { oip: "2", type: "Update", weight: 0.5 },
      { oip: "1", type: "Merge", count: 2 ** 60 },
    ]) {
      const seen = new FirstSeen();
      const book = new LogBook(seen);
      const witnessed = witnessLog([...ada.events, later], at(30), seen);
      expect(witnessed.undecided).toBe(true);
      book.hold(witnessed.toHold, at(30));
      expect(book.log(ada.address).ok).toBe(false);
      // The log without it is an earlier state, and does not take its place.
      book.hold(ada.events, at(40));
      expect(book.log(ada.address).ok).toBe(false);
    }
  });

  it(`${clause("L1 7.3")} lets no rival take a position where it holds an event it cannot judge`, () => {
    const { ada, whole, counts } = removal();
    // Another event for position 2, signed by the same control key, which keeps the key.
    const rival = new KeyMind("ada").update(10).update(20, { homes: ["https://rival.example"] });
    const view = (understood: string[], order: readonly (readonly unknown[])[]) => {
      const made = witness([whole, rival.events]);
      // The mind's own event was seen at 20, the rival long after.
      const evidence: EvidenceView = {
        proofSeen: () => at(26),
        eventSeen: (id) => (id === contentId(rival.events[2]) ? at(5000) : made.eventSeen(id)),
      };
      const book = new LogBook(evidence, { understood });
      for (const events of order) book.hold(events, LATER);
      return book;
    };
    for (const order of [
      [whole, rival.events],
      [rival.events, whole],
    ]) {
      // A verifier that implements the extension takes the event that was seen first.
      const able = view(["com.example.recovery"], order);
      expect(heads(able, ada.address).heads[2]).toBe(contentId(whole[2]));
      expect(counts(able)).toBe(false);
      // One that does not cannot tell, and does not take the rival for want of a judgement.
      const unable = view([], order);
      expect(unable.log(ada.address)).toMatchObject({
        ok: false,
        issues: [{ clause: "core 8.3" }],
      });
      expect(counts(unable)).toBe(false);
    }
  });

  it(`${clause("L1 7.3")} keeps an event that conflicts with the one held, and does not follow the later`, () => {
    const { left, right, mind } = twoBranches();
    for (const [first, second] of [
      [left, right],
      [right, left],
    ] as const) {
      // Held one after the other with `hold`, as one source's first word and its second.
      const seenAt = new Map<object, number>([
        [first.events[1] as object, 20],
        [second.events[1] as object, 40],
      ]);
      const { evidence } = bookOf([first.events, second.events], seenAt);
      const book = new LogBook(evidence);
      expect(book.hold(first.events, at(50)).ok).toBe(true);
      expect(book.hold(second.events, at(60)).ok).toBe(true);
      // The event with the earlier evidence has the position, whichever copy came later.
      expect(heads(book, mind).heads[1]).toBe(contentId(first.events[1]));
    }
    // And where the evidence cannot separate them, the mind is duplicitous.
    const tied = new LogBook(witness([left.events, right.events]));
    tied.hold(left.events, LATER);
    tied.hold(right.events, LATER);
    expect(heads(tied, mind).log.duplicitous).toBe(true);
  });

  it("knows a log up to the latest time a copy that reached its end was known", () => {
    const ada = new KeyMind("ada").update(10);
    const book = new LogBook(witness([ada.events]));
    book.hold(ada.events, at(90));
    expect(book.hold(ada.events, at(50))).toStrictEqual({ ok: true, value: ada.address });
    expect(heads(book, ada.address).log.asOf).toBe(at(90));
    book.hold(ada.events, at(95));
    expect(heads(book, ada.address).log.asOf).toBe(at(95));
    // An earlier state served later says nothing of the log held.
    book.hold(ada.events.slice(0, 1), at(99));
    expect(heads(book, ada.address).log.asOf).toBe(at(95));
    // A copy with an invalid event after the log was served with the log, at that time.
    book.hold([...ada.events, { junk: true }], at(120));
    expect(heads(book, ada.address).log.asOf).toBe(at(120));
  });

  it("answers for a mind no longer, once it was shown more of its log than it holds", () => {
    // Nine events for one position, each signed by the control key: the mind's own, which
    // a witness saw first, and eight more.
    const rivals = Array.from({ length: 9 }, (_, n) =>
      new KeyMind("ada").update(20, { homes: [`https://home${n}.example`] }),
    );
    const [own, ...others] = rivals as [KeyMind, ...KeyMind[]];
    const evidence = witness(rivals.map((rival) => rival.events));
    evidence.sawEvent(contentId(own.events[1]), at(19));
    // With eight in all, the evidence decides, whatever order they came in.
    const book = new LogBook(evidence);
    for (const rival of others.slice(0, 7)) book.hold(rival.events, LATER);
    book.hold(own.events, LATER);
    expect(heads(book, own.address).heads[1]).toBe(contentId(own.events[1]));
    // The ninth is more than the book holds. It says so, and answers for the mind no more:
    // what it holds is not all it was shown.
    const full = new LogBook(evidence);
    for (const rival of others) full.hold(rival.events, LATER);
    expect(full.hold(own.events, LATER)).toMatchObject({
      ok: false,
      issues: [{ clause: "implementation limit" }],
    });
    expect(full.log(own.address)).toMatchObject({
      ok: false,
      issues: [{ clause: "implementation limit" }],
    });
    expect(full.hold(own.events, LATER).ok).toBe(false);
    full.drop(own.address);
    full.hold(own.events, LATER);
    expect(heads(full, own.address).heads).toHaveLength(2);
  });

  it("answers by what it was shown, in whatever order the copies and the evidence came", () => {
    const ada = new KeyMind("ada").update(10).update(20).update(30).update(40);
    const ids = ada.events.map((event) => contentId(event));
    const step = fc.oneof(
      fc.record({
        length: fc.integer({ min: 1, max: 5 }),
        tail: fc.constantFrom("none", "none", "invalid", "unread"),
        // Whether the caller asks `witnessLog` what to hold, or holds what came.
        asked: fc.boolean(),
      }),
      // The witness's times for more of the log's events arrive.
      fc.record({ evidence: fc.integer({ min: 1, max: 5 }) }),
    );
    fc.assert(
      fc.property(fc.array(step, { minLength: 1, maxLength: 10 }), (steps) => {
        const evidence = new FirstSeen();
        evidence.sawEvent(ids[0]!, at(0));
        const book = new LogBook(evidence);
        // What has been shown: how far the evidence goes, the longest run of the log's events
        // in any copy, and the positions at which a copy held an event nobody can read.
        let evidenced = 1;
        let longest = 0;
        const unread = new Set<number>();
        for (const made of steps) {
          if ("evidence" in made) {
            for (const id of ids.slice(0, made.evidence)) evidence.sawEvent(id, at(50));
            evidenced = Math.max(evidenced, made.evidence);
            book.forget();
          } else {
            const events: unknown[] = ada.events.slice(0, made.length);
            if (made.tail === "invalid") events.push({ junk: true });
            if (made.tail === "unread") events.push(MERGE);
            // Asked with the book's evidence and no time of its own, so that nothing is recorded.
            const given = made.asked
              ? witnessLog(events, LATER, new FirstSeen(), {
                  evidence: {
                    proofSeen: () => undefined,
                    eventSeen: (id) => evidence.eventSeen(id) ?? at(-1e6),
                  },
                }).toHold
              : events;
            if (given !== undefined) book.hold(given, LATER);
            longest = Math.max(longest, made.length);
            if (made.tail === "unread") unread.add(made.length);
          }
          const answer = book.log(ada.address);
          // An event with no evidence yet, or one that cannot be read, stops the log where
          // the events before it verify. Otherwise the log is every event that was shown.
          const stopped =
            longest > evidenced || [...unread].some((position) => position <= evidenced);
          if (stopped || longest === 0) expect(answer.ok).toBe(false);
          else expect(answer.ok && answer.value.entries.length).toBe(longest);
        }
      }),
      { numRuns: process.env["OIP_MUTATION"] === undefined ? 300 : 60 },
    );
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
