// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, proofDigest } from "@oip/core";
import type { Proof } from "@oip/schema";
import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
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
import { at, intentBy, KeyMind, LATER, locationBy, signer, T, witness } from "@oip/testkit/minds";

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

  it("replaces a log it is given again, and forgets what it verified before", () => {
    const ada = new KeyMind("ada");
    const short = [...ada.events];
    ada.update(10).update(20);
    const book = new LogBook(witness([ada.events]));
    book.hold(short, LATER);
    expect(heads(book, ada.address).heads).toHaveLength(1);
    book.hold(ada.events, LATER);
    expect(heads(book, ada.address).heads).toHaveLength(3);
    book.hold(short, LATER);
    expect(heads(book, ada.address).heads).toHaveLength(1);
  });

  it("knows a mind's log up to the earliest time any of its branches was known", () => {
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
