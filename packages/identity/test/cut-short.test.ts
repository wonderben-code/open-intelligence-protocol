// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A check that was cut short, and what a verifier keeps.
 *
 * With the call stack all but spent, a function that judges still answers:
 * whatever fails inside it becomes a refusal. That refusal is true of the
 * moment and not of what was judged, so nothing may keep it. These tests
 * make the fault for certain, by noting a failure for want of room from
 * inside the work, as the places that turn one into an answer do.
 * `spent-stack.test.ts` makes it by spending the stack.
 */

import { contentId, hexToBytes, type SyncSigner } from "@oip/core";
import { CUT_SHORT, cutShort, cutShortCount, noteCutShort } from "@oip/schema";
import { clause } from "@oip/testkit";
import {
  at,
  bookOf,
  Collective,
  intentBy,
  KeyMind,
  LATER,
  rawSign,
  T,
  witness,
} from "@oip/testkit/minds";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  collectiveSignedTime,
  didDocument,
  draftUpdate,
  type EvidenceView,
  FirstSeen,
  judgeRecord,
  LogBook,
  operationalProofs,
  operationalProofTime,
  ownSignedTime,
  verifyLog,
  witnessLog,
  witnessRecord,
} from "../src/index.ts";

const SPENT = { ok: false, issues: [{ clause: "implementation limit", path: "" }] };

/** A value that fails with `error` as soon as anything is asked of it. */
function failing(error: Error): object {
  const refuse = (): never => {
    throw error;
  };
  return new Proxy(
    {},
    { ownKeys: refuse, get: refuse, has: refuse, getOwnPropertyDescriptor: refuse },
  );
}

const overflow = (): RangeError => new RangeError("Maximum call stack size exceeded");

/** Options that find no room when one member of them is asked for, and are read as given otherwise. */
function withoutRoomFor<T extends object>(options: T, name: string): T {
  return new Proxy(options, {
    getOwnPropertyDescriptor: (target, key) => {
      if (key === name) throw overflow();
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
  });
}

/** Evidence that notes a check cut short, while `cut.now` is set, each time it is asked about an event. */
function cutting(seen: EvidenceView): { view: EvidenceView; cut: { now: boolean } } {
  const cut = { now: false };
  return {
    cut,
    view: {
      proofSeen: (digest) => seen.proofSeen(digest),
      eventSeen: (id) => {
        if (cut.now) noteCutShort(overflow());
        return seen.eventSeen(id);
      },
    },
  };
}

describe(`${clause("core 4.4")} a check that was cut short`, () => {
  it("is no verdict on a log: the book refuses, keeps nothing, and is right when asked again", () => {
    const ada = new KeyMind("ada").update(10);
    const intent = judgeRecord(ada.sign(intentBy(ada, 20)));
    if (!intent.ok) throw new Error(JSON.stringify(intent.issues));
    const seen = witness([ada.events], [ada.sign(intentBy(ada, 20))]);
    const { view, cut } = cutting(seen);
    const book = new LogBook(view);
    book.hold(ada.events, LATER);
    cut.now = true;
    expect(book.log(ada.address)).toMatchObject(SPENT);
    expect(ownSignedTime(intent.value, ada.address, book)).toBeUndefined();
    // Nothing of it was kept: with room again, the log verifies and the record counts.
    cut.now = false;
    expect(book.log(ada.address)).toMatchObject({ ok: true, value: { mind: ada.address } });
    expect(ownSignedTime(intent.value, ada.address, book)).toBe(at(20));
    // A verdict reached with room is kept, and a check cut short afterwards does not touch it.
    cut.now = true;
    expect(book.log(ada.address).ok).toBe(true);
  });

  it("is no verdict on a member's log either, or on the collective that rests on it", () => {
    const [a, b] = [new KeyMind("a"), new KeyMind("b")];
    const club = new Collective("club", [a, b], 2, 5);
    const { view, cut } = cutting(witness([a.events, b.events, club.events]));
    const book = new LogBook(view);
    for (const mind of [a, b, club]) book.hold(mind.events, LATER);
    cut.now = true;
    expect(book.log(club.address)).toMatchObject(SPENT);
    expect(book.log(a.address)).toMatchObject(SPENT);
    cut.now = false;
    for (const mind of [club, a, b]) expect(book.log(mind.address).ok, mind.name).toBe(true);
  });

  it("is no look: a look that was cut short records nothing, and says so", () => {
    const ada = new KeyMind("ada").update(10);
    const seen = new FirstSeen();
    const { view, cut } = cutting(seen);
    const book = new LogBook(view);
    cut.now = true;
    // The caller is told, so that it looks again: silence would leave the removal in the
    // update to be seen a look late.
    expect(book.witness(ada.events, at(50), seen)).toStrictEqual(cutShort());
    expect(book.witnessHeld(at(50), seen)).toStrictEqual(cutShort());
    expect(ada.events.map((event) => seen.eventSeen(contentId(event)))).toStrictEqual([
      undefined,
      undefined,
    ]);
    // The copy itself was taken in: holding it again changes nothing, and nothing was lost.
    cut.now = false;
    expect(book.witnessHeld(at(50), seen)).toStrictEqual({ ok: true, value: true });
    expect(ada.events.map((event) => seen.eventSeen(contentId(event)))).toStrictEqual([
      at(50),
      at(50),
    ]);
  });

  it("is looked at again at the same reading, so that a removed key signs nothing in between", () => {
    // Ada removes her first key in an update the verifier obtains at 150. A proof by the
    // removed key reaches the verifier at 200.
    const ada = new KeyMind("ada");
    const record = ada.sign(intentBy(ada, 120));
    ada.update(140, { keys: [{ key: ada.operational(1).publicKey }] });
    const late = judgeRecord(record);
    if (!late.ok) throw new Error(JSON.stringify(late.issues));
    const removal = contentId(ada.events[1]);
    /** What the verifier concludes of the proof, if it looks again at `again` after a look cut short at 150. */
    const counts = (again: number | undefined) => {
      const seen = new FirstSeen();
      const { view, cut } = cutting(seen);
      const book = new LogBook(view);
      cut.now = true;
      const first = book.witness(ada.events, at(150), seen, { following: [ada.address] });
      cut.now = false;
      // A caller that heeds the refusal asks again at once, with the same reading.
      if (again !== undefined)
        book.witness(ada.events, at(again), seen, { following: [ada.address] });
      witnessRecord(late.value, at(200), seen);
      book.witnessHeld(at(400), seen, { following: [ada.address] });
      return {
        first: first.ok ? "ok" : first.issues[0].clause,
        removalSeen: seen.eventSeen(removal),
        counts: ownSignedTime(late.value, ada.address, book),
      };
    };
    // Asked again at 150: the removal is seen at 150, and the proof first seen at 200 is by a
    // key that was gone.
    expect(counts(150)).toStrictEqual({
      first: "implementation limit",
      removalSeen: at(150),
      counts: undefined,
    });
    // Not asked again: the removal is seen at the next look, at 400, and the proof counts.
    // That is why the look must say that it was cut short.
    expect(counts(undefined)).toStrictEqual({
      first: "implementation limit",
      removalSeen: at(400),
      counts: at(200),
    });
  });

  it("is looked at again at the same reading for what waited on a log that is followed, too", () => {
    // A club's removal of its keys waits on its members' logs, which the verifier follows.
    // The look that would have recorded it at 160 is cut short after it has moved those logs
    // to 160. Made again with the same reading, it moves nothing, and still looks.
    const [a, b, c] = ["a", "b", "c"].map((name) => new KeyMind(name)) as [
      KeyMind,
      KeyMind,
      KeyMind,
    ];
    const zed = new KeyMind("zed");
    const club = new Collective("club", [a, b, c], 2, 5);
    const removal = rawSign(draftUpdate(club.head, T(20), { keys: [] }), [
      a.asMember(),
      b.asMember(),
    ]);
    const signed = judgeRecord(club.sign(intentBy(club, 15), { position: 0 }));
    if (!signed.ok) throw new Error(JSON.stringify(signed.issues));
    const following = [a, b, c, club].map((mind) => mind.address);
    const seen = new FirstSeen();
    const { view, cut } = cutting(seen);
    const book = new LogBook(view);
    for (const mind of [a, b, c, club]) {
      expect(book.witness(mind.events, at(100), seen, { following }).ok).toBe(true);
    }
    // The removal arrives at 150 with no reading of the members' logs, and waits.
    expect(book.witness([...club.events, removal], at(150), seen).ok).toBe(true);
    expect(seen.eventSeen(contentId(removal))).toBeUndefined();
    cut.now = true;
    expect(book.witness(zed.events, at(160), seen, { following })).toStrictEqual(cutShort());
    expect(seen.eventSeen(contentId(removal))).toBeUndefined();
    cut.now = false;
    expect(book.witness(zed.events, at(160), seen, { following }).ok).toBe(true);
    expect(seen.eventSeen(contentId(removal))).toBe(at(160));
    // So a proof by the removed key, first seen at 165, does not count.
    for (const proof of signed.value.proofs) seen.sawProof(proof.digest, at(165));
    book.witnessHeld(at(400), seen, { following });
    expect(ownSignedTime(signed.value, club.address, book)).toBeUndefined();
  });

  it("is no reading of the logs followed: `following` that could not be read follows nothing, and says so", () => {
    const ada = new KeyMind("ada").update(10);
    const seen = new FirstSeen();
    const book = new LogBook(seen);
    const unread = { following: failing(overflow()) } as never;
    expect(book.witness(ada.events, at(50), seen, unread)).toStrictEqual(cutShort());
    expect(book.witnessHeld(at(50), seen, unread)).toStrictEqual(cutShort());
    // Names that fail to be read for another reason name nothing, as before.
    const broken = { following: failing(new Error("no")) } as never;
    expect(book.witness(ada.events, at(50), seen, broken).ok).toBe(true);
  });

  it("is no book: one whose options could not be read is not made", () => {
    const seen = new FirstSeen();
    expect(() => new LogBook(seen, failing(overflow()) as never)).toThrow(CUT_SHORT);
    // Options that fail to be read for another reason are options that say nothing.
    expect(new LogBook(seen, failing(new Error("no")) as never).log("x").ok).toBe(false);
  });

  it("is no log, in whole or in part: the verifiers of one copy say nothing of it", () => {
    const ada = new KeyMind("ada").update(10);
    const seen = witness([ada.events]);
    const { view, cut } = cutting(seen);
    const context = { evidence: view, asOf: LATER };
    cut.now = true;
    expect(verifyLog(ada.events, context)).toStrictEqual(cutShort());
    const own = new FirstSeen();
    // Not the events before the one whose check was cut short, and not that it is invalid.
    const witnessed = witnessLog(ada.events, at(50), own, { evidence: view });
    expect(witnessed).toStrictEqual({ log: undefined, failure: cutShort(), undecided: true });
    expect(ada.events.map((event) => own.eventSeen(contentId(event)))).toStrictEqual([
      undefined,
      undefined,
    ]);
    cut.now = false;
    expect(verifyLog(ada.events, context).ok).toBe(true);
    expect(witnessLog(ada.events, at(50), own, { evidence: view }).log?.entries).toHaveLength(2);
    // And for an event, or a context, that cannot be read for want of room.
    const [genesis] = ada.events;
    expect(verifyLog([genesis, failing(overflow())], context)).toStrictEqual(cutShort());
    expect(verifyLog(ada.events, failing(overflow()) as never)).toStrictEqual(cutShort());
    // One that cannot be read for another reason is refused as what it is.
    const unreadable = verifyLog([genesis, failing(new Error("no"))], context);
    expect(unreadable.ok).toBe(false);
    expect(unreadable).not.toStrictEqual(cutShort());
    expect(verifyLog(ada.events, failing(new Error("no")) as never)).not.toStrictEqual(cutShort());
  });

  it("is no time for a proof, and no proof that counts", () => {
    const ada = new KeyMind("ada");
    const record = judgeRecord(ada.sign(intentBy(ada, 20)));
    if (!record.ok) throw new Error(JSON.stringify(record.issues));
    const [proof] = record.value.proofs;
    if (proof === undefined) throw new Error("no proof");
    const seen = witness([ada.events], [ada.sign(intentBy(ada, 20))]);
    const { cut } = cutting(seen);
    const book = new LogBook(seen);
    book.hold(ada.events, LATER);
    // The log is asked for through a view that notes a check cut short.
    const noting = {
      evidence: book.evidence,
      log: (mind: string) => {
        if (cut.now) noteCutShort(overflow());
        return book.log(mind);
      },
    };
    cut.now = true;
    expect(operationalProofTime("Intent", proof, noting)).toStrictEqual(cutShort());
    expect(operationalProofs(record.value, ada.address, noting)).toStrictEqual([]);
    expect(ownSignedTime(record.value, ada.address, noting)).toBeUndefined();
    cut.now = false;
    expect(operationalProofTime("Intent", proof, noting)).toStrictEqual({
      ok: true,
      value: at(20),
    });
    expect(operationalProofs(record.value, ada.address, noting)).toHaveLength(1);
    expect(ownSignedTime(record.value, ada.address, noting)).toBe(at(20));
  });

  it("is no time for a record, where the check that was cut short is not of one proof", () => {
    const ada = new KeyMind("ada");
    const twice = ada.sign(ada.sign(intentBy(ada, 20)), { created: T(21) });
    const record = judgeRecord(twice);
    if (!record.ok) throw new Error(JSON.stringify(record.issues));
    const book = bookOf([ada], [twice]);
    /** A view that notes a check cut short the `n`th time it is asked for a log. */
    const notingAt = (n: number) => {
      let asked = 0;
      return {
        evidence: book.evidence,
        log: (mind: string) => {
          if (++asked === n) noteCutShort(overflow());
          return book.log(mind);
        },
      };
    };
    // The second proof's time was cut short: the first is not given as all there is.
    expect(operationalProofs(record.value, ada.address, notingAt(2))).toStrictEqual([]);
    expect(operationalProofs(record.value, ada.address, notingAt(9))).toHaveLength(2);
    // Both proofs have their times, and the look for a threshold was cut short.
    expect(ownSignedTime(record.value, ada.address, notingAt(3))).toBeUndefined();
    expect(ownSignedTime(record.value, ada.address, notingAt(9))).toBe(at(20));
  });

  it("is no time for a collective's record, where a member's proof could not be judged", () => {
    const ann = new KeyMind("ann");
    const bo = new KeyMind("bo");
    const club = new Collective("club", [ann, bo], 2, 5);
    const signed = bo.sign(ann.sign(intentBy(club, 20)));
    const record = judgeRecord(signed);
    if (!record.ok) throw new Error(JSON.stringify(record.issues));
    const book = bookOf([ann, bo, club], [signed]);
    const log = book.log(club.address);
    if (!log.ok) throw new Error(JSON.stringify(log.issues));
    const cut = { now: true };
    const noting = {
      evidence: book.evidence,
      log: (mind: string) => {
        if (cut.now && mind === bo.address) noteCutShort(overflow());
        return book.log(mind);
      },
    };
    expect(collectiveSignedTime(record.value, log.value, noting)).toBeUndefined();
    cut.now = false;
    expect(collectiveSignedTime(record.value, log.value, noting)).toBe(at(20));
  });

  it("is no reading of the options a record is judged with", () => {
    const ada = new KeyMind("ada");
    const record = ada.sign(intentBy(ada, 20));
    expect(judgeRecord(record, failing(overflow()) as never)).toStrictEqual(cutShort());
    // Options that cannot be read for another reason name no extension: the record is judged.
    expect(judgeRecord(record, failing(new Error("no")) as never).ok).toBe(true);
    // And so for the list of extensions among them.
    expect(judgeRecord(record, { understood: failing(overflow()) as never })).toStrictEqual(
      cutShort(),
    );
    expect(judgeRecord(record, { understood: failing(new Error("no")) as never }).ok).toBe(true);
  });

  it("is no reading of the options a document is asked for with", () => {
    const ada = new KeyMind("ada").update(10);
    const log = verifyLog(ada.events, { evidence: witness([ada.events]), asOf: LATER });
    if (!log.ok) throw new Error(JSON.stringify(log.issues));
    const versionId = log.value.entries[0].state.versionId;
    const first = didDocument(log.value, { versionId });
    const latest = didDocument(log.value);
    expect(first).not.toStrictEqual(latest);
    // A version that could not be read is not read as none asked for: that would be the
    // document of the latest version, given as the one of the version named.
    expect(didDocument(log.value, withoutRoomFor({ versionId }, "versionId"))).toStrictEqual(
      cutShort(),
    );
    for (const name of ["endpoints", "verifiedAliases"]) {
      expect(didDocument(log.value, withoutRoomFor({ versionId }, name))).toStrictEqual(cutShort());
    }
    expect(didDocument(log.value, { versionId })).toStrictEqual(first);
    // Options that cannot be read for another reason are options that say nothing.
    expect(didDocument(log.value, failing(new Error("no")) as never)).toStrictEqual(latest);
  });

  it("is no reading of the options a copy is witnessed with, and no failure of the evidence", () => {
    const ada = new KeyMind("ada").update(10);
    const seen = witness([ada.events]);
    const cut = { log: undefined, failure: cutShort(), undecided: true };
    const own = new FirstSeen();
    // Options that could not be read are not read as none: nothing is witnessed with them.
    expect(witnessLog(ada.events, at(50), own, failing(overflow()) as never)).toStrictEqual(cut);
    expect(own.eventSeen(contentId(ada.events[0]))).toBeUndefined();
    // Nor is any one of them, where the others can be read.
    for (const name of ["evidence", "memberLog", "maxEvents", "understood"]) {
      const options = withoutRoomFor({ evidence: seen }, name);
      expect(witnessLog(ada.events, at(50), own, options)).toStrictEqual(cut);
      expect(own.eventSeen(contentId(ada.events[0]))).toBeUndefined();
    }
    // Evidence that found no room has not said the log is unreadable.
    const spent = {
      proofSeen: seen.proofSeen.bind(seen),
      eventSeen: () => {
        throw overflow();
      },
    };
    expect(witnessLog(ada.events, at(50), own, { evidence: spent })).toStrictEqual(cut);
    expect(own.eventSeen(contentId(ada.events[0]))).toBeUndefined();
    // Evidence that fails otherwise has: that is the caller's own, and it is told.
    const broken = {
      proofSeen: seen.proofSeen.bind(seen),
      eventSeen: () => {
        throw new Error("no");
      },
    };
    const told = witnessLog(ada.events, at(50), own, { evidence: broken });
    expect(told.failure).not.toStrictEqual(cutShort());
    expect(told.log).toBeUndefined();
    expect(witnessLog(ada.events, at(50), own, { evidence: seen }).log?.entries).toHaveLength(2);
  });

  it("is no event that cannot be read: a value held as one would stop its mind", () => {
    const ada = new KeyMind("ada").update(10);
    // A value that is not plain data, and that fails for want of room when it is asked what
    // kind of event it is.
    const second = new Proxy(
      { x: 1.5 },
      {
        getOwnPropertyDescriptor: (target, name) => {
          if (name === "x") return Reflect.getOwnPropertyDescriptor(target, name);
          throw overflow();
        },
      },
    );
    const book = new LogBook(witness([ada.events]));
    expect(book.hold([ada.events[0], second], LATER)).toStrictEqual(cutShort());
    // Nothing of the copy was kept, and the log as it is is taken afterwards.
    expect(book.log(ada.address).ok).toBe(false);
    expect(book.hold(ada.events, LATER).ok).toBe(true);
    expect(book.log(ada.address)).toMatchObject({ ok: true });
  });

  it("is no judgement of a record: `judgeRecord` says so, and keeps no proof out", () => {
    expect(judgeRecord(failing(overflow()))).toMatchObject(SPENT);
    // Any other failure of a value to be read is the value's own, as before.
    expect(judgeRecord(failing(new Error("no")))).toMatchObject({
      ok: false,
      issues: [{ clause: "core 1.2" }],
    });
    const ada = new KeyMind("ada");
    expect(judgeRecord(ada.sign(intentBy(ada, 20)))).toMatchObject({ ok: true });
  });

  it("is what a process in no state to serialise gives, and a book keeps nothing of it", () => {
    // Other code has put a `toJSON` on every object. Nothing is hashed or signed in a
    // process in that state (core 2), so no proof can be judged: that is no verdict on the
    // record, and none on a log.
    const ada = new KeyMind("ada");
    const record = ada.sign(intentBy(ada, 20));
    const book = new LogBook(witness([ada.events], [record]));
    let judged: ReturnType<typeof judgeRecord> | undefined;
    let held: ReturnType<LogBook["hold"]> | undefined;
    Object.defineProperty(Object.prototype, "toJSON", {
      value: () => "rewritten",
      configurable: true,
      writable: true,
    });
    try {
      judged = judgeRecord(record);
      held = book.hold(ada.events, LATER);
    } finally {
      delete (Object.prototype as { toJSON?: unknown }).toJSON;
    }
    expect(judged).toMatchObject(SPENT);
    expect(held).toMatchObject(SPENT);
    // Back in a process that can: the record counts, and the book takes the log in.
    expect(judgeRecord(record).ok).toBe(true);
    expect(book.hold(ada.events, LATER).ok).toBe(true);
    expect(book.log(ada.address).ok).toBe(true);
  });

  it("is no copy of a log: `hold` takes nothing in, where it would have held a value it could not read", () => {
    const ada = new KeyMind("ada").update(10);
    const book = new LogBook(witness([ada.events]));
    expect(book.hold([ada.events[0], failing(overflow())], LATER)).toMatchObject(SPENT);
    expect(book.log(ada.address)).toMatchObject({ ok: false, issues: [{ clause: "L1 6.3" }] });
    expect(book.hold(ada.events, LATER).ok).toBe(true);
    expect(book.log(ada.address)).toMatchObject({ ok: true });
    // A value that fails for a reason of its own is held as one the verifier cannot
    // judge, and stops the log at it, as before (Layer 1, 4.9).
    const other = new LogBook(witness([ada.events]));
    expect(other.hold([ada.events[0], failing(new Error("no"))], LATER).ok).toBe(true);
    expect(other.log(ada.address).ok).toBe(false);
  });
});

describe(`${clause("core 5.5")} what arrives from outside`, () => {
  /** By how much the count moves while `work` runs. */
  const moved = (work: () => unknown): number => {
    const before = cutShortCount();
    work();
    return cutShortCount() - before;
  };

  /**
   * A signer that makes, with a key, a signature whose R is no canonical encoding of a point:
   * its y-coordinate is the field's modulus. The library reports such an R in a `RangeError`.
   */
  const bending = (honest: SyncSigner): SyncSigner => ({
    publicKey: honest.publicKey,
    sign: (message) => {
      const signature = honest.sign(message);
      signature.set(
        hexToBytes("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        0,
      );
      return signature;
    },
  });

  /** A copy of a signed value with one more entry in its `proof`, which anyone could add. */
  const withEntry = <T extends object>(signed: T, added: { proof: object[] }): T => ({
    ...signed,
    proof: [...(signed as { proof: object[] }).proof, ...added.proof],
  });

  it("is a proof that does not verify, and takes nothing from the proof beside it", () => {
    // Anyone can add an entry to a copy of a record. The library reports this one in a
    // `RangeError`, which is no sign of a spent stack: the record is judged, and counts.
    const ada = new KeyMind("ada");
    const intent = intentBy(ada, 20);
    const bent = rawSign(
      intent,
      [
        {
          member: ada.address,
          versionId: ada.versionId(),
          invocation: bending(ada.operational()),
        },
      ],
      { purpose: "assertionMethod" },
    );
    const record = withEntry(ada.sign(intent), bent);
    expect(record.proof).toHaveLength(2);
    let judged: ReturnType<typeof judgeRecord> | undefined;
    expect(
      moved(() => {
        judged = judgeRecord(record);
      }),
    ).toBe(0);
    expect(judged?.ok && judged.value.proofs).toHaveLength(1);
    const book = new LogBook(witness([ada.events], [record]));
    book.hold(ada.events, LATER);
    expect(judged?.ok && ownSignedTime(judged.value, ada.address, book)).toBe(at(20));
  });

  it("is a copy of a log that is held and verifies, with such an entry on one of its events", () => {
    const ada = new KeyMind("ada").update(10);
    const update = ada.events[1] as object;
    const bent = rawSign(update, [{ control: bending(ada.control(1)) }]);
    const copy = [ada.events[0], withEntry(update, bent)];
    expect((copy[1] as { proof: unknown[] }).proof).toHaveLength(2);
    const book = new LogBook(witness([ada.events]));
    expect(moved(() => expect(book.hold(copy, LATER).ok).toBe(true))).toBe(0);
    expect(book.log(ada.address)).toMatchObject({ ok: true });
    expect(verifyLog(copy, { evidence: witness([ada.events]), asOf: LATER }).ok).toBe(true);
  });

  it("never moves the count: no value of JSON, given as a record or as a log", () => {
    const context = { evidence: new FirstSeen(), asOf: LATER };
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(
          moved(() => {
            judgeRecord(value);
            verifyLog(value, context);
            verifyLog([value], context);
            new LogBook(new FirstSeen()).hold([value], LATER);
          }),
        ).toBe(0);
      }),
      { numRuns: 200 },
    );
  });

  it("is answered, and never thrown on, where it throws what cannot be looked at", () => {
    const revoked = (): object => {
      const { proxy, revoke } = Proxy.revocable({}, {});
      revoke();
      return proxy;
    };
    const sly = new Error("plain");
    Object.defineProperty(sly, "name", {
      get: () => {
        // Not an error, and not a thing that can be looked at.
        throw revoked() as Error;
      },
    });
    const trapped = new Proxy(
      {},
      {
        getPrototypeOf: () => {
          throw new Error("trap");
        },
      },
    );
    const ada = new KeyMind("ada").update(10);
    const seen = new FirstSeen();
    const context = { evidence: witness([ada.events]), asOf: LATER };
    for (const thrown of [revoked(), sly, trapped]) {
      const value = failing(thrown as Error);
      const book = new LogBook(witness([ada.events]));
      expect(judgeRecord(value).ok).toBe(false);
      expect(judgeRecord(ada.sign(intentBy(ada, 20)), value as never).ok).toBeTypeOf("boolean");
      expect(verifyLog([ada.events[0], value], context).ok).toBe(false);
      expect(book.hold([ada.events[0], value], LATER).ok).toBeTypeOf("boolean");
      expect(book.witness(ada.events, at(50), seen, { following: value } as never).ok).toBeTypeOf(
        "boolean",
      );
      expect(book.witnessHeld(at(50), seen, { following: value } as never).ok).toBeTypeOf(
        "boolean",
      );
      expect(witnessLog([value], at(50), seen).log).toBeUndefined();
    }
    // The value itself may be one that cannot be looked at.
    expect(judgeRecord(revoked()).ok).toBe(false);
    expect(verifyLog(revoked(), context).ok).toBe(false);
    expect(new LogBook(new FirstSeen()).hold(revoked(), LATER).ok).toBe(false);
  });
});
