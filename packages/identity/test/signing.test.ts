// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { CLOCK_SKEW, contentId, type Instant, proofDigest } from "@oip/core";
import type { Proof } from "@oip/schema";
import { clause, copy, withStackSpent } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  collectiveSignedTime,
  CURRENT_STATE_TYPES,
  draftUpdate,
  FirstSeen,
  judgeRecord,
  LogBook,
  operationalProofs,
  operationalProofTime,
  ownSignedTime,
  signEventSync,
} from "../src/index.ts";
import {
  at,
  bookOf,
  Collective,
  intentBy,
  KeyMind,
  LATER,
  locationBy,
  type Mind,
  rawSign,
  T,
  witness,
} from "@oip/testkit/minds";

type Signed = object & { proof: Proof[] };

function judged(record: unknown) {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}

/** When a record is signed by a mind's own authority, for a verifier that saw everything as it was made. */
const signedAt = (record: Signed, mind: Mind, others: readonly Mind[] = []): Instant | undefined =>
  ownSignedTime(judged(record), mind.address, bookOf([mind, ...others], [record]));

/** Why the first proof on a record is not by a valid operational key. */
function refusal(record: Signed, book: LogBook): string {
  const { record: validated, proofs } = judged(record);
  const [proof] = proofs;
  if (proof === undefined) return "no proof verifies";
  const time = operationalProofTime(validated.type, proof, book);
  return time.ok ? "it counts" : time.issues[0].clause;
}

/** A book that holds some logs, and has seen what it is told, when it is told. */
function bookSeeing(
  minds: readonly Mind[],
  seen: readonly [Signed, number][],
  asOf: Instant = LATER,
): LogBook {
  const evidence = witness(minds.map((mind) => mind.events));
  for (const [record, seconds] of seen) {
    for (const proof of record.proof) evidence.sawProof(proofDigest(proof), at(seconds));
  }
  const book = new LogBook(evidence);
  for (const mind of minds) book.hold(mind.events, asOf);
  return book;
}

describe(`${clause("L1 6.1")} a proof by a valid operational key`, () => {
  it("counts for the mind, at its evaluation time", () => {
    const ada = new KeyMind("ada");
    expect(signedAt(ada.sign(intentBy(ada, 10)), ada)).toBe(at(10));
    const record = judged(ada.sign(intentBy(ada, 10)));
    const counted = operationalProofs(record, ada.address, bookOf([ada], [record.record]));
    expect(counted).toHaveLength(1);
    expect(counted[0]).toMatchObject({ mind: ada.address, time: at(10), proof: { index: 0 } });
  });

  it("item 1: needs the signer's log, verified, and the version the proof pins in it", () => {
    const ada = new KeyMind("ada");
    const intent = ada.sign(intentBy(ada, 10));
    const stranger = bookSeeing([], [[intent, 10]]);
    expect(refusal(intent, stranger)).toBe("L1 6.3");
    const broken = new KeyMind("bea").raw(5, "Update", { seq: 7 });
    const byBroken = broken.sign(intentBy(broken, 10), { position: 0 });
    expect(refusal(byBroken, bookSeeing([broken], [[byBroken, 10]]))).toBe("L1 4.2");
    // Pinned to an event the log does not have.
    const longer = new KeyMind("ada").update(5);
    const ahead = longer.sign(intentBy(longer, 10));
    expect(refusal(ahead, bookSeeing([ada], [[ahead, 10]]))).toBe("L1 6.1");
    expect(refusal(ahead, bookSeeing([longer], [[ahead, 10]]))).toBe("it counts");
  });

  it("item 2: needs the key among the operational keys at that version", () => {
    const ada = new KeyMind("ada").update(20, {
      keys: [{ key: new KeyMind("ada").operational(1).publicKey }],
    });
    const asOperational = (record: Signed) => refusal(record, bookSeeing([ada], [[record, 30]]));
    // Key 1 was added by event 1.
    expect(asOperational(ada.sign(intentBy(ada, 30), { key: 1, position: 1 }))).toBe("it counts");
    expect(asOperational(ada.sign(intentBy(ada, 30), { key: 1, position: 0 }))).toBe("L1 6.1");
    // An invocation key and a control key sign identity events, and nothing else.
    for (const by of [ada.invocation(), ada.control(0), ada.control(2)]) {
      expect(asOperational(ada.sign(intentBy(ada, 30), { by, position: 1 }))).toBe("L1 6.1");
    }
    const stranger = new KeyMind("stranger");
    expect(asOperational(ada.sign(intentBy(ada, 30), { by: stranger.operational() }))).toBe(
      "L1 6.1",
    );
  });

  it("item 3: stops at the evaluation time of the event that removes the key, or retires the mind", () => {
    for (const end of ["removed", "retired"]) {
      const ada = new KeyMind("ada");
      if (end === "removed") ada.update(20, { keys: [] });
      else ada.retire(20);
      const when = (seconds: number) => {
        const intent = ada.sign(intentBy(ada, seconds), { position: 0 });
        return refusal(intent, bookSeeing([ada], [[intent, seconds]]));
      };
      expect(when(10), end).toBe("it counts");
      expect(when(19.999999999), end).toBe("it counts");
      expect(when(20), end).toBe("L1 6.1");
      expect(when(30), end).toBe("L1 6.1");
    }
  });

  it(`${clause("L1 3.10")} counts nothing pinned to the version that retired the mind`, () => {
    // The Retire leaves the key in its set, and no later event removes it.
    const ada = new KeyMind("ada").retire(20);
    for (const seconds of [20, 30]) {
      const intent = ada.sign(intentBy(ada, seconds), { position: 1 });
      expect(refusal(intent, bookSeeing([ada], [[intent, seconds]]))).toBe("L1 3.10");
    }
  });

  it("item 3: looks at every later event, not only the next", () => {
    const ada = new KeyMind("ada");
    const key = ada.operational().publicKey;
    ada
      .update(20)
      .update(30, { keys: [] })
      .update(40, { keys: [{ key }] });
    const intent = ada.sign(intentBy(ada, 35), { position: 0 });
    // Back in the set at event 3: a proof pinned there counts again, one pinned before does not.
    expect(refusal(intent, bookSeeing([ada], [[intent, 35]]))).toBe("L1 6.1");
    const again = ada.sign(intentBy(ada, 45), { position: 3 });
    expect(refusal(again, bookSeeing([ada], [[again, 45]]))).toBe("it counts");
    const early = ada.sign(intentBy(ada, 25), { position: 1 });
    expect(refusal(early, bookSeeing([ada], [[early, 25]]))).toBe("it counts");
  });

  it("item 4: withdraws what a key signed from the time it is declared compromised", () => {
    const ada = new KeyMind("ada");
    const key = ada.operational().publicKey;
    ada.update(50, { revoked: [{ key, compromisedSince: T(20) }] });
    const when = (seconds: number) => {
      const intent = ada.sign(intentBy(ada, seconds), { position: 0 });
      return refusal(intent, bookSeeing([ada], [[intent, seconds]]));
    };
    expect(when(10)).toBe("it counts");
    expect(when(19.999999999)).toBe("it counts");
    // Signed before the revocation was published, and withdrawn all the same.
    expect(when(20)).toBe("L1 6.1");
    expect(when(30)).toBe("L1 6.1");
    // A revocation that names no time removes the key and withdraws nothing.
    const bea = new KeyMind("bea");
    bea.update(50, { revoked: [{ key: bea.operational().publicKey }] });
    const before = bea.sign(intentBy(bea, 30), { position: 0 });
    expect(refusal(before, bookSeeing([bea], [[before, 30]]))).toBe("it counts");
  });

  it("items 5 and 7: needs the purpose of the record's type and a signature that verifies", () => {
    const ada = new KeyMind("ada");
    const intent = ada.sign(intentBy(ada, 10));
    const changed = { ...copy(intent), want: "Something else." };
    expect(judged(changed).proofs).toEqual([]);
    expect(signedAt(changed, ada)).toBeUndefined();
    const purpose = copy(intent);
    (purpose.proof[0] as { proofPurpose: string }).proofPurpose = "authentication";
    expect(judged(purpose).proofs).toEqual([]);
    expect(signedAt(purpose, ada)).toBeUndefined();
  });

  it("item 6: counts on a record that describes the present only while the key is current", () => {
    expect(CURRENT_STATE_TYPES).toEqual(["Location", "Participant", "Hello"]);
    const ada = new KeyMind("ada");
    const location = ada.sign(locationBy(ada, 10));
    const intent = ada.sign(intentBy(ada, 10));
    const all: [object & { proof: Proof[] }, number][] = [
      [location, 10],
      [intent, 10],
    ];
    expect(refusal(location, bookSeeing([ada], all))).toBe("it counts");
    // Signed before the key was removed. The Intent stays valid; the Location does not.
    ada.update(20, { keys: [{ key: ada.operational(1).publicKey }] });
    expect(refusal(intent, bookSeeing([ada], all))).toBe("it counts");
    expect(refusal(location, bookSeeing([ada], all))).toBe("L1 6.1");
    // The same for a mind that has retired.
    const bea = new KeyMind("bea");
    const last = bea.sign(locationBy(bea, 10));
    const note = bea.sign(intentBy(bea, 10));
    bea.retire(20);
    const seen: [object & { proof: Proof[] }, number][] = [
      [last, 10],
      [note, 10],
    ];
    expect(refusal(note, bookSeeing([bea], seen))).toBe("it counts");
    expect(refusal(last, bookSeeing([bea], seen))).toBe("L1 6.1");
  });

  it("is for the mind the proof names, and for no other", () => {
    const ada = new KeyMind("ada");
    const bea = new KeyMind("bea");
    const intent = ada.sign(intentBy(bea, 10));
    const book = bookOf([ada, bea], [intent]);
    expect(ownSignedTime(judged(intent), ada.address, book)).toBe(at(10));
    expect(ownSignedTime(judged(intent), bea.address, book)).toBeUndefined();
    expect(operationalProofs(judged(intent), bea.address, book)).toEqual([]);
  });

  it("takes the earliest of several proofs", () => {
    const ada = new KeyMind("ada", 0, {
      keys: [0, 1].map((n) => ({ key: new KeyMind("ada").operational(n).publicKey })),
    });
    const once = ada.sign(intentBy(ada, 10), { key: 1, created: T(30) });
    const twice = ada.sign(once, { key: 0, created: T(20) });
    expect(signedAt(twice, ada)).toBe(at(20));
    // Whichever comes first in the record.
    const other = ada.sign(ada.sign(intentBy(ada, 10), { key: 0, created: T(20) }), {
      key: 1,
      created: T(30),
    });
    expect(signedAt(other, ada)).toBe(at(20));
    expect(operationalProofs(judged(twice), ada.address, bookOf([ada], [twice]))).toHaveLength(2);
  });
});

describe(`${clause("core 9.3", "core 9.4")} a proof is judged at the time evidence shows it existed`, () => {
  const ada = new KeyMind("ada").update(20, { keys: [] });

  it(`${clause("core 9.2")} never takes the signer's own date for evidence`, () => {
    // Dated before the key's removal, by whoever holds the removed key.
    const intent = ada.sign(intentBy(ada, 10), { position: 0 });
    expect(refusal(intent, bookSeeing([ada], []))).toBe("core 9.4");
    expect(refusal(intent, bookSeeing([ada], [[intent, 25]]))).toBe("L1 6.1");
    expect(refusal(intent, bookSeeing([ada], [[intent, 15]]))).toBe("it counts");
  });

  it("evaluates a proof at the later of its date and its evidence", () => {
    const bea = new KeyMind("bea");
    const intent = bea.sign(intentBy(bea, 100));
    const time = (seen: number) => {
      const { record, proofs } = judged(intent);
      const [proof] = proofs;
      if (proof === undefined) throw new Error("the proof does not verify");
      return operationalProofTime(record.type, proof, bookSeeing([bea], [[intent, seen]]));
    };
    expect(time(100)).toEqual({ ok: true, value: at(100) });
    expect(time(500)).toEqual({ ok: true, value: at(500) });
    // Seen before its own date, within the skew: the date stands.
    expect(time(-200)).toEqual({ ok: true, value: at(100) });
    expect(time(-200.000000001)).toMatchObject({ ok: false, issues: [{ clause: "core 9.3" }] });
    expect(CLOCK_SKEW).toBe(300_000_000_000n);
  });

  it("holds evidence for one proof: a signature added later has none of the first one's", () => {
    const bea = new KeyMind("bea", 0, {
      keys: [0, 1].map((n) => ({ key: new KeyMind("bea").operational(n).publicKey })),
    });
    const first = bea.sign(intentBy(bea, 10), { key: 0 });
    const both = bea.sign(first, { key: 1, created: T(10) });
    expect(contentId(both)).toBe(contentId(first));
    const book = bookSeeing([bea], [[first, 10]]);
    const counted = operationalProofs(judged(both), bea.address, book);
    expect(counted.map((proof) => proof.proof.index)).toEqual([0]);
  });

  it("needs the signer's log as it stood no earlier than the evidence for the proof", () => {
    const bea = new KeyMind("bea");
    const intent = bea.sign(intentBy(bea, 100));
    const seen: [Signed, number][] = [[intent, 100]];
    expect(refusal(intent, bookSeeing([bea], seen, at(99.999999999)))).toBe("core 9.4");
    expect(refusal(intent, bookSeeing([bea], seen, at(100)))).toBe("it counts");
    // The log's own date is not the proof's: what matters is when the proof was first seen.
    expect(refusal(intent, bookSeeing([bea], [[intent, 400]], at(399)))).toBe("core 9.4");
    expect(refusal(intent, bookSeeing([bea], [[intent, 400]], at(400)))).toBe("it counts");
    // A proof dated a little ahead of the clock that received it is judged at its
    // date, and the log need only reach the moment it was received: a verifier
    // can count it at once, whatever the signer's clock says.
    expect(refusal(intent, bookSeeing([bea], [[intent, 50]], at(50)))).toBe("it counts");
    expect(refusal(intent, bookSeeing([bea], [[intent, 50]], at(49)))).toBe("core 9.4");
  });
});

describe(`${clause("core 9.6")} expiry`, () => {
  it("does not count a proof evaluated more than 300 seconds after the record expires", () => {
    const ada = new KeyMind("ada");
    const intent = ada.sign(intentBy(ada, 10, { expires: T(100) }));
    const when = (seen: number) =>
      ownSignedTime(judged(intent), ada.address, bookSeeing([ada], [[intent, seen]]));
    expect(when(10)).toBe(at(10));
    expect(when(400)).toBe(at(400));
    expect(when(400.000000001)).toBeUndefined();
    // The key is as valid as ever: it is the record that has expired.
    expect(refusal(intent, bookSeeing([ada], [[intent, 500]]))).toBe("it counts");
    expect(
      operationalProofs(judged(intent), ada.address, bookSeeing([ada], [[intent, 500]])),
    ).toEqual([]);
  });
});

describe(`${clause("L1 6.2", "core 9.7")} removing a key, and declaring it compromised`, () => {
  it("leaves what the key signed valid for a verifier with evidence of when, and for no other", () => {
    const ada = new KeyMind("ada");
    const intent = ada.sign(intentBy(ada, 10));
    ada.update(20, { keys: [] });
    // A witness saw the proof in time. A verifier that first sees it now can only count it from now.
    expect(refusal(intent, bookSeeing([ada], [[intent, 10]]))).toBe("it counts");
    expect(refusal(intent, bookSeeing([ada], [[intent, 1000]]))).toBe("L1 6.1");
    const own = new FirstSeen();
    own.sawProof(proofDigest(intent.proof[0]!), at(1000));
    const late = bookSeeing([ada], []);
    expect(refusal(intent, late)).toBe("core 9.4");
  });
});

describe(`${clause("L1 6.3")} a version the verifier does not have`, () => {
  it("counts nothing until the verifier holds the events, with their first-seen times", () => {
    const ada = new KeyMind("ada");
    const old = [...ada.events];
    ada.update(20, { keys: [{ key: ada.operational(1).publicKey }] });
    const intent = ada.sign(intentBy(ada, 30), { key: 1 });
    const evidence = witness([ada.events], [intent]);
    const book = new LogBook(evidence);
    book.hold(old, LATER);
    expect(refusal(intent, book)).toBe("L1 6.1");
    book.hold(ada.events, LATER);
    expect(refusal(intent, book)).toBe("it counts");
    // Events without evidence of when they existed are not a log a proof can be counted against.
    const blind = new LogBook(witness([old], [intent]));
    blind.hold(ada.events, LATER);
    expect(refusal(intent, blind)).toBe("core 9.5");
  });
});

describe(`${clause("L1 6.4")} a member's proof on another mind's identity event`, () => {
  const founders = () => [new KeyMind("a"), new KeyMind("b"), new KeyMind("c")] as const;

  /** Whether a collective's log verifies, and if not the clause of the reason. */
  function verdict(
    club: Collective,
    members: readonly Mind[],
    seen: Readonly<Record<number, number>> = {},
    asOf: Instant = LATER,
  ): string {
    const evidence = witness([club.events, ...members.map((member) => member.events)]);
    const late = new FirstSeen();
    club.events.forEach((event, position) => {
      const seconds = seen[position];
      late.sawEvent(
        contentId(event),
        seconds === undefined ? evidence.eventSeen(contentId(event))! : at(seconds),
      );
    });
    for (const member of members) {
      for (const event of member.events) {
        late.sawEvent(contentId(event), evidence.eventSeen(contentId(event))!);
      }
    }
    const book = new LogBook(late);
    book.hold(club.events, LATER);
    for (const member of members) book.hold(member.events, asOf);
    const log = book.log(club.address);
    return log.ok ? "verifies" : log.issues[0].clause;
  }

  it("items 1 and 2: is by an invocation key of the member at the version it pins", () => {
    const [a, b, c] = founders();
    expect(verdict(new Collective("club", [a, b, c], 2), [a, b, c])).toBe("verifies");
    // Without a member's log its proof cannot be judged.
    expect(verdict(new Collective("club", [a, b, c], 2), [a, b])).toBe("L1 6.3");
    // An operational key does not sign identity events.
    const club = new Collective("club", [a, b, c], 2);
    const head = { mind: club.address, seq: 0, head: contentId(club.events[0]) };
    const operational = {
      member: a.address,
      versionId: a.versionId(),
      invocation: a.operational(),
    };
    club.events.push(signEventSync(draftUpdate(head, T(10)), [operational, b.asMember()]));
    expect(verdict(club, [a, b, c])).toBe("L1 6.4");
  });

  it("item 3: stands if the key was removed after the event's evaluation time, and not otherwise", () => {
    const [a, b, c] = founders();
    const club = new Collective("club", [a, b, c], 2, 10).update(20, [a, b]);
    // a removes its invocation key at 30: both events came first.
    a.update(30, { invocation: [] });
    expect(verdict(club, [a, b, c])).toBe("verifies");
    // The same events, first seen after the removal: who can say they were not signed later?
    expect(verdict(club, [a, b, c], { 1: 31 })).toBe("L1 6.4");
    expect(verdict(club, [a, b, c], { 1: 30 })).toBe("L1 6.4");
    expect(verdict(club, [a, b, c], { 1: 29 })).toBe("verifies");
    expect(verdict(club, [a, b, c], { 0: 31, 1: 31 })).toBe("L1 6.4");
    // A member that retires can sign nothing more, whichever version its proof pins.
    for (const position of [0, 1]) {
      const [d, e, f] = founders();
      const other = new Collective("club", [d, e, f], 2, 10);
      d.retire(30);
      const head = { mind: other.address, seq: 0, head: contentId(other.events[0]) };
      const signers = [d.asMember(0, position), e.asMember()];
      other.events.push(signEventSync(draftUpdate(head, T(40)), signers));
      expect(verdict(other, [d, e, f]), `pinned to ${position}`).toBe(
        position === 0 ? "L1 6.4" : "L1 3.10",
      );
    }
  });

  it("is not unmade by a compromise declaration in the member's log", () => {
    const [a, b, c] = founders();
    const club = new Collective("club", [a, b, c], 3, 10);
    a.update(30, { revoked: [{ key: a.invocation().publicKey, compromisedSince: T(0) }] });
    expect(verdict(club, [a, b, c])).toBe("verifies");
  });

  it(`${clause("core 9.4")} needs the member's log as it stood no earlier than the evidence for the event`, () => {
    const [a, b, c] = founders();
    const club = new Collective("club", [a, b, c], 2, 10);
    expect(verdict(club, [a, b, c], {}, at(9))).toBe("core 9.4");
    expect(verdict(club, [a, b, c], {}, at(10))).toBe("verifies");
    expect(verdict(club, [a, b, c], { 0: 50 }, at(49))).toBe("core 9.4");
    // Seen before its own date: the log need only reach the evidence.
    expect(verdict(club, [a, b, c], { 0: 5 }, at(5))).toBe("verifies");
    expect(verdict(club, [a, b, c], { 0: 5 }, at(4))).toBe("core 9.4");
  });
});

describe(`${clause("L1 9.1", "L1 9.4", "L1 9.5")} a collective acts as one`, () => {
  const people = () =>
    [new KeyMind("a"), new KeyMind("b"), new KeyMind("c"), new KeyMind("d")] as const;

  it("signs a record when a threshold of its members have signed it with their own operational keys", () => {
    const [a, b, c] = people();
    const club = new Collective("club", [a, b, c], 2, 5);
    const all = [club, a, b, c];
    const one = a.sign(intentBy(club, 10));
    expect(signedAt(one, club, all)).toBeUndefined();
    const two = c.sign(one, { created: T(30) });
    // Signed by the collective from the moment the second signature existed.
    expect(signedAt(two, club, all)).toBe(at(30));
    const three = b.sign(two, { created: T(20) });
    expect(signedAt(three, club, all)).toBe(at(20));
    // Each member's proof counts for that member too.
    expect(signedAt(three, a, all)).toBe(at(10));
  });

  it("counts members, not proofs, and only minds that are members", () => {
    const [a, b, c, d] = people();
    const twoKeys = new KeyMind("a", 0, {
      keys: [0, 1].map((n) => ({ key: a.operational(n).publicKey })),
    });
    const club = new Collective("club", [twoKeys, b, c], 2, 5);
    const all = [club, twoKeys, b, c, d];
    const twice = twoKeys.sign(twoKeys.sign(intentBy(club, 10), { key: 0 }), { key: 1 });
    expect(signedAt(twice, club, all)).toBeUndefined();
    expect(signedAt(d.sign(twice), club, all)).toBeUndefined();
    expect(signedAt(b.sign(twice), club, all)).toBe(at(10));
  });

  it("does not count a proof that names an authority: it acts for that principal", () => {
    const [a, b, c] = people();
    const club = new Collective("club", [a, b, c], 2, 5);
    const all = [club, a, b, c];
    const authority = [`${club.address}/${contentId(intentBy(club, 1))}`];
    const one = a.sign(intentBy(club, 10));
    const withAuthority = b.sign(one, { more: { authority } });
    expect(signedAt(withAuthority, club, all)).toBeUndefined();
    expect(signedAt(b.sign(one), club, all)).toBe(at(10));
  });

  it("judges each time by the membership and the threshold of the state at that time", () => {
    const [a, b, c, d] = people();
    const club = new Collective("club", [a, b, c], 2, 5);
    // At 20, d joins and c leaves; the threshold stays 2 of 3.
    club.update(20, [a, b, d], {
      controller: { members: [a.address, b.address, d.address], threshold: 2 },
    });
    const all = [club, a, b, c, d];
    // c signed while a member; d signed after joining. At no time were two signers both members.
    const split = d.sign(c.sign(intentBy(club, 10)), { created: T(30) });
    expect(signedAt(split, club, all)).toBeUndefined();
    // a and c while c was a member.
    expect(signedAt(a.sign(c.sign(intentBy(club, 10)), { created: T(15) }), club, all)).toBe(
      at(15),
    );
    // a and c after c left.
    expect(
      signedAt(a.sign(c.sign(intentBy(club, 25)), { created: T(26) }), club, all),
    ).toBeUndefined();
    // a and d after d joined.
    expect(signedAt(a.sign(d.sign(intentBy(club, 25)), { created: T(26) }), club, all)).toBe(
      at(26),
    );
    // d before it joined, a after: d's proof stands from 10, and d is a member from 20.
    expect(signedAt(a.sign(d.sign(intentBy(club, 10)), { created: T(26) }), club, all)).toBe(
      at(26),
    );
    // Before the collective existed, nothing is signed by it.
    expect(
      signedAt(a.sign(b.sign(intentBy(club, 1)), { created: T(2) }), club, all),
    ).toBeUndefined();
  });

  it("needs the threshold of the latest state for a record that describes the present", () => {
    const [a, b, c, d] = people();
    const club = new Collective("club", [a, b, c], 2, 5);
    const location = b.sign(c.sign(locationBy(club, 10)));
    const intent = b.sign(c.sign(intentBy(club, 10)));
    expect(signedAt(location, club, [club, a, b, c])).toBe(at(10));
    club.update(20, [a, b, d], {
      controller: { members: [a.address, b.address, d.address], threshold: 2 },
    });
    const all = [club, a, b, c, d];
    // c has left. What the collective signed before stands; what it says of the present does not.
    expect(signedAt(intent, club, all)).toBe(at(10));
    expect(signedAt(location, club, all)).toBeUndefined();
    expect(signedAt(a.sign(b.sign(locationBy(club, 30))), club, all)).toBe(at(30));
    club.retire(40, [a, b]);
    expect(signedAt(a.sign(b.sign(locationBy(club, 30))), club, all)).toBeUndefined();
    expect(signedAt(intent, club, all)).toBe(at(10));
  });

  it("signs nothing once retired, and keeps what it signed before", () => {
    const [a, b, c] = people();
    const club = new Collective("club", [a, b, c], 2, 5).retire(20, [a, b]);
    const all = [club, a, b, c];
    expect(signedAt(a.sign(b.sign(intentBy(club, 10))), club, all)).toBe(at(10));
    expect(signedAt(a.sign(b.sign(intentBy(club, 30))), club, all)).toBeUndefined();
  });

  it("may authorise operational keys of its own, which count as for any mind", () => {
    const [a, b, c] = people();
    const club = new Collective("club", [a, b, c], 2, 5);
    const all = [club, a, b, c];
    expect(signedAt(club.sign(intentBy(club, 10)), club, all)).toBe(at(10));
    const log = bookOf(all).log(club.address);
    if (!log.ok) throw new Error("the collective does not verify");
    const record = judged(club.sign(intentBy(club, 10)));
    expect(collectiveSignedTime(record, log.value, bookOf(all, [record.record]))).toBeUndefined();
    // A mind that is not member-controlled has no threshold to sign by.
    const solo = bookOf([a]).log(a.address);
    if (!solo.ok) throw new Error("the log does not verify");
    expect(collectiveSignedTime(record, solo.value, bookOf(all, [record.record]))).toBeUndefined();
  });

  it("applies the expiry of the record to the time the threshold was reached", () => {
    const [a, b, c] = people();
    const club = new Collective("club", [a, b, c], 2, 5);
    const all = [club, a, b, c];
    const expiring = intentBy(club, 10, { expires: T(100) });
    expect(signedAt(b.sign(a.sign(expiring), { created: T(400) }), club, all)).toBe(at(400));
    expect(signedAt(b.sign(a.sign(expiring), { created: T(401) }), club, all)).toBeUndefined();
  });
});

describe(`${clause("L1 3.11", "core 6.2")} the keys that sign records`, () => {
  it("does not take a control key's proof for an operational one", () => {
    const ada = new KeyMind("ada");
    const intent = rawSign(intentBy(ada, 10), [{ control: ada.control(0) }], {
      purpose: "assertionMethod",
    });
    const record = judged(intent);
    // The signature is good: what it is not is a proof by a key of any mind.
    expect(record.proofs).toHaveLength(1);
    const book = bookOf([ada], [intent]);
    const [proof] = record.proofs;
    if (proof === undefined) throw new Error("the proof does not verify");
    expect(operationalProofTime("Intent", proof, book)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 3.11" }],
    });
    expect(ownSignedTime(record, ada.address, book)).toBeUndefined();
  });

  it("counts nothing for a mind whose log is not held", () => {
    const ada = new KeyMind("ada");
    const intent = ada.sign(intentBy(ada, 10));
    expect(ownSignedTime(judged(intent), ada.address, bookOf([], [intent]))).toBeUndefined();
  });

  it("does not count towards a threshold a member's proof by a key it has removed", () => {
    const [a, b, c] = [new KeyMind("a"), new KeyMind("b"), new KeyMind("c")] as const;
    const club = new Collective("club", [a, b, c], 2, 5);
    a.update(20, { keys: [] });
    const all = [club, a, b, c];
    const late = b.sign(a.sign(intentBy(club, 30), { position: 0 }));
    expect(signedAt(late, club, all)).toBeUndefined();
    const early = b.sign(a.sign(intentBy(club, 10), { position: 0 }));
    expect(signedAt(early, club, all)).toBe(at(10));
  });
});

describe("judging a record", () => {
  it("validates it, and keeps only the proofs that verify", () => {
    const ada = new KeyMind("ada");
    const intent = ada.sign(intentBy(ada, 10));
    const junk = { ...intent.proof[0], proofValue: "z1111" };
    const record = judged({ ...intent, proof: [junk, intent.proof[0]] });
    expect(record.proofs.map((proof) => proof.index)).toEqual([1]);
    expect(record.expires).toBeUndefined();
    expect(judged(ada.sign(intentBy(ada, 10, { expires: T(20) }))).expires).toBe(at(20));
  });

  it("refuses what is not a well-formed record, and never throws", () => {
    const ada = new KeyMind("ada");
    const intent = ada.sign(intentBy(ada, 10));
    const hostile = new Proxy(
      {},
      {
        ownKeys: () => {
          throw new Error("boom");
        },
      },
    );
    for (const notRecord of [null, 1, "record", [], { ...intent, want: 5 }, { a: 0.5 }, hostile]) {
      expect(judgeRecord(notRecord).ok).toBe(false);
    }
    const large = {
      ...intentBy(ada, 10),
      ext: { "com.example.padding": { blob: "x".repeat(1_100_000) } },
    };
    expect(judgeRecord({ ...large, proof: intent.proof })).toMatchObject({
      ok: false,
      issues: [{ clause: "core 1.6" }],
    });
  });

  it("answers and does not throw with the stack all but spent", () => {
    const ada = new KeyMind("ada");
    const intent = ada.sign(intentBy(ada, 10));
    const book = bookOf([ada], [intent]);
    const answers = withStackSpent(() => {
      const record = judgeRecord(intent);
      return record.ok ? ownSignedTime(record.value, ada.address, book) : record.issues[0].clause;
    });
    expect(answers).toHaveLength(200);
    expect(answers.at(-1)).toBe(at(10));
  });

  it("reads a record of a type an extension defines", () => {
    const ada = new KeyMind("ada");
    const custom = ada.sign({
      oip: "1",
      type: "com.example.Note",
      created: T(10),
      ext: { "com.example": { v: 1 } },
      critical: ["com.example"],
    });
    expect(signedAt(custom, ada)).toBe(at(10));
  });
});
