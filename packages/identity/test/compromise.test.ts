// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import type { Proof } from "@oip/schema";
import { clause } from "@oip/testkit";
import {
  at,
  Collective,
  intentBy,
  KeyMind,
  LATER,
  type Mind,
  T,
  witness,
} from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  compromisedSince,
  disregardingCompromise,
  type IdentityView,
  judgeRecord,
  LogBook,
  ownSignedTime,
} from "../src/index.ts";

type Signed = object & { proof: Proof[] };

/** A book that holds some logs, and saw each record when it was made. */
function bookOf(minds: readonly Mind[], records: readonly Signed[]): LogBook {
  const evidence = witness(
    minds.map((mind) => mind.events),
    records,
  );
  const book = new LogBook(evidence);
  for (const mind of minds) book.hold(mind.events, LATER);
  return book;
}

const signedAt = (record: Signed, mind: Mind, view: IdentityView) => {
  const judged = judgeRecord(record);
  if (!judged.ok) throw new Error(JSON.stringify(judged.issues));
  return ownSignedTime(judged.value, mind.address, view);
};

describe(`${clause("L2 8.3", "L1 6.2")} a view with compromise declarations disregarded`, () => {
  /** At 50 Ada revokes her key, and declares it compromised since 20. */
  const ada = new KeyMind("ada");
  const key = ada.operational().publicKey;
  ada.update(50, { revoked: [{ key, compromisedSince: T(20) }] });
  const signedOn = (seconds: number) => ada.sign(intentBy(ada, seconds), { position: 0 });

  it("counts what the key signed before the event that revoked it, and nothing after", () => {
    const [early, between, late] = [signedOn(10), signedOn(30), signedOn(60)];
    const book = bookOf([ada], [early, between, late]);
    const lenient = disregardingCompromise(book);
    expect(signedAt(early, ada, book)).toBe(at(10));
    expect(signedAt(early, ada, lenient)).toBe(at(10));
    // Withdrawn by the declaration, and counted without it.
    expect(signedAt(between, ada, book)).toBeUndefined();
    expect(signedAt(between, ada, lenient)).toBe(at(30));
    // The key is revoked all the same, from the event's own time.
    expect(signedAt(late, ada, book)).toBeUndefined();
    expect(signedAt(late, ada, lenient)).toBeUndefined();
  });

  it("disregards a member's declaration where a collective signs by its threshold", () => {
    const [bea, cal] = [new KeyMind("bea"), new KeyMind("cal")];
    const club = new Collective("club", [ada, bea, cal], 2, 5);
    const record = bea.sign(ada.sign(intentBy(club, 30), { position: 0 }));
    const book = bookOf([ada, bea, cal, club], [record]);
    expect(signedAt(record, club, book)).toBeUndefined();
    expect(signedAt(record, club, disregardingCompromise(book))).toBe(at(30));
  });

  it("changes nothing of the view it was made from", () => {
    const book = bookOf([ada], []);
    const lenient = disregardingCompromise(book);
    const held = book.log(ada.address);
    const without = lenient.log(ada.address);
    if (!held.ok || !without.ok) throw new Error("the log does not verify");
    expect(compromisedSince(held.value, key)).toBe(at(20));
    expect(compromisedSince(without.value, key)).toBeUndefined();
    // The same events, states and times, and the revocation itself.
    expect(without.value.entries).toBe(held.value.entries);
    expect(without.value.revocations).toStrictEqual([
      { ...held.value.revocations[0], compromisedSince: undefined },
    ]);
    expect(lenient.evidence).toBe(book.evidence);
  });

  it("answers with the same log each time, frozen, and with the view's own refusals", () => {
    const book = bookOf([ada], []);
    const lenient = disregardingCompromise(book);
    const first = lenient.log(ada.address);
    const second = lenient.log(ada.address);
    if (!first.ok || !second.ok) throw new Error("the log does not verify");
    expect(second.value).toBe(first.value);
    expect(Object.isFrozen(lenient)).toBe(true);
    expect(Object.isFrozen(first.value)).toBe(true);
    expect(Object.isFrozen(first.value.revocations)).toBe(true);
    expect(Object.isFrozen(first.value.revocations[0])).toBe(true);
    const unknown = new KeyMind("unknown");
    expect(lenient.log(unknown.address)).toStrictEqual(book.log(unknown.address));
    expect(lenient.log(unknown.address).ok).toBe(false);
    // A log that changes in the book is another log, and is copied again.
    book.hold(ada.events, at(10 ** 9 + 1));
    const third = lenient.log(ada.address);
    if (!third.ok) throw new Error("the log does not verify");
    expect(third.value).not.toBe(first.value);
    expect(compromisedSince(third.value, key)).toBeUndefined();
  });
});
