// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, type JsonObject } from "@oip/core";
import { LogBook, type VerifiedLog } from "@oip/identity";
import type { Proof, Validation } from "@oip/schema";
import { clause } from "@oip/testkit";
import {
  at,
  Collective,
  KeyMind,
  LATER,
  type Mind,
  rawSign,
  signer,
  witness,
} from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { type Held, judgeCopy } from "../src/index.ts";

type Signed = JsonObject & { proof: Proof[] };

const proofsOf = (event: JsonObject | undefined): Proof[] =>
  (event as Signed | undefined)?.proof ?? [];

/** What a resolver holds: the logs of some minds, verified, and the evidence it has of them. */
function holding(
  minds: readonly Mind[] = [],
  kept: Readonly<Record<string, readonly Proof[]>> = {},
) {
  const evidence = witness(minds.map((mind) => mind.events));
  const book = new LogBook(evidence);
  for (const mind of minds) book.hold(mind.events, LATER);
  const held: Held = {
    evidence,
    memberLog: (mind) => book.log(mind),
    proofs: (id) => kept[id] ?? [],
  };
  return { held, evidence };
}

/** An event with more proofs on it, beside its own. */
function withMore(event: Signed, more: Parameters<typeof rawSign>[1]): Signed {
  return { ...event, proof: [...event.proof, ...rawSign(event, more).proof] } as unknown as Signed;
}

/** The events of a mind, as signed records. */
const eventsOf = (mind: Mind): Signed[] => mind.events as unknown as Signed[];

const ada = new KeyMind("ada").update(10);
const eve = new KeyMind("eve");
const [a, b, c] = ["a", "b", "c"].map((name) => new KeyMind(name)) as [KeyMind, KeyMind, KeyMind];

describe(`${clause("L1 17.2")} a copy of a log that is published`, () => {
  it("adds its events, each with the proofs that sign it, where every event verifies", () => {
    const { held } = holding();
    const taken = judgeCopy(ada.events, at(20), held);
    expect(taken.refused).toBeUndefined();
    expect(taken.events).toStrictEqual(ada.events);
    expect(taken.log?.mind).toBe(ada.address);
    expect(taken.log?.entries).toHaveLength(2);
    // An event not seen before is judged as seen now.
    expect(taken.log?.entries.map((entry) => entry.time)).toStrictEqual([at(20), at(20)]);
  });

  it("records nothing: what to take is the answer, and the resolver stores it", () => {
    const { held, evidence } = holding();
    judgeCopy(ada.events, at(20), held);
    for (const event of ada.events) expect(evidence.eventSeen(contentId(event))).toBeUndefined();
  });

  it("adds the events of a collective that its members signed, where their logs are held", () => {
    const club = new Collective("club", [a, b, c], 2, 5).update(20, [a, b]);
    const { held } = holding([a, b, c]);
    const taken = judgeCopy(club.events, at(30), held);
    expect(taken.refused).toBeUndefined();
    expect(taken.events).toStrictEqual(club.events);
    expect(taken.log?.entries).toHaveLength(2);
  });
});

describe(`${clause("L1 7.1", "L1 17.2")} the proofs kept for an event`, () => {
  it("are those that can count: not one whose signature fails, and not a stranger's", () => {
    const [genesis, update] = eventsOf(ada) as [Signed, Signed];
    const bent = { ...proofsOf(update)[0], proofValue: proofsOf(genesis)[0]?.proofValue } as Proof;
    const crowded = withMore(update, [
      // A control key the event does not reveal, and a mind that controls nothing here.
      { control: eve.control(0) },
      eve.asMember(),
    ]);
    crowded.proof.push(bent);
    expect(crowded.proof).toHaveLength(4);
    const taken = judgeCopy([genesis, crowded], at(20), holding([eve]).held);
    expect(taken.refused).toBeUndefined();
    expect(taken.events).toStrictEqual(ada.events);
  });

  it("are those of its members by keys that are theirs, for a collective's event", () => {
    const club = new Collective("club", [a, b, c], 2, 5);
    const [genesis] = eventsOf(club) as [Signed];
    const crowded = withMore(genesis, [
      eve.asMember(),
      { control: eve.control(0) },
      // A member's name on a key that is not the member's.
      { invocation: signer("eve/other"), member: a.address, versionId: a.versionId() },
      // And on a version the member's log does not have.
      { invocation: signer("eve/other"), member: b.address, versionId: `7-${contentId(genesis)}` },
    ]);
    expect(crowded.proof).toHaveLength(7);
    const taken = judgeCopy([crowded], at(30), holding([a, b, c, eve]).held);
    expect(taken.refused).toBeUndefined();
    expect(taken.events).toStrictEqual(club.events);
  });

  it("are at most as many as a record carries, however many are shown", () => {
    const [genesis] = eventsOf(ada) as [Signed];
    const strangers = Array.from({ length: 300 }, (_, n) => ({ control: signer(`stranger/${n}`) }));
    // Shown in copies of 200 proofs each, as no record may carry more than 256.
    const copies = [strangers.slice(0, 150), strangers.slice(150)].map((some) =>
      withMore(genesis, some),
    );
    for (const copy of copies) {
      const taken = judgeCopy([copy], at(20), holding().held);
      expect(proofsOf(taken.events[0])).toStrictEqual(genesis.proof);
    }
  });

  it("include the proofs already held for the event, which a copy need not carry again", () => {
    const club = new Collective("club", [a, b, c], 2, 5);
    const [genesis] = eventsOf(club) as [Signed];
    const [byA, byB, byC] = genesis.proof as [Proof, Proof, Proof];
    const onlyC = { ...genesis, proof: [byC] };
    // Alone, one member's proof is not the two the threshold asks for.
    const alone = judgeCopy([onlyC], at(30), holding([a, b, c]).held);
    expect(alone.events).toStrictEqual([]);
    expect(alone.refused).toMatchObject({ position: 0 });
    // With the two held, it is three.
    const kept = { [contentId(genesis)]: [byA, byB] };
    const together = judgeCopy([onlyC], at(30), holding([a, b, c], kept).held);
    expect(together.refused).toBeUndefined();
    expect(proofsOf(together.events[0])).toStrictEqual([byA, byB, byC]);
  });

  it("are every proof whose signature verifies, where the copy would not verify with fewer", () => {
    // A resolver whose reading of which proofs can count is wrong: here, one whose members'
    // logs cannot be read when that is asked, though they could when the copy was judged.
    const club = new Collective("club", [a, b, c], 2, 5);
    const { held } = holding([a, b, c, eve]);
    let asked = 0;
    const forgetful: Held = {
      ...held,
      memberLog: (mind): Validation<VerifiedLog> => {
        asked++;
        // The first judging asks for three logs. What is asked next is the reading.
        return asked > 3 && asked <= 6
          ? { ok: false, issues: [{ path: "", message: "not now", clause: "L1 6.3" }] }
          : held.memberLog(mind);
      },
    };
    const [genesis] = eventsOf(club) as [Signed];
    const crowded = withMore(genesis, [{ control: eve.control(0) }]);
    const taken = judgeCopy([crowded], at(30), forgetful);
    expect(taken.refused).toBeUndefined();
    expect(taken.log?.entries).toHaveLength(1);
    // Nothing was left out that might count: the stranger's proof is kept with the rest.
    expect(proofsOf(taken.events[0])).toStrictEqual(crowded.proof);
  });
});

describe(`${clause("L1 4.9", "L1 17.2")} an event of the copy that does not verify`, () => {
  it("is not taken, and nothing after it: one that is invalid", () => {
    const [genesis, update] = eventsOf(ada) as [Signed, Signed];
    // Signed by a key the event does not reveal.
    const forged = rawSign(update, [{ control: eve.control(0) }]);
    const later = new KeyMind("ada").update(10).update(15).events[2];
    const taken = judgeCopy([genesis, forged, later], at(20), holding().held);
    expect(taken.events).toStrictEqual([genesis]);
    expect(taken.log?.entries).toHaveLength(1);
    expect(taken.refused).toMatchObject({ position: 1, undecided: false });
  });

  it("is not taken, and is called undecided: one the resolver cannot judge", () => {
    // A collective whose members' logs the resolver does not hold.
    const club = new Collective("club", [a, b, c], 2, 5);
    const none = judgeCopy(club.events, at(30), holding().held);
    expect(none.events).toStrictEqual([]);
    expect(none.log).toBeUndefined();
    expect(none.refused).toMatchObject({ position: 0, undecided: true });
    // An event that lists an extension the resolver does not implement.
    const [genesis] = eventsOf(ada) as [Signed];
    const extended = new KeyMind("ada").update(10, {
      ext: { "ext.example": { rule: "new" } },
      critical: ["ext.example"],
    }).events[1];
    const taken = judgeCopy([genesis, extended], at(20), holding().held);
    expect(taken.events).toStrictEqual([genesis]);
    expect(taken.refused).toMatchObject({ position: 1, undecided: true });
    // A resolver that implements it takes the event.
    const understanding = { ...holding().held, understood: ["ext.example"] };
    expect(judgeCopy([genesis, extended], at(20), understanding).events).toHaveLength(2);
  });

  it("is not taken where it is no record at all, with what comes before it taken", () => {
    const [genesis, update] = eventsOf(ada) as [Signed, Signed];
    for (const value of [7, "x", null, [], { oip: "1", created: 0.5 }]) {
      const taken = judgeCopy([genesis, value, update], at(20), holding().held);
      expect(taken.events).toStrictEqual([genesis]);
      expect(taken.refused).toMatchObject({ position: 1, undecided: false });
    }
    expect(judgeCopy([], at(20), holding().held)).toMatchObject({ events: [], log: undefined });
    expect(judgeCopy([7], at(20), holding().held).refused).toMatchObject({ position: 0 });
  });

  it("is not taken where no proof on it has a signature that verifies", () => {
    const [genesis, update] = eventsOf(ada) as [Signed, Signed];
    const unsigned = {
      ...update,
      proof: [{ ...proofsOf(update)[0], proofValue: proofsOf(genesis)[0]?.proofValue }],
    };
    const taken = judgeCopy([genesis, unsigned], at(20), holding().held);
    expect(taken.events).toStrictEqual([genesis]);
    expect(taken.refused).toMatchObject({ position: 1 });
  });
});
