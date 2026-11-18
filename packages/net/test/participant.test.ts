// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, proofDigest } from "@oip/core";
import { type IdentityView, type JudgedRecord, judgeRecord } from "@oip/identity";
import { clause, type JsonObject, readVectors } from "@oip/testkit";
import { at, bookOf, Collective, KeyMind, type Mind, rawSign, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import {
  currentLocation,
  currentParticipant,
  verifyFeed,
  verifyParticipant,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

/** A profile of a mind, not yet signed. */
const draft = (author: Mind, seconds: number, more: JsonObject = {}): JsonObject => ({
  oip: "1",
  type: "Participant",
  author: author.address,
  created: T(seconds),
  name: author.name,
  kind: "agent",
  ...more,
});

const judged = (record: object): JudgedRecord => {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
};

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");

/** Whether a profile counts, for a verifier that holds these minds' logs and saw the profile's proofs. */
const verified = (record: object, minds: readonly Mind[] = [ada, bob]) =>
  verifyParticipant(judged(record), bookOf(minds, [record]));

const refusal = (record: object, minds?: readonly Mind[]) => {
  const result = verified(record, minds);
  if (result.ok) throw new Error("the profile counts");
  return { clause: result.issues[0].clause, path: result.issues[0].path };
};

describe(`${clause("L1 16.1")} a participant profile`, () => {
  it("counts for the mind it describes when that mind signed it and its kind is the mind's", () => {
    const profile = ada.sign(draft(ada, 10, { summary: "Translates leases." }));
    const result = verified(profile);
    if (!result.ok) throw new Error(JSON.stringify(result.issues));
    expect(result.value.id).toBe(contentId(profile));
    expect(result.value.record.name).toBe("ada");
    expect(result.value.time).toBe(at(10));
  });

  it("has the kind of the mind's identity state, and no other", () => {
    expect(refusal(ada.sign(draft(ada, 10, { kind: "person" })))).toStrictEqual({
      clause: "L1 16.1",
      path: "/kind",
    });
    // A collective is one, and says so.
    const club = new Collective("club", [ada, bob], 2, 5);
    const minds = [ada, bob, club];
    expect(refusal(club.sign(draft(club, 10), { position: 0 }), minds).path).toBe("/kind");
    expect(verified(club.sign(draft(club, 10, { kind: "collective" })), minds).ok).toBe(true);
  });

  it("is signed by its author's own authority, under the current-state rule", () => {
    // In Ada's name, by Bob.
    expect(refusal(bob.sign(draft(ada, 10)))).toStrictEqual({ clause: "L1 16.1", path: "/proof" });
    // With a key Eve has since removed.
    const eve = new KeyMind("eve");
    const early = eve.sign(draft(eve, 10));
    expect(verified(early, [eve]).ok).toBe(true);
    eve.update(100, { keys: [{ key: eve.operational(1).publicKey }] });
    expect(refusal(early, [eve])).toStrictEqual({ clause: "L1 16.1", path: "/proof" });
    expect(verified(eve.sign(draft(eve, 110), { key: 1 }), [eve]).ok).toBe(true);
    // A mind whose log the verifier does not hold has no kind to compare with.
    expect(verified(ada.sign(draft(ada, 10)), [bob]).ok).toBe(false);
  });

  it("is a Participant record", () => {
    const location = ada.sign({
      oip: "1",
      type: "Location",
      author: ada.address,
      seq: 1,
      created: T(10),
      ttl: 900,
      status: "active",
      endpoints: [],
    });
    expect(refusal(location)).toStrictEqual({ clause: "L1 16.1", path: "/type" });
  });

  it(`${clause("L1 16.2")} gives each of its capabilities an id of its own`, () => {
    const capability = (id: string) => ({ id, summary: `Does ${id}.` });
    expect(
      verified(ada.sign(draft(ada, 10, { capabilities: [capability("a"), capability("b")] }))).ok,
    ).toBe(true);
    // Ids differ by case, and by nothing less.
    expect(
      verified(ada.sign(draft(ada, 10, { capabilities: [capability("a"), capability("A")] }))).ok,
    ).toBe(true);
    // A profile that uses one twice is not well formed: it is never judged as a profile.
    const twice = rawSign(
      draft(ada, 10, { capabilities: [capability("a"), capability("b"), capability("a")] }),
      [{ member: ada.address, versionId: ada.versionId(), invocation: ada.operational() }],
      { purpose: "assertionMethod" },
    );
    expect(judgeRecord(twice)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 16.2", path: "/capabilities/2/id" }],
    });
  });

  it("stands for the profile of the test vectors, which names its mind's kind", () => {
    const cases = (readVectors() as unknown as { cases: Record<string, JsonObject> }).cases;
    const profile = judged(cases["participant"]!).record as { kind: string; author: string };
    const [genesis] = cases["lexis_agent_log"] as unknown as [{ kind: string }];
    expect(profile.kind).toBe(genesis.kind);
  });
});

describe(`${clause("L1 16.4")} the current profile`, () => {
  const [old, newer, newest] = [10, 20, 30].map(
    (seconds) => ada.sign(draft(ada, seconds, { summary: `As of ${seconds}.` })) as Signed,
  ) as [Signed, Signed, Signed];
  const location = (participant?: object) =>
    ada.sign({
      oip: "1",
      type: "Location",
      author: ada.address,
      seq: 1,
      created: T(40),
      ttl: 900,
      status: "active",
      endpoints: [],
      ...(participant === undefined ? {} : { participant: contentId(participant) }),
    });
  /** The entries that publish the records, one after another from seq 0. */
  const feedOf = (author: Mind, records: readonly Signed[]) => {
    const entries: object[] = [];
    for (const [seq, record] of records.entries()) {
      entries.push(
        author.sign({
          oip: "1",
          type: "Entry",
          author: author.address,
          seq,
          ...(seq === 0 ? {} : { prev: contentId(entries[seq - 1]!) }),
          created: T(50 + seq),
          object: contentId(record),
          objectType: String(record["type"]),
          proofs: record.proof.map((proof) => proofDigest(proof)),
        }),
      );
    }
    return entries;
  };
  /** The current profile, for a verifier that holds these records. */
  function current(
    profiles: readonly object[],
    sources: { location?: object; entries?: readonly object[]; of?: Mind },
  ) {
    const all = [
      ...profiles,
      ...(sources.entries ?? []),
      ...(sources.location ? [sources.location] : []),
    ];
    const view: IdentityView = bookOf([ada, bob], all);
    const of = sources.of ?? ada;
    const feed = sources.entries && verifyFeed(sources.entries, of.address, view);
    return currentParticipant(
      profiles.map((profile) => judged(profile)),
      ada.address,
      view,
      {
        location: sources.location && currentLocation([judged(sources.location)], of.address, view),
        feed: feed?.ok === true ? feed.value : undefined,
      },
    )?.id;
  }

  it("is the one the current location record names", () => {
    expect(current([old, newer, newest], { location: location(newer) })).toBe(contentId(newer));
    // Whatever the feed publishes.
    expect(
      current([old, newer, newest], { location: location(old), entries: feedOf(ada, [newest]) }),
    ).toBe(contentId(old));
  });

  it(`${clause("core 3.1")} is judged with the proofs of every copy held of it`, () => {
    // Each of two members sent the copy that carries its own proof. It is one profile, and
    // the two proofs together meet the collective's threshold.
    const [ann, bo] = [new KeyMind("ann"), new KeyMind("bo")];
    const club = new Collective("club", [ann, bo], 2, 5);
    const content = draft(club, 10, { kind: "collective" });
    const [byAnn, byBo] = [ann.sign(content) as Signed, bo.sign(content) as Signed];
    const where = bo.sign(
      ann.sign({
        oip: "1",
        type: "Location",
        author: club.address,
        seq: 1,
        created: T(40),
        ttl: 900,
        status: "active",
        endpoints: [],
        participant: contentId(content),
      }),
    );
    const view: IdentityView = bookOf([ann, bo, club], [byAnn, byBo, where]);
    const asked = (profiles: readonly object[]) =>
      currentParticipant(
        profiles.map((profile) => judged(profile)),
        club.address,
        view,
        { location: currentLocation([judged(where)], club.address, view) },
      )?.id;
    expect(asked([byAnn])).toBeUndefined();
    expect(asked([byBo])).toBeUndefined();
    expect(asked([byAnn, byBo])).toBe(contentId(content));
  });

  it("is, failing that, the most recent profile that counts among those the feed publishes", () => {
    const intent = ada.sign({
      oip: "1",
      type: "Intent",
      author: ada.address,
      created: T(5),
      want: "A translation.",
    }) as Signed;
    const entries = feedOf(ada, [old, newer, intent]);
    // No location record; one that names no profile; one that names a profile not held.
    expect(current([old, newer], { entries })).toBe(contentId(newer));
    expect(current([old, newer], { location: location(), entries })).toBe(contentId(newer));
    expect(current([old, newer], { location: location(newest), entries })).toBe(contentId(newer));
    // The most recent the feed publishes is not held: the one before it.
    expect(current([old], { entries })).toBe(contentId(old));
    // One the location record names that does not count: by its kind.
    const wrong = ada.sign(draft(ada, 35, { kind: "person" })) as Signed;
    expect(current([old, newer, wrong], { location: location(wrong), entries })).toBe(
      contentId(newer),
    );
    // And the most recent in the feed that does not count is passed over.
    expect(current([old, wrong], { entries: feedOf(ada, [old, wrong]) })).toBe(contentId(old));
  });

  it("is none when neither names a profile that is held and counts", () => {
    expect(current([old, newer], {})).toBeUndefined();
    expect(current([], { location: location(old), entries: feedOf(ada, [old]) })).toBeUndefined();
    expect(current([old], { entries: [] })).toBeUndefined();
    // An entry that names a profile's content ID as a record of another type is about no profile.
    const [entry] = feedOf(ada, [old]) as [JsonObject];
    const { proof: _, ...content } = entry;
    const mistyped = ada.sign({ ...content, objectType: "Intent" });
    expect(current([old], { entries: [mistyped] })).toBeUndefined();
    expect(current([old], { entries: [entry] })).toBe(contentId(old));
    // A profile held that neither names is not current, however recent.
    expect(
      current([newest], { location: location(old), entries: feedOf(ada, [newer]) }),
    ).toBeUndefined();
  });

  it("takes nothing from another mind's location record or feed", () => {
    // Bob's location record and feed name Ada's profile.
    const bobs = bob.sign({
      oip: "1",
      type: "Location",
      author: bob.address,
      seq: 1,
      created: T(40),
      ttl: 900,
      status: "active",
      endpoints: [],
      participant: contentId(old),
    });
    expect(current([old], { location: bobs, of: bob })).toBeUndefined();
    expect(current([old], { entries: feedOf(bob, [old]), of: bob })).toBeUndefined();
    // Nor a profile in another mind's name from her own.
    const forged = bob.sign(draft(bob, 10)) as Signed;
    expect(current([forged], { location: location(forged) })).toBeUndefined();
  });
});
