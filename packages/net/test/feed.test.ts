// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, proofDigest } from "@oip/core";
import {
  type IdentityView,
  type JudgedRecord,
  judgeRecord,
  LogBook,
  ownSignedTime,
} from "@oip/identity";
import { clause, type JsonObject } from "@oip/testkit";
import {
  at,
  bookOf,
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
  checkpointRoot,
  committedProofs,
  type VerifiedFeed,
  verifyCheckpoint,
  verifyFeed,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

/** An entry of a mind's feed, not yet signed: at `seq`, after `prev`, publishing `object`. */
function draft(
  author: Mind,
  seq: number,
  prev: object | undefined,
  object: Signed,
  seconds: number,
): JsonObject {
  return {
    oip: "1",
    type: "Entry",
    author: author.address,
    seq,
    ...(prev === undefined ? {} : { prev: contentId(prev) }),
    created: T(seconds),
    object: contentId(object),
    objectType: String(object["type"]),
    proofs: object.proof.map((proof) => proofDigest(proof)),
  };
}

/** For `map`, which would hand `contentId` an index as its second argument. */
const idOf = (record: object): string => contentId(record);
const digestOf = (proof: object): string => proofDigest(proof);

const ada = new KeyMind("ada");
const bob = new KeyMind("bob");

/** Three Intents of Ada's, and the three entries that publish them, made at 10, 20 and 30. */
const published = [1, 2, 3].map(
  (n) => ada.sign(intentBy(ada, n, { want: `Thing ${n}.` })) as Signed,
);
const first = ada.sign(draft(ada, 0, undefined, published[0]!, 10)) as Signed;
const second = ada.sign(draft(ada, 1, first, published[1]!, 20)) as Signed;
const third = ada.sign(draft(ada, 2, second, published[2]!, 30)) as Signed;

const judged = (record: object): JudgedRecord => {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
};

/** A verifier that holds the logs of the minds, and saw each proof of the records when it was made. */
const viewOf = (minds: readonly Mind[], records: readonly object[]): IdentityView =>
  bookOf(minds, records);

/** The feed a verifier makes of the values, with what it holds of Ada. */
function feedOf(
  values: readonly unknown[],
  view: IdentityView = viewOf([ada, bob], values as object[]),
) {
  const feed = verifyFeed(values, ada.address, view);
  if (!feed.ok) throw new Error(JSON.stringify(feed.issues));
  return feed.value;
}

const ids = (feed: VerifiedFeed) => feed.entries.map((entry) => entry.id);

describe(`${clause("L1 10.1")} a mind's public feed`, () => {
  it("is its entries from seq 0, each naming the one before, in whatever order they are held", () => {
    const inOrder = [first, second, third].map((entry) => contentId(entry));
    for (const values of [
      [first, second, third],
      [third, first, second],
      [second, third, first, second, first],
    ]) {
      const feed = feedOf(values);
      expect(ids(feed)).toStrictEqual(inOrder);
      expect(feed.entries.map((entry) => entry.time)).toStrictEqual([at(10), at(20), at(30)]);
      expect(feed.entries.map((entry) => entry.entry.seq)).toStrictEqual([0, 1, 2]);
      expect(feed.author).toBe(ada.address);
      expect(feed.equivocation).toStrictEqual([]);
      expect(feed.refused).toStrictEqual([]);
    }
    expect(ids(feedOf([]))).toStrictEqual([]);
  });

  it("goes as far as the entries that follow one another, and no further", () => {
    // The second is missing: the third names an entry that is not held.
    expect(ids(feedOf([first, third]))).toStrictEqual([contentId(first)]);
    // The first is missing: nothing stands at seq 0.
    expect(ids(feedOf([second, third]))).toStrictEqual([]);
    // An entry at the right seq that names another entry than the one before it.
    const astray = ada.sign(draft(ada, 2, first, published[2]!, 30));
    expect(ids(feedOf([first, second, astray]))).toStrictEqual([first, second].map(idOf));
    // One that names the right entry from the wrong seq.
    const skipping = ada.sign(draft(ada, 3, second, published[2]!, 30));
    expect(ids(feedOf([first, second, skipping]))).toStrictEqual([first, second].map(idOf));
    // The first entry names nothing before it.
    const circular = ada.sign(draft(ada, 0, second, published[0]!, 10));
    expect(ids(feedOf([circular, second]))).toStrictEqual([]);
  });

  it("counts an entry from the evidence for its author's signature, not from its date", () => {
    const view = viewOf([ada], [first, second]);
    // The second entry's proof was first seen at 500.
    const seen = witness([ada.events], [first]);
    for (const proof of judged(second).proofs) seen.sawProof(proof.digest, at(500));
    const late = new LogBook(seen);
    late.hold(ada.events, LATER);
    expect(feedOf([first, second], view).entries.map((entry) => entry.time)).toStrictEqual([
      at(10),
      at(20),
    ]);
    expect(feedOf([first, second], late).entries.map((entry) => entry.time)).toStrictEqual([
      at(10),
      at(500),
    ]);
    // With no evidence for its proof, an entry is not signed, and the feed ends before it.
    expect(ids(feedOf([first, second], bookOf([ada], [first])))).toStrictEqual([contentId(first)]);
  });

  it("is signed by its author's own authority, and nobody else's", () => {
    // Bob writes Ada's name on an entry and signs it himself.
    const forged = bob.sign(draft(ada, 1, first, published[1]!, 20));
    const feed = feedOf([first, forged]);
    expect(ids(feed)).toStrictEqual([contentId(first)]);
    // It is an entry in Ada's name, so it is not refused as a value: it is not valid.
    expect(feed.refused).toStrictEqual([]);
    // Beside the true entry, it changes nothing: the same entry, with one more proof.
    const both = feedOf([first, forged, second]);
    expect(ids(both)).toStrictEqual([first, second].map(idOf));
    expect(both.equivocation).toStrictEqual([]);
    // A mind whose log the verifier does not hold has no feed it can verify.
    expect(ids(feedOf([first, second], viewOf([bob], [first, second])))).toStrictEqual([]);
  });

  it(`${clause("core 3.1")} judges an entry with the proofs of every copy held`, () => {
    // A club of two with a threshold of two and no key of its own. Each member signs
    // its own copy of the club's first entry.
    const [ann, bo] = [new KeyMind("ann"), new KeyMind("bo")];
    const club = new Collective("club", [ann, bo], 2, 5).update(6, [ann, bo], { keys: [] });
    const published = ann.sign(intentBy(ann, 7)) as Signed;
    const entry = draft(club, 0, undefined, published, 10);
    const [byAnn, byBo] = [ann.sign(entry), bo.sign(entry)];
    expect(contentId(byAnn)).toBe(contentId(byBo));
    const view = viewOf([ann, bo, club], [byAnn, byBo]);
    const feed = (values: readonly object[]) => {
      const result = verifyFeed(values, club.address, view);
      if (!result.ok) throw new Error(JSON.stringify(result.issues));
      return result.value;
    };
    expect(feed([byAnn]).entries).toHaveLength(0);
    expect(feed([byBo]).entries).toHaveLength(0);
    for (const values of [
      [byAnn, byBo],
      [byBo, byAnn, byAnn],
    ]) {
      const [only] = feed(values).entries;
      expect(only?.id).toBe(contentId(entry));
      expect(only?.judged.proofs).toHaveLength(2);
      expect(only?.time).toBe(at(10));
    }
  });

  it("lists what is no entry of this feed, with its place and why, and never throws", () => {
    const theirs = bob.sign(draft(bob, 0, undefined, published[0]!, 10));
    const { proof: _, ...unsigned } = second;
    const values = [first, 5, null, published[0], theirs, { ...second, seq: -1 }, unsigned, second];
    const feed = feedOf(values, viewOf([ada, bob], [first, second]));
    expect(ids(feed)).toStrictEqual([first, second].map(idOf));
    expect(feed.refused.map((value) => value.index)).toStrictEqual([1, 2, 3, 4, 5, 6]);
    expect(feed.refused[2]?.issues[0]).toMatchObject({ clause: "L1 10.1" });
    expect(feed.refused[3]?.issues[0]).toMatchObject({ clause: "L1 10.1" });
    for (const value of feed.refused) expect(value.issues[0]?.message.length).toBeGreaterThan(0);
    // What is given must be a list, and the mind an address.
    const view = viewOf([ada], []);
    for (const entries of [undefined, null, 5, "entries", {}, { length: 1 }]) {
      expect(verifyFeed(entries, ada.address, view)).toMatchObject({
        ok: false,
        issues: [{ clause: "L1 10.1" }],
      });
    }
    expect(verifyFeed([], 5 as never, view)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 2.2" }],
    });
  });
});

describe(`${clause("L1 10.3")} feed equivocation`, () => {
  const rival = ada.sign(draft(ada, 1, first, published[2]!, 25)) as Signed;

  it("is two valid entries with different content IDs at one seq, and stops the feed there", () => {
    const feed = feedOf([first, second, rival, third]);
    expect(ids(feed)).toStrictEqual([contentId(first)]);
    expect(feed.equivocation.map((entry) => entry.id)).toStrictEqual(
      [contentId(second), contentId(rival)].sort(),
    );
    expect(feed.equivocation.map((entry) => entry.entry.seq)).toStrictEqual([1, 1]);
    // In the same order whatever order they were held in.
    expect(
      feedOf([rival, third, second, first]).equivocation.map((entry) => entry.id),
    ).toStrictEqual(feed.equivocation.map((entry) => entry.id));
    // At the first position too.
    const other = ada.sign(draft(ada, 0, undefined, published[1]!, 11));
    const split = feedOf([first, other]);
    expect(split.entries).toStrictEqual([]);
    expect(split.equivocation).toHaveLength(2);
  });

  it("is not the same entry held twice, or with other proofs", () => {
    const again = ada.sign(second, { created: T(21) });
    expect(contentId(again)).toBe(contentId(second));
    const feed = feedOf([first, second, again, third]);
    expect(ids(feed)).toStrictEqual([first, second, third].map(idOf));
    expect(feed.equivocation).toStrictEqual([]);
    expect(feed.entries[1]?.judged.proofs).toHaveLength(2);
  });

  it("is not made by an entry that is not valid", () => {
    // In Ada's name, by Bob: no entry, so the position has one.
    const forged = bob.sign(draft(ada, 1, first, published[2]!, 25));
    const feed = feedOf([first, second, forged, third]);
    expect(ids(feed)).toStrictEqual([first, second, third].map(idOf));
    expect(feed.equivocation).toStrictEqual([]);
  });
});

describe(`${clause("L1 10.4")} a feed after a key is declared compromised`, () => {
  // Eve's first entry is made at 10. A thief with her key makes a second at 30. At 300
  // she replaces the key and declares it compromised since 20, and goes on from her
  // first entry with the new key.
  const eve = new KeyMind("eve");
  const made = eve.sign(intentBy(eve, 5)) as Signed;
  const own = eve.sign(draft(eve, 0, undefined, made, 10)) as Signed;
  const thiefs = eve.sign(draft(eve, 1, own, made, 30)) as Signed;
  const before = new KeyMind("eve");
  eve.update(300, {
    keys: [{ key: eve.operational(1).publicKey }],
    revoked: [{ key: eve.operational(0).publicKey, compromisedSince: T(20) }],
  });
  const resumed = eve.sign(draft(eve, 1, own, made, 310), { key: 1 }) as Signed;
  const feed = (values: readonly object[], mind: Mind) => {
    const result = verifyFeed(values, eve.address, viewOf([mind], values));
    if (!result.ok) throw new Error(JSON.stringify(result.issues));
    return result.value;
  };

  it("loses the entries the key signed from that time on, which never count as equivocation", () => {
    expect(before.address).toBe(eve.address);
    // Until the declaration is known, the thief's entry is as good as any.
    expect(ids(feed([own, thiefs], before))).toStrictEqual([own, thiefs].map(idOf));
    // Once it is, the entry is no entry, and the feed goes on from the last valid one.
    const known = feed([own, thiefs, resumed], eve);
    expect(ids(known)).toStrictEqual([own, resumed].map(idOf));
    expect(known.equivocation).toStrictEqual([]);
    expect(ids(feed([own, thiefs], eve))).toStrictEqual([contentId(own)]);
    // What the key signed before that time stands.
    expect(known.entries[0]?.time).toBe(at(10));
  });
});

describe(`${clause("L1 10.5")} a checkpoint`, () => {
  const checkpoint = (size: number, covered: readonly Signed[], more: JsonObject = {}) =>
    ada.sign({
      oip: "1",
      type: "Checkpoint",
      author: ada.address,
      created: T(40),
      size,
      head: contentId(covered.at(-1) ?? first),
      root: checkpointRoot(covered.map((entry) => contentId(entry))) ?? contentId(first),
      ...more,
    }) as Signed;
  const whole = checkpoint(3, [first, second, third]);
  const check = (record: Signed, values: readonly object[] = [first, second, third]) => {
    const view = viewOf([ada, bob], [...values, record]);
    return verifyCheckpoint(judged(record), feedOf(values, view), view);
  };
  const refusal = (record: Signed, values?: readonly object[]) => {
    const result = check(record, values);
    if (result.ok) throw new Error("the checkpoint verifies");
    return { clause: result.issues[0].clause, path: result.issues[0].path };
  };

  it("covers the first `size` entries of its author's feed, by their Merkle root and the last of them", () => {
    const covered = check(whole);
    if (!covered.ok) throw new Error(JSON.stringify(covered.issues));
    expect(covered.value.entries.map((entry) => entry.id)).toStrictEqual(
      [first, second, third].map(idOf),
    );
    expect(covered.value.time).toBe(at(40));
    // A checkpoint over part of what is held.
    const part = check(checkpoint(2, [first, second]));
    expect(part.ok && part.value.entries).toHaveLength(2);
    const one = check(checkpoint(1, [first]));
    expect(one.ok && one.value.entries).toHaveLength(1);
  });

  it("commits to the proofs its entries list, for which a time it existed at is evidence", () => {
    const covered = check(checkpoint(2, [first, second]));
    if (!covered.ok) throw new Error(JSON.stringify(covered.issues));
    expect([...covered.value.proofs].sort()).toStrictEqual(
      [published[0]!, published[1]!].flatMap((record) => record.proof.map(digestOf)).sort(),
    );
    // An entry that lists no proofs commits to none.
    const { proofs: _, ...bare } = draft(ada, 0, undefined, published[0]!, 10);
    const silent = ada.sign(bare) as Signed;
    const of = check(checkpoint(1, [silent]), [silent]);
    expect(of.ok && of.value.proofs.size).toBe(0);
  });

  it("is refused for a wrong head, root or size, or for more entries than are held verified", () => {
    expect(
      refusal(checkpoint(3, [first, second, third], { head: contentId(second) })),
    ).toStrictEqual({
      clause: "L1 10.5",
      path: "/head",
    });
    expect(
      refusal(checkpoint(3, [first, second, third], { root: checkpointRoot([contentId(first)])! })),
    ).toStrictEqual({ clause: "L1 10.5", path: "/root" });
    // The root of the entries in another order.
    expect(
      refusal(
        checkpoint(3, [first, second, third], {
          root: checkpointRoot([second, first, third].map((entry) => contentId(entry)))!,
        }),
      ),
    ).toStrictEqual({ clause: "L1 10.5", path: "/root" });
    // A size that does not go with the head and the root.
    expect(refusal(checkpoint(2, [first, second, third]))).toStrictEqual({
      clause: "L1 10.5",
      path: "/head",
    });
    // More than the verifier holds: it cannot say what the root should be.
    expect(refusal(whole, [first, second])).toStrictEqual({ clause: "L1 10.5", path: "/size" });
    expect(refusal(whole, [first, third])).toStrictEqual({ clause: "L1 10.5", path: "/size" });
  });

  it("is signed by its author's own authority, and is of that author's feed", () => {
    const { proof: _, ...content } = whole;
    const forged = bob.sign(content) as Signed;
    expect(refusal(forged)).toStrictEqual({ clause: "L1 10.5", path: "/proof" });
    // Bob's own checkpoint, held against Ada's feed.
    const bobs = bob.sign({ ...content, author: bob.address }) as Signed;
    expect(refusal(bobs)).toStrictEqual({ clause: "L1 10.5", path: "/author" });
    // A record of another type.
    expect(refusal(first)).toStrictEqual({ clause: "L1 10.5", path: "/type" });
  });
});

describe(`${clause("L1 10.6")} a checkpoint that is shown to have existed at a time`, () => {
  // How an anchor's attestation is carried is not yet specified (OEP-0004), so none is read
  // here. A verifier that has checked one holds a time at which the checkpoint existed, and
  // that time is what this test gives it.
  //
  // Finn publishes three Intents in his feed, at 10, 20 and 30, and a checkpoint over the
  // first two at 40. At 100 he replaces the key that signed them. A verifier that followed
  // the feed as it was made obtains the Intents themselves only at 5,000.
  const finn = new KeyMind("finn");
  const intents = [10, 20, 30].map((seconds) => finn.sign(intentBy(finn, seconds)) as Signed);
  const entries: Signed[] = [];
  for (const [n, intent] of intents.entries()) {
    entries.push(finn.sign(draft(finn, n, entries.at(-1), intent, 10 * (n + 1))));
  }
  const covering = entries.slice(0, 2);
  const checkpoint = finn.sign({
    oip: "1",
    type: "Checkpoint",
    author: finn.address,
    created: T(40),
    size: 2,
    head: contentId(covering[1]!),
    root: checkpointRoot(covering.map(idOf)),
  }) as Signed;
  finn.update(100, { keys: [{ key: finn.operational(1).publicKey }] });

  /** What the verifier holds, with a time for each proof that the anchor is evidence for. */
  const holding = (anchored: ReadonlySet<string> = new Set(), time = at(50)) => {
    const seen = witness([finn.events], [...entries, checkpoint]);
    for (const intent of intents) {
      for (const proof of intent.proof) seen.sawProof(proofDigest(proof), at(5000));
    }
    for (const digest of anchored) seen.sawProof(digest, time);
    const book = new LogBook(seen);
    book.hold(finn.events, LATER);
    return book;
  };
  const signedAt = (book: LogBook) =>
    intents.map((intent) => ownSignedTime(judged(intent), finn.address, book));
  const covered = () => {
    const view = holding();
    const feed = verifyFeed(entries, finn.address, view);
    if (!feed.ok) throw new Error(JSON.stringify(feed.issues));
    const result = verifyCheckpoint(judged(checkpoint), feed.value, view);
    if (!result.ok) throw new Error(JSON.stringify(result.issues));
    return result.value;
  };

  it("is evidence, from that time, for each proof a covered entry commits to", () => {
    // Without it, each Intent was first seen after the key that signed it was gone.
    expect(signedAt(holding())).toStrictEqual([undefined, undefined, undefined]);
    // The anchor shows the checkpoint existed at 50. The proofs of the first two Intents
    // existed then, when the key was Finn's; the third entry is not covered.
    expect(signedAt(holding(covered().proofs))).toStrictEqual([at(50), at(50), undefined]);
  });

  it("is evidence of no earlier time than the anchor's, and of none that helps once the key is gone", () => {
    // An anchor made at 50 does not show that a proof existed at 10, the date the proof gives.
    expect(signedAt(holding(covered().proofs))[0]).not.toBe(at(10));
    // An anchor made after the key was replaced shows the proofs existed when it was not Finn's.
    expect(signedAt(holding(covered().proofs, at(200)))).toStrictEqual([
      undefined,
      undefined,
      undefined,
    ]);
  });

  it(`${clause("L2 10.2", "core 9.7")} keeps a Commitment a party listed verifiable after the keys that signed it are removed`, () => {
    // Gia and Hal sign a Commitment, at 10 and 12. Gia lists it in her feed at 20, and her
    // checkpoint over that entry is shown to have existed at 50. At 100 each of them replaces
    // the key that signed. The verifier obtains the Commitment at 5,000.
    const gia = new KeyMind("gia");
    const hal = new KeyMind("hal");
    const commitment = hal.sign(
      gia.sign({
        oip: "1",
        type: "Commitment",
        author: gia.address,
        created: T(10),
        parties: [
          { mind: gia.address, role: "debtor", required: true },
          { mind: hal.address, role: "creditor", required: true },
        ],
        promise: "Translate the lease.",
        terms: {},
      }),
      { created: T(12) },
    ) as Signed;
    const listed = gia.sign(draft(gia, 0, undefined, commitment, 20)) as Signed;
    const over = gia.sign({
      oip: "1",
      type: "Checkpoint",
      author: gia.address,
      created: T(30),
      size: 1,
      head: contentId(listed),
      root: checkpointRoot([contentId(listed)]),
    }) as Signed;
    gia.update(100, { keys: [{ key: gia.operational(1).publicKey }] });
    hal.update(100, { keys: [{ key: hal.operational(1).publicKey }] });

    const held = (anchored: ReadonlySet<string> = new Set()) => {
      const seen = witness([gia.events, hal.events], [listed, over]);
      for (const proof of commitment.proof) seen.sawProof(proofDigest(proof), at(5000));
      for (const digest of anchored) seen.sawProof(digest, at(50));
      const book = new LogBook(seen);
      for (const mind of [gia, hal]) book.hold(mind.events, LATER);
      return book;
    };
    const signedBy = (book: LogBook) =>
      [gia, hal].map((mind) => ownSignedTime(judged(commitment), mind.address, book));

    const view = held();
    const feed = verifyFeed([listed], gia.address, view);
    if (!feed.ok) throw new Error(JSON.stringify(feed.issues));
    // The entry commits to the proofs the Commitment carried when it was listed: both parties'.
    expect(committedProofs(feed.value.entries[0]!.entry, judged(commitment))).toStrictEqual(
      commitment.proof.map(digestOf),
    );
    const checked = verifyCheckpoint(judged(over), feed.value, view);
    if (!checked.ok) throw new Error(JSON.stringify(checked.issues));

    // Without the checkpoint's time, neither signature counts: each key was gone when it was seen.
    expect(signedBy(view)).toStrictEqual([undefined, undefined]);
    // With it, both count from 50, when each key was its mind's.
    expect(signedBy(held(checked.value.proofs))).toStrictEqual([at(50), at(50)]);
  });

  it("is evidence for the proofs the entries list, and for no proof added to a record since", () => {
    // A second signature on the first Intent, by the same key, that no entry lists.
    const again = finn.sign(intents[0]!, { position: 0, created: T(15) }) as Signed;
    const added = again.proof.map(digestOf).filter((digest) => !covered().proofs.has(digest));
    expect(added).toHaveLength(1);
    const seen = witness([finn.events], [...entries, checkpoint]);
    for (const digest of [...covered().proofs]) seen.sawProof(digest, at(50));
    const book = new LogBook(seen);
    book.hold(finn.events, LATER);
    // The proof the entry lists counts from 50; the added one has no evidence of when it was made.
    const counted = judged({ ...intents[0]!, proof: again.proof.slice(1) });
    expect(ownSignedTime(judged(again), finn.address, book)).toBe(at(50));
    expect(seen.proofSeen(added[0]!)).toBeUndefined();
    expect(ownSignedTime(counted, finn.address, book)).toBeUndefined();
  });
});

describe(`${clause("L1 10.1")} what an entry commits to`, () => {
  const record = published[0]!;
  const entry = judged(first).record as Parameters<typeof committedProofs>[0];

  it("is the proofs it lists that the record has, by their digests", () => {
    expect(committedProofs(entry, judged(record))).toStrictEqual(record.proof.map(digestOf));
    // The record has gained a proof since: the entry says nothing of it.
    const cosigned = bob.sign(record) as Signed;
    expect(contentId(cosigned)).toBe(contentId(record));
    expect(committedProofs(entry, judged(cosigned))).toStrictEqual(record.proof.map(digestOf));
    // A copy without the proof the entry lists: nothing the entry commits to is there.
    const { proof: _, ...content } = record;
    expect(committedProofs(entry, judged(bob.sign(content)))).toStrictEqual([]);
  });

  it("is nothing for a record the entry is not about", () => {
    expect(committedProofs(entry, judged(published[1]!))).toBeUndefined();
    // The same content ID under another type's name is another claim.
    expect(committedProofs({ ...entry, objectType: "Offer" }, judged(record))).toBeUndefined();
  });
});
