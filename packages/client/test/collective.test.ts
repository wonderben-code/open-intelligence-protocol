// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, mindAddress } from "@oip/core";
import type { IdentityEvent } from "@oip/schema";
import { clause } from "@oip/testkit";
import { at, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Lookup, Mind } from "../src/index.ts";
import { freshKeystore, refusal } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const HOME = "https://host.example";

let world: World;
beforeEach(() => {
  world = new World(1000);
  world.resolver(A);
  world.host(HOME);
});
afterEach(() => {
  world.close();
});

/** A person with a keystore of their own. */
async function member() {
  const made = await freshKeystore(world, [A]);
  const mind = await Mind.create(made.options, { kind: "human", homes: [HOME] });
  return { ...made, mind };
}

/** Four people. Time passes after they are made, as it does. */
async function people() {
  const all = [await member(), await member(), await member(), await member()] as const;
  world.clock.at = at(1010);
  return all;
}

type Person = Awaited<ReturnType<typeof member>>;

/** A collective of the first three, two of whom act for it, signed by all three and published. */
async function club(a: Person, b: Person, c: Person) {
  const members = [a.mind.address, b.mind.address, c.mind.address];
  let genesis = await a.mind.foundCollective(
    { members, threshold: 2, homes: [HOME] },
    { invocation: a.lock },
  );
  genesis = await b.mind.signEvent(genesis, { invocation: b.lock });
  genesis = await c.mind.signEvent(genesis, { invocation: c.lock });
  const resolved = await a.mind.publishLog([genesis]);
  world.clock.at += 10_000_000_000n;
  return { address: resolved.mind, genesis, members };
}

const reader = () => new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock });

describe(`${clause("L1 9.2")} a collective`, () => {
  it("is founded by its members, each of whom signs its genesis, and is then anyone's to resolve", async () => {
    const [a, b, c] = await people();
    const members = [a.mind.address, b.mind.address, c.mind.address];
    const first = await a.mind.foundCollective(
      { members, threshold: 2, alsoKnownAs: ["https://club.example"] },
      { invocation: a.lock },
    );
    expect(first).toMatchObject({
      type: "Genesis",
      kind: "collective",
      controller: { members, threshold: 2 },
    });
    expect(first.proof).toHaveLength(1);
    // Not every founder has signed: it is no collective yet, and nothing is published.
    const second = await b.mind.signEvent(first, { invocation: b.lock });
    expect(second.proof).toHaveLength(2);
    const before = world.asked.length;
    expect(await refusal(() => a.mind.publishLog([second]))).toBe("oip: invalid-record");
    expect(world.asked.slice(before).filter((asked) => asked.startsWith("PUT"))).toStrictEqual([]);
    // Signing twice adds nothing.
    expect(await b.mind.signEvent(second, { invocation: b.lock })).toStrictEqual(second);
    const genesis = await c.mind.signEvent(second, { invocation: c.lock });
    expect(contentId(genesis)).toBe(contentId(first));
    const resolved = await c.mind.publishLog([genesis]);
    expect(resolved.mind).toBe(mindAddress(contentId(genesis)));
    expect(c.mind.publications).toStrictEqual([{ service: "resolver", origin: A, taken: true }]);
    const other = await reader().resolve(resolved.mind);
    expect(other.state).toMatchObject({
      kind: "collective",
      controller: { kind: "member", members, threshold: 2 },
      retired: false,
    });
    expect(other.did.didDocumentMetadata.members).toStrictEqual(members);
  });

  it("is not founded by a mind that is no member of it, with a threshold that is no majority, or of members named twice", async () => {
    const [a, b, c, d] = await people();
    const members = [a.mind.address, b.mind.address, c.mind.address];
    expect(
      await refusal(() =>
        d.mind.foundCollective({ members, threshold: 2 }, { invocation: d.lock }),
      ),
    ).toBe("oip: forbidden");
    for (const wrong of [
      { members, threshold: 1 },
      { members, threshold: 4 },
      { members: [a.mind.address, a.mind.address, b.mind.address], threshold: 2 },
      { members: [a.mind.address, "nobody"], threshold: 2 },
    ]) {
      expect(
        await refusal(() => a.mind.foundCollective(wrong, { invocation: a.lock })),
        JSON.stringify(wrong.threshold),
      ).toBe("oip: invalid-record");
    }
    // What is no identity event is not signed, and what is no log is not published.
    expect(
      await refusal(() => a.mind.signEvent({ type: "Genesis" } as never, { invocation: a.lock })),
    ).toBe("oip: invalid-record");
    expect(await refusal(() => a.mind.publishLog([]))).toBe("oip: invalid-record");
    expect(await refusal(() => a.mind.publishLog([{ type: "Genesis" }]))).toBe(
      "oip: invalid-record",
    );
    expect(
      await refusal(() =>
        a.mind.publishLog([{ type: "Genesis", controller: { members: [5, "nobody"] } }]),
      ),
    ).toBe("oip: invalid-record");
  });

  it(`${clause("L1 9.3")} changes by the threshold of its members, and every member that is new`, async () => {
    const [a, b, c, d] = await people();
    const { address, genesis, members } = await club(a, b, c);
    const wider = [...members, d.mind.address];
    let update = await a.mind.changeCollective(
      address,
      { members: wider, threshold: 3, alsoKnownAs: ["https://club.example"] },
      { invocation: a.lock },
    );
    expect(update).toMatchObject({
      type: "Update",
      seq: 1,
      prev: contentId(genesis),
      controller: { members: wider, threshold: 3 },
    });
    update = await b.mind.signEvent(update, { invocation: b.lock });
    // Two of three have signed, and the member that is new has not.
    expect(await refusal(() => a.mind.publishLog([genesis, update]))).toBe("oip: invalid-record");
    update = await d.mind.signEvent(update, { invocation: d.lock });
    const resolved = await a.mind.publishLog([genesis, update]);
    expect(resolved.state).toMatchObject({
      seq: 1,
      controller: { members: wider, threshold: 3 },
      alsoKnownAs: ["https://club.example"],
    });
    // The threshold alone, or the members alone: what is left out stays.
    world.clock.at = at(1050);
    const lower = await a.mind.changeCollective(address, { threshold: 4 }, { invocation: a.lock });
    expect(lower).toMatchObject({ seq: 2, controller: { members: wider, threshold: 4 } });
    const fewer = await b.mind.changeCollective(
      address,
      { members: wider.slice(0, 3) },
      { invocation: b.lock },
    );
    expect(fewer).toMatchObject({ controller: { members: wider.slice(0, 3), threshold: 3 } });
    // A change of something else leaves its members as they are.
    world.clock.at = at(1100);
    let homes = await d.mind.changeCollective(address, { homes: [] }, { invocation: d.lock });
    expect((homes as { controller?: unknown }).controller).toBeUndefined();
    for (const signer of [c]) {
      homes = await signer.mind.signEvent(homes, { invocation: signer.lock });
    }
    // The members that drafted other events for this position sign no second one.
    await expect(a.mind.signEvent(homes, { invocation: a.lock })).rejects.toMatchObject({
      code: "already-signed",
    });
    // Three of four must sign: a member whose keystore is another one stands in for the third.
    expect(await refusal(() => d.mind.publishLog([genesis, update, homes]))).toBe(
      "oip: invalid-record",
    );
  });

  it("is dated no earlier than the event before it, by a member whose clock runs behind", async () => {
    const [a, b, c] = await people();
    const { address, genesis } = await club(a, b, c);
    // The same member, on a machine whose clock is a minute slow.
    a.mind.close();
    const slow = await Mind.open({
      ...a.options,
      clock: { now: () => world.clock.at - 60_000_000_000n },
    });
    let update = await slow.changeCollective(address, { homes: [] }, { invocation: a.lock });
    expect(update.created).toBe((genesis as { created: string }).created);
    expect(update.proof[0]?.["created"]).toBe(update.created);
    update = await b.mind.signEvent(update, { invocation: b.lock });
    expect((await b.mind.publishLog([genesis, update])).state).toMatchObject({ seq: 1, homes: [] });
  });

  it(`${clause("L1 3.4", "L1 7.3")} a member signs one event for each position of its log, and no other`, async () => {
    const [a, b, c] = await people();
    const { address } = await club(a, b, c);
    await a.mind.changeCollective(address, { homes: [] }, { invocation: a.lock });
    // Another event for the same position: two would be duplicity, and would name this member.
    await expect(
      a.mind.changeCollective(
        address,
        { alsoKnownAs: ["https://other.example"] },
        { invocation: a.lock },
      ),
    ).rejects.toMatchObject({ name: "KeystoreError", code: "already-signed" });
    // What is no collective's log is not extended as one.
    expect(
      await refusal(() => a.mind.changeCollective(b.mind.address, {}, { invocation: a.lock })),
    ).toBe("oip: forbidden");
    // A mind with no invocation key of its own in its keystore signs for no collective.
    const invocation = await c.keystore.unlock("invocation", c.lock);
    for (const key of invocation.keys()) await invocation.remove(key.publicKey);
    invocation.lock();
    expect(
      await refusal(() => c.mind.changeCollective(address, { homes: [] }, { invocation: c.lock })),
    ).toBe("oip: forbidden");
  });
});

describe(`${clause("L1 9.5", "L2 7.1")} what a collective signs`, () => {
  it("counts for it once the threshold of its members have signed, each with a key of their own", async () => {
    const [a, b, c, d] = await people();
    const { address } = await club(a, b, c);
    const intent = await a.mind.intent({ author: address, want: "A hall for the spring meeting." });
    expect(await a.mind.countsFor(intent, address)).toBe(false);
    // One who is no member adds nothing.
    const outsider = await d.mind.cosign(intent);
    expect(await d.mind.countsFor(outsider, address)).toBe(false);
    const both = await b.mind.cosign(intent);
    expect(both.proof).toHaveLength(2);
    expect(await b.mind.countsFor(both, address)).toBe(true);
    expect(await b.mind.statusOf(both)).toBe("open");
    // Anyone who holds the record can tell.
    a.mind.hold(both);
    expect(await a.mind.countsFor(intent, address)).toBe(true);
  });

  it(`${clause("L2 6.2", "L2 7.1")} a member with a role in its charter signs for it alone, within what the role may do`, async () => {
    const [a, b, c, d] = await people();
    const { address } = await club(a, b, c);
    const draft = await a.mind.charter(address, {
      name: "The club",
      purpose: "To meet in spring.",
      roles: {
        buyer: {
          purpose: "Books what the club needs.",
          powers: [
            { command: "/oip/sign/Intent", policy: [["<=", ".constraints.budget.max", "100"]] },
          ],
        },
      },
      assignments: [{ mind: c.mind.address, role: "buyer" }],
      expires: T(100_000),
    });
    expect(draft).toMatchObject({ type: "Collective", author: address });
    // One member's word is not the collective's.
    const wanting =
      (max: string, by = c) =>
      (charter: typeof draft) =>
        by.mind.intent(
          { author: address, want: "A hall.", constraints: { budget: { max } } },
          { charter },
        );
    const early = await wanting("80")(draft);
    expect(await c.mind.countsFor(early, address)).toBe(false);
    const charter = await b.mind.cosign(draft);
    world.clock.at += 10_000_000_000n;
    c.mind.hold(charter);
    // In force, the charter lets its buyer sign within the budget, and nobody else.
    const within = await wanting("80")(charter);
    expect(await c.mind.countsFor(within, address)).toBe(true);
    const beyond = await wanting("101")(charter);
    expect(await c.mind.countsFor(beyond, address)).toBe(false);
    a.mind.hold(charter);
    const unassigned = await wanting("80", a)(charter);
    expect(await a.mind.countsFor(unassigned, address)).toBe(false);
    // The charter named, and not carried, counts for whoever holds it.
    const named = await c.mind.intent(
      { author: address, want: "Chairs.", constraints: { budget: { max: "20" } } },
      { charter, as: "references" },
    );
    expect(named.proof[0]?.["authority"]).toStrictEqual([`${address}/${contentId(charter)}`]);
    expect(await c.mind.countsFor(named, address)).toBe(true);
    expect(await d.mind.countsFor(named, address)).toBe(false);
    // A proof acts for another by a chain, or by a charter, and not by both or by neither.
    expect(
      await refusal(() => c.mind.intent({ author: address, want: "x" }, { charter, chain: [] })),
    ).toBe("oip: invalid-record");
    expect(await refusal(() => c.mind.intent({ author: address, want: "x" }, {}))).toBe(
      "oip: invalid-record",
    );
  });
});

describe("a failure that is nobody's answer", () => {
  it("reaches the caller as it is, when a log is published", async () => {
    const [a, b, c] = await people();
    const { genesis } = await club(a, b, c);
    a.mind.close();
    // What stands in for `fetch` is broken for a member's log: its answer has headers that cannot be read.
    const broken: typeof world.fetch = (request) =>
      request.url.endsWith(b.mind.address.slice("did:oip:".length))
        ? Promise.resolve({
            status: 200,
            body: null,
            headers: {
              get: () => {
                throw new RangeError("not a response");
              },
            },
          } as unknown as Response)
        : world.fetch(request);
    const again = await Mind.open({ ...a.options, fetch: broken });
    await expect(again.publishLog([genesis])).rejects.toThrow(RangeError);
    // What is no event at all is the caller's mistake, as the protocol names it.
    const unreadable = "an event" as unknown as IdentityEvent;
    expect(await refusal(() => again.publishLog([unreadable]))).toBe("oip: invalid-record");
    expect(await refusal(() => again.signEvent({} as never, { invocation: a.lock }))).toBe(
      "oip: invalid-record",
    );
  });
});
