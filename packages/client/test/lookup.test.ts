// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, MEDIA_TYPE, mindId, OipError, proofDigest } from "@oip/core";
import { judgeRecord, ownSignedTime } from "@oip/identity";
import { clause, type JsonObject } from "@oip/testkit";
import { at, Collective, intentBy, KeyMind, locationBy, type Mind, T } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { Lookup, systemClock, TransportError } from "../src/index.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const B = "https://resolver-b.example";

let world: World;
beforeEach(() => {
  world = new World(100);
});
afterEach(() => {
  world.close();
});

const lookupOf = (resolvers: readonly string[] = [A], more: object = {}) =>
  new Lookup({ resolvers, fetch: world.fetch, clock: world.clock, ...more });

/** What a call is refused with. */
async function refusal(work: () => Promise<unknown>): Promise<string> {
  try {
    await work();
  } catch (error) {
    if (error instanceof OipError) return `oip: ${error.code}`;
    if (error instanceof TransportError) return `transport: ${error.failure}`;
    throw error;
  }
  throw new Error("nothing was refused");
}

/** A resolver that serves whatever bundle a test gives it. */
function serving(origin: string, bundle: (mind: string) => object | undefined): void {
  world.put(origin, (request) => {
    const id = new URL(request.url).pathname.split("/").at(-1) ?? "";
    const served = bundle(`did:oip:${id}`);
    return served === undefined
      ? new Response(
          JSON.stringify({ type: "urn:oip:error:not-found", title: "Unknown", status: 404 }),
          { status: 404, headers: { "content-type": "application/problem+json" } },
        )
      : new Response(JSON.stringify(served), { headers: { "content-type": MEDIA_TYPE } });
  });
}

const bundleOf = (mind: Mind, more: JsonObject = {}): JsonObject => ({
  oip: "1",
  type: "Bundle",
  mind: mind.address,
  log: mind.events,
  ...more,
});

describe(`${clause("L1 17.1")} resolving a mind`, () => {
  it("gives its verified log, its state and its DID document, from a resolver the client trusts", async () => {
    world.resolver(A);
    const ada = new KeyMind("ada").update(10);
    expect(await world.publish(A, ada)).toBe(202);
    const resolved = await lookupOf().resolve(ada.address);
    expect(resolved.mind).toBe(ada.address);
    expect(resolved.log.entries.map((entry) => entry.event)).toStrictEqual(ada.events);
    expect(resolved.state).toMatchObject({
      mind: ada.address,
      seq: 1,
      kind: "agent",
      keys: [ada.operational().publicKey],
      retired: false,
    });
    expect(resolved.duplicitous).toBe(false);
    expect(resolved.did.didDocument.id).toBe(ada.address);
    expect(resolved.did.didDocumentMetadata.versionId).toBe(ada.versionId());
    expect(resolved.location).toBeUndefined();
    expect(resolved.sources).toStrictEqual([{ resolver: A, events: 2 }]);
    expect(world.asked).toContain(`GET ${A}/oip/v1/resolve/${mindId(ada.address) ?? ""}`);
  });

  it("is refused for what is no address, before anything is asked", async () => {
    world.resolver(A);
    const asked = world.asked.length;
    for (const address of ["did:web:example.com", "ada", "", "did:oip:short"]) {
      expect(await refusal(() => lookupOf().resolve(address)), address).toBe("oip: invalid-record");
    }
    expect(world.asked).toHaveLength(asked);
  });

  it("needs a resolver, named by its HTTPS origin", () => {
    expect(() => lookupOf([])).toThrow(TypeError);
    for (const resolver of [
      "http://resolver.example",
      "https://resolver.example/",
      "https://resolver.example/oip",
      "resolver.example",
    ]) {
      expect(() => lookupOf([resolver]), resolver).toThrow(TypeError);
    }
  });

  it("says that a mind is not found where no resolver holds it", async () => {
    world.resolver(A);
    world.resolver(B);
    const ada = new KeyMind("ada");
    expect(await refusal(() => lookupOf([A, B]).resolve(ada.address))).toBe("oip: not-found");
  });

  it("asks every resolver, and says what each answered", async () => {
    world.resolver(A);
    world.resolver(B);
    const ada = new KeyMind("ada");
    // Resolver A has the whole log, resolver B an earlier copy of it, and a third is gone.
    await world.publish(B, ada);
    ada.update(10);
    await world.publish(A, ada);
    const gone = "https://resolver-c.example";
    const resolved = await lookupOf([A, B, gone]).resolve(ada.address);
    expect(resolved.log.entries).toHaveLength(2);
    expect(resolved.sources).toStrictEqual([
      { resolver: A, events: 2 },
      { resolver: B, events: 1 },
      { resolver: gone, events: undefined, failure: "unreachable" },
    ]);
    // A mind that only the earlier copy's resolver holds is resolved from it.
    const bob = new KeyMind("bob");
    await world.publish(B, bob);
    expect((await lookupOf([A, B, gone]).resolve(bob.address)).sources).toStrictEqual([
      { resolver: A, events: undefined, failure: "not-found" },
      { resolver: B, events: 1 },
      { resolver: gone, events: undefined, failure: "unreachable" },
    ]);
  });

  it("says why no resolver served the mind: the one that refused, before the one that was gone", async () => {
    const ada = new KeyMind("ada");
    world.resolver(A);
    const gone = "https://resolver-c.example";
    // Unknown to one and the other unreachable: it may be known where the client could not ask.
    expect(await refusal(() => lookupOf([A, gone]).resolve(ada.address))).toBe(
      "transport: unreachable",
    );
    expect(await refusal(() => lookupOf([gone]).resolve(ada.address))).toBe(
      "transport: unreachable",
    );
    // One that answered with a problem of its own says the most.
    world.put(
      B,
      () =>
        new Response(
          JSON.stringify({ type: "urn:oip:error:rate-limited", title: "Slow down", status: 429 }),
          {
            status: 429,
            headers: { "content-type": "application/problem+json" },
          },
        ),
    );
    expect(await refusal(() => lookupOf([A, gone, B]).resolve(ada.address))).toBe(
      "oip: rate-limited",
    );
  });
});

describe("a failure that is nobody's answer", () => {
  it("is not taken for a resolver that failed: it reaches the caller as it is", async () => {
    world.resolver(A);
    const ada = new KeyMind("ada");
    await world.publish(A, ada);
    // What stands in for `fetch` is broken: its answer has headers that cannot be read.
    const broken = () =>
      Promise.resolve({
        status: 200,
        body: null,
        headers: {
          get: () => {
            throw new RangeError("not a response");
          },
        },
      } as unknown as Response);
    const lookup = new Lookup({ resolvers: [A, B], fetch: broken, clock: world.clock });
    await expect(lookup.resolve(ada.address)).rejects.toThrow(RangeError);
  });

  it("is the clock of the machine, where a client is given no other", async () => {
    world.resolver(A);
    const ada = new KeyMind("ada");
    await world.publish(A, ada);
    // The resolver saw the log at 100 seconds into 2026. By the machine's clock that is long ago.
    const resolved = await new Lookup({ resolvers: [A], fetch: world.fetch }).resolve(ada.address);
    expect(resolved.log.entries[0]?.time).toBe(at(100));
    expect(resolved.log.asOf).toBeGreaterThan(at(100));
    expect(systemClock.now()).toBeGreaterThanOrEqual(resolved.log.asOf);
  });
});

describe(`${clause("core 9.4")} the witness rule, applied when a mind is resolved`, () => {
  // Ada's log: a genesis the resolver saw at 100, and an update dated 300 that removes her
  // first operational key. The resolver saw the update at 400. The client resolves at 1000.
  async function resolvedLate() {
    world.resolver(A);
    const ada = new KeyMind("ada");
    await world.publish(A, ada);
    const before = ada.sign(intentBy(ada, 150));
    ada.update(300, { keys: [{ key: ada.operational(1).publicKey }] });
    world.clock.at = at(400);
    await world.publish(A, ada);
    world.clock.at = at(1000);
    const lookup = lookupOf();
    const resolved = await lookup.resolve(ada.address);
    return { ada, lookup, resolved, before };
  }

  it("takes the time of each event from the resolver, not from the event and not from its own first sight", async () => {
    const { resolved } = await resolvedLate();
    expect(resolved.log.entries.map((entry) => entry.time)).toStrictEqual([at(100), at(400)]);
  });

  it("counts a proof by a removed key if it was seen before the resolver saw the removal, and not after", async () => {
    const { ada, lookup, before } = await resolvedLate();
    const judged = judgeRecord(before);
    if (!judged.ok) throw new Error("not a record");
    const digest = proofDigest(before.proof[0]);
    // With no evidence of when the proof existed, it does not count at all.
    expect(ownSignedTime(judged.value, ada.address, lookup.view)).toBeUndefined();
    // Evidence at 350: after the update's own date, and before the resolver saw it. It counts.
    lookup.seen.sawProof(digest, at(350));
    expect(ownSignedTime(judged.value, ada.address, lookup.view)).toBe(at(350));
    // A proof first seen at 500 was seen after the removal the resolver witnessed at 400. If the
    // client went by its own first sight of the update, at 1000, this would count.
    const after = ada.sign(intentBy(ada, 160), { key: 0, position: 0 });
    const late = judgeRecord(after);
    if (!late.ok) throw new Error("not a record");
    lookup.seen.sawProof(proofDigest(after.proof[0]), at(500));
    expect(ownSignedTime(late.value, ada.address, lookup.view)).toBeUndefined();
  });

  it("takes no time that is ahead of its own clock as evidence of anything earlier than now", async () => {
    const ada = new KeyMind("ada");
    const genesis = contentId(ada.events[0]);
    // A resolver whose clock runs a minute fast, and one that names a time a year ahead.
    serving(A, () => bundleOf(ada, { firstSeen: { [genesis]: T(160) } }));
    const fast = await lookupOf().resolve(ada.address);
    expect(fast.log.entries[0]?.time).toBe(at(100));
    serving(B, () => bundleOf(ada, { firstSeen: { [genesis]: T(100 + 365 * 86_400) } }));
    // A time that far ahead is evidence of nothing, and the log has none: it does not verify.
    expect(await refusal(() => lookupOf([B]).resolve(ada.address))).toBe("oip: invalid-proof");
  });

  it("takes times for the events a resolver served, and for nothing else it names", async () => {
    const ada = new KeyMind("ada");
    const bob = new KeyMind("bob");
    const digest = proofDigest(ada.sign(intentBy(ada, 5)).proof[0]);
    serving(A, (mind) =>
      mind === ada.address
        ? bundleOf(ada, {
            firstSeen: {
              [contentId(ada.events[0])]: T(50),
              // Another mind's event, and a proof that is on no record of the bundle.
              [contentId(bob.events[0])]: T(1),
              [digest]: T(1),
            },
          })
        : undefined,
    );
    const lookup = lookupOf();
    await lookup.resolve(ada.address);
    expect(lookup.view.evidence.eventSeen(contentId(ada.events[0]))).toBe(at(50));
    expect(lookup.view.evidence.eventSeen(contentId(bob.events[0]))).toBeUndefined();
    expect(lookup.view.evidence.proofSeen(digest)).toBeUndefined();
    // What names neither an event nor a proof makes the bundle no bundle at all.
    serving(B, () => bundleOf(ada, { firstSeen: { "not a name": T(1) } }));
    expect(await refusal(() => lookupOf([B]).resolve(ada.address))).toBe("oip: invalid-record");
  });

  it("holds the log as of each resolution, so that what was removed since is known", async () => {
    world.resolver(A);
    const ada = new KeyMind("ada");
    await world.publish(A, ada);
    const lookup = lookupOf();
    const first = await lookup.resolve(ada.address);
    expect(first.state.keys).toStrictEqual([ada.operational(0).publicKey]);
    expect(first.log.asOf).toBe(at(100));
    ada.update(150, { keys: [{ key: ada.operational(1).publicKey }] });
    world.clock.at = at(200);
    await world.publish(A, ada);
    world.clock.at = at(300);
    const second = await lookup.resolve(ada.address);
    expect(second.state.keys).toStrictEqual([ada.operational(1).publicKey]);
    expect(second.log.asOf).toBe(at(300));
    expect(second.log.entries.map((entry) => entry.time)).toStrictEqual([at(100), at(200)]);
  });
});

describe(`${clause("L1 17.2")} what a resolver serves is verified`, () => {
  it("is refused if an event of the log does not verify", async () => {
    const ada = new KeyMind("ada").update(10);
    const eve = new KeyMind("eve").update(10);
    // The second event of the log is Eve's: signed, and not by Ada's control key.
    const forged = { ...bundleOf(ada), log: [ada.events[0], eve.events[1]] };
    serving(A, () => ({
      ...forged,
      firstSeen: { [contentId(ada.events[0])]: T(1), [contentId(eve.events[1])]: T(2) },
    }));
    const error = await lookupOf()
      .resolve(ada.address)
      .catch((thrown: unknown) => thrown);
    expect(error).toBeInstanceOf(OipError);
    expect(error).toMatchObject({ code: "invalid-proof" });
    expect((error as OipError).detail).toContain(`${A} served a log of ${ada.address}`);
  });

  it("is refused if it is no bundle, or the bundle of another mind", async () => {
    const ada = new KeyMind("ada");
    const bob = new KeyMind("bob");
    serving(A, () => bundleOf(bob));
    expect(await refusal(() => lookupOf().resolve(ada.address))).toBe("oip: invalid-record");
    serving(A, () => ada.events[0]);
    expect(await refusal(() => lookupOf().resolve(ada.address))).toBe("oip: invalid-record");
    serving(A, () => ({ ...bundleOf(ada), log: "events" }));
    expect(await refusal(() => lookupOf().resolve(ada.address))).toBe("oip: invalid-record");
  });

  it("is not relied on without the resolver's times: a log served bare does not verify", async () => {
    const ada = new KeyMind("ada");
    serving(A, () => bundleOf(ada));
    expect(await refusal(() => lookupOf().resolve(ada.address))).toBe("oip: invalid-proof");
  });

  it(`${clause("L1 7.2")} shows duplicity where two resolvers hold different events for one position`, async () => {
    world.resolver(A);
    world.resolver(B);
    const first = new KeyMind("ada").update(10);
    const other = new KeyMind("ada").update(11);
    await world.publish(A, first);
    await world.publish(B, other);
    const resolved = await lookupOf([A, B]).resolve(first.address);
    expect(resolved.duplicitous).toBe(true);
    expect(resolved.did.didDocumentMetadata.duplicitous).toBe(true);
    // One resolver alone shows nothing of it: that is why a client trusts more than one.
    expect((await lookupOf([A]).resolve(first.address)).duplicitous).toBe(false);
  });
});

describe(`${clause("L1 9.6")} resolving a collective`, () => {
  async function club() {
    world.resolver(A);
    const [a, b, c] = ["a", "b", "c"].map((name) => new KeyMind(name)) as [
      KeyMind,
      KeyMind,
      KeyMind,
    ];
    for (const member of [a, b, c]) await world.publish(A, member);
    world.clock.at = at(110);
    const collective = new Collective("club", [a, b, c], 2, 5).update(20, [a, b]);
    expect(await world.publish(A, collective)).toBe(202);
    return { a, b, c, collective };
  }

  it("fetches the logs its own rests on, and verifies it with them", async () => {
    const { a, b, c, collective } = await club();
    world.clock.at = at(500);
    const before = world.asked.length;
    const lookup = lookupOf();
    const resolved = await lookup.resolve(collective.address);
    expect(resolved.log.entries).toHaveLength(2);
    expect(resolved.state.kind).toBe("collective");
    expect(resolved.did.didDocumentMetadata.members).toStrictEqual(
      [a, b, c].map((member) => member.address),
    );
    // One request for the collective and one for each member.
    expect(world.asked.slice(before)).toHaveLength(4);
    for (const member of [a, b, c]) expect(lookup.view.log(member.address).ok).toBe(true);
  });

  it("verifies it after a member has removed the key that signed, by the resolver's times", async () => {
    const { a, collective } = await club();
    a.update(300, { invocation: [{ key: a.invocation(1).publicKey }] });
    world.clock.at = at(400);
    await world.publish(A, a);
    world.clock.at = at(500);
    const resolved = await lookupOf().resolve(collective.address);
    expect(resolved.log.entries.map((entry) => entry.time)).toStrictEqual([at(110), at(110)]);
  });

  it("fetches no more logs for one mind than it was told to", async () => {
    const { collective } = await club();
    world.clock.at = at(500);
    expect(await refusal(() => lookupOf([A], { maxLogs: 3 }).resolve(collective.address))).toBe(
      "oip: too-large",
    );
    expect(
      (await lookupOf([A], { maxLogs: 4 }).resolve(collective.address)).log.entries,
    ).toHaveLength(2);
  });

  it("is refused if a member's log is held by no resolver", async () => {
    const { b, collective } = await club();
    world.clock.at = at(500);
    const real = world.fetch;
    // A resolver that has lost one member.
    world.put(B, (request) =>
      request.url.endsWith(mindId(b.address) ?? "")
        ? new Response(
            JSON.stringify({ type: "urn:oip:error:not-found", title: "Unknown", status: 404 }),
            {
              status: 404,
              headers: { "content-type": "application/problem+json" },
            },
          )
        : real(new Request(request.url.replace(B, A), request)),
    );
    expect(await refusal(() => lookupOf([B]).resolve(collective.address))).toBe("oip: not-found");
  });
});

describe(`${clause("L1 15.2")} the location record of a resolved mind`, () => {
  /** Publishes a mind's log with a location record. */
  async function located(mind: KeyMind, record: object): Promise<number> {
    const response = await world.fetch(
      new Request(`${A}/oip/v1/resolve/${mindId(mind.address) ?? ""}`, {
        method: "PUT",
        headers: { "content-type": MEDIA_TYPE },
        body: JSON.stringify({ ...bundleOf(mind), location: record }),
      }),
    );
    return response.status;
  }

  it("is the current one a resolver served, if it counts and is not stale", async () => {
    world.resolver(A);
    const ada = new KeyMind("ada");
    const location = ada.sign(locationBy(ada, 90));
    expect(await located(ada, location)).toBe(202);
    const lookup = lookupOf();
    const resolved = await lookup.resolve(ada.address);
    expect(resolved.location?.record).toStrictEqual(location);
    expect(resolved.location?.id).toBe(contentId(location));
    // Its time-to-live is 900 seconds from 90: at 991 it is stale, and a sender asks again.
    world.clock.at = at(990);
    expect((await lookup.resolve(ada.address)).location?.id).toBe(contentId(location));
    world.clock.at = at(991);
    expect((await lookup.resolve(ada.address)).location).toBeUndefined();
  });

  it("is none where what was served does not count for the mind", async () => {
    const ada = new KeyMind("ada");
    const eve = new KeyMind("eve");
    const genesis = contentId(ada.events[0]);
    // A location record signed by Eve in Ada's name, and one of Eve's own, served for Ada.
    const forged = eve.sign({ ...locationBy(ada, 90) }, { by: eve.operational() });
    for (const location of [forged, eve.sign(locationBy(eve, 90))]) {
      serving(A, () =>
        bundleOf(ada, {
          location: location as unknown as JsonObject,
          firstSeen: {
            [genesis]: T(1),
            [proofDigest(location.proof[0])]: T(95),
          },
        }),
      );
      expect((await lookupOf().resolve(ada.address)).location).toBeUndefined();
    }
  });

  it("is none where the resolver names no time for its proof, or it needs what this client lacks", async () => {
    const ada = new KeyMind("ada");
    const genesis = contentId(ada.events[0]);
    const own = ada.sign(locationBy(ada, 90));
    // Served without a time for its proof: there is no evidence of when it was signed.
    serving(A, () => bundleOf(ada, { location: own, firstSeen: { [genesis]: T(1) } }));
    expect((await lookupOf().resolve(ada.address)).location).toBeUndefined();
    // With the time, it is the mind's location.
    const timed = { [genesis]: T(1), [proofDigest(own.proof[0])]: T(95) };
    serving(A, () => bundleOf(ada, { location: own, firstSeen: timed }));
    expect((await lookupOf().resolve(ada.address)).location?.id).toBe(contentId(own));
    // One that depends on an extension this client does not implement may not be relied on (core 8.3).
    const extended = ada.sign({
      ...locationBy(ada, 90),
      ext: { "ext.example": { rule: "new" } },
      critical: ["ext.example"],
    });
    serving(A, () =>
      bundleOf(ada, {
        location: extended,
        firstSeen: { [genesis]: T(1), [proofDigest(extended.proof[0])]: T(95) },
      }),
    );
    expect((await lookupOf().resolve(ada.address)).location).toBeUndefined();
  });
});
