// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The Resolver profile over the wire (Layer 1, Section 17): the resolver
 * API, first-seen witnessing served as `firstSeen`, live evaluation of new
 * events, and duplicity evidence.
 */

import { contentId, type JsonObject, proofDigest, withProofs } from "@oip/core";

import { authenticationChecks } from "./authentication.ts";
import type { WireAnswer, WireStream, WireOptions } from "./client.ts";
import { describe, expectProblem, expectStatus, WireClient } from "./client.ts";
import { second, WireMind, word } from "./minds.ts";
import { expect, need, NotApplicable, present, Recorder, type WireReport } from "./report.ts";
import { expectLog, idOf, isObject, recordOf, same, seenTime, verifies } from "./shapes.ts";

/** What the stream told of: its cursor, the mind, and the content ID of the record. */
interface Told {
  readonly cursor: string;
  readonly mind: string;
  readonly record: string;
}

/**
 * Runs the Resolver profile against a resolver. It publishes a few minds of
 * its own, so it is run against a deployment that may hold them.
 */
export async function resolverProfile(options: WireOptions): Promise<WireReport> {
  const client = new WireClient(options);
  const suite = new Recorder("resolver");
  const started = client.now();
  const stamp = (): string => second(client.now());
  const fresh = (): WireMind => WireMind.create(client.random, stamp());
  const path = (id: string): string => `/oip/v1/resolve/${id}`;
  /**
   * Publishes a bundle of a mind, signed by the mind: a resolver that asks for no signature
   * ignores it. Where the resolver will not take the whole log, `signer` is the mind as it was
   * at an event that it will take, since the signature is judged by the log as far as it
   * verified (17.3).
   */
  const publish = (
    mind: WireMind,
    bundle: JsonObject = mind.bundle(),
    signer: WireMind = mind,
  ): Promise<WireAnswer> => client.ask("PUT", path(mind.id), { body: bundle, signedBy: signer });
  /** The bundle the resolver serves for a mind. */
  const resolved = async (mind: WireMind, when: string): Promise<JsonObject> => {
    const bundle = recordOf(await client.ask("GET", path(mind.id)), 200, "Bundle", when);
    expect(bundle["mind"] === mind.address, `${when}: the bundle is of ${mind.address}`);
    return bundle;
  };

  await suite.check(
    {
      id: "unknown-mind",
      clauses: ["L1 17.1"],
      title: "A mind the resolver does not know is answered 404",
    },
    async () => {
      expectProblem(await client.ask("GET", path(fresh().id)), "not-found", "an unknown mind");
    },
  );

  await suite.check(
    { id: "not-a-mind", clauses: ["L1 17.1"], title: "A path that names no mind is answered 404" },
    async () => {
      expectProblem(await client.ask("GET", path("not-a-mind")), "not-found", "what is no mind ID");
    },
  );

  // Ada: published, published again, updated, and given a location record.
  const ada = fresh();
  let sent: [bigint, bigint] = [client.now(), client.now()];
  const published = await suite.check(
    { id: "publish", clauses: ["L1 17.1"], title: "A bundle is published and answered 202" },
    async () => {
      sent = [client.now(), client.now()];
      expectStatus(await publish(ada), 202, "a mind's first bundle");
      sent = [sent[0], client.now()];
      return true;
    },
  );

  const first = await suite.check(
    {
      id: "resolve",
      clauses: ["L1 17.1", "L1 13.1", "core 10.1"],
      title: "A published mind resolves to a Bundle with its log",
    },
    async () => {
      need(published, "the publication of a bundle");
      const bundle = await resolved(ada, "a published mind");
      expectLog(bundle["log"], ada.events, "a published mind");
      expect(verifies(bundle["log"], client.now()), "the log that is served verifies");
      return bundle;
    },
  );

  const genesisSeen = await suite.check(
    {
      id: "first-seen",
      clauses: ["L1 17.1", "L1 17.2", "L1 13.1"],
      title: "The bundle gives the time each event was first seen",
    },
    () => seenTime(need(first, "a resolved bundle")["firstSeen"], ada.id, sent, "a published mind"),
  );

  await suite.check(
    {
      id: "first-seen-kept",
      clauses: ["L1 17.2"],
      title: "An event published again keeps the time it was first seen",
    },
    async () => {
      const before = need(genesisSeen, "a first-seen time");
      expectStatus(await publish(ada), 202, "the same bundle again");
      const bundle = await resolved(ada, "a mind published twice");
      const now = seenTime(bundle["firstSeen"], ada.id, sent, "a mind published twice");
      expect(
        now === before,
        "the time an event was first seen does not change when it is seen again",
      );
    },
  );

  await suite.check(
    {
      id: "update",
      clauses: ["L1 17.1", "L1 17.2"],
      title: "A later event is merged into the log held",
    },
    async () => {
      const before = need(genesisSeen, "a first-seen time");
      const from = client.now();
      const update = ada.update(stamp());
      expectStatus(await publish(ada), 202, "a bundle with one more event");
      const bundle = await resolved(ada, "an updated mind");
      expectLog(bundle["log"], ada.events, "an updated mind");
      const span = [from, client.now()] as const;
      expect(
        seenTime(bundle["firstSeen"], ada.id, sent, "an updated mind") === before,
        "the genesis keeps the time it was first seen",
      );
      seenTime(bundle["firstSeen"], contentId(update), span, "an updated mind");
    },
  );

  const location = (author: WireMind, signer: WireMind = author) =>
    signer.sign({
      oip: "1",
      type: "Location",
      author: author.address,
      seq: 1,
      created: stamp(),
      ttl: 900,
      status: "active",
      endpoints: [{ binding: "https", url: "https://mind.invalid/oip", priority: 10 }],
    });

  const located = await suite.check(
    {
      id: "location",
      clauses: ["L1 17.1", "L1 17.2", "L1 13.1"],
      title: "A mind's location record is served, with the time its proof was first seen",
    },
    async () => {
      need(published, "the publication of a bundle");
      const record = location(ada);
      const from = client.now();
      expectStatus(
        await publish(ada, ada.bundle({ location: record })),
        202,
        "a bundle with a location",
      );
      const bundle = await resolved(ada, "a mind with a location");
      expect(same(bundle["location"], record), "the bundle carries the location record as signed");
      const digest = proofDigest(record.proof[0]);
      seenTime(bundle["firstSeen"], digest, [from, client.now()], "a mind with a location");
      return record;
    },
  );

  await suite.check(
    {
      id: "location-of-another",
      clauses: ["L1 17.2", "L1 15.1"],
      title: "A location record that the mind's own authority did not sign is not served",
    },
    async () => {
      const mind = fresh();
      const other = fresh();
      expectStatus(await publish(other), 202, "a second mind");
      expectStatus(await publish(mind), 202, "a mind without a location");
      const forged = location(mind, other);
      // Whatever the answer, the record is not the mind's.
      await publish(mind, mind.bundle({ location: forged }));
      const bundle = await resolved(mind, "a mind whose location another signed");
      expect(bundle["location"] === undefined, "no location record is served for the mind");
      const digest = proofDigest(forged.proof[0]);
      expect(
        !isObject(bundle["firstSeen"]) || !Object.hasOwn(bundle["firstSeen"], digest),
        "no first-seen time is served for the proof of a record that is not stored",
      );
    },
  );

  // Dan: an event whose proof does not verify, and what verified before it.
  await suite.check(
    {
      id: "invalid-event",
      clauses: ["L1 17.2", "core 10.2"],
      title: "An event that does not verify is refused, and what verified before it is merged",
    },
    async () => {
      const mind = fresh();
      const one = mind.update(stamp());
      const two = mind.update(stamp());
      // The signature of another event: well formed, and not this event's.
      const forged = {
        ...two,
        proof: [{ ...present(two.proof[0]), proofValue: present(one.proof[0]).proofValue }],
      };
      const answer = await publish(
        mind,
        mind.bundle({ log: [mind.genesis, one, forged] }),
        mind.branch(2),
      );
      expectProblem(
        answer,
        "invalid-proof",
        "a log whose third event has another event's signature",
      );
      const bundle = await resolved(mind, "a log with an invalid event");
      expectLog(bundle["log"], mind.events.slice(0, 2), "a log with an invalid event");
      // The genuine event is not kept out by the copy that did not verify.
      expectStatus(await publish(mind), 202, "the genuine third event");
      expectLog(
        (await resolved(mind, "the genuine log"))["log"],
        mind.events,
        "after an invalid copy of an event",
      );
    },
  );

  await suite.check(
    {
      id: "critical-extension",
      clauses: ["L1 17.2", "core 8.3"],
      title:
        "An event with a critical extension the resolver cannot know is refused as unsupported",
    },
    async () => {
      const mind = fresh();
      // A namespace made for this run: no implementation understands it.
      const namespace = `invalid.oip-conformance.x${word(client.random)}`;
      mind.update(stamp(), {
        ext: { [namespace]: { note: "conformance" } },
        critical: [namespace],
      });
      expectProblem(
        await publish(mind, mind.bundle(), mind.branch(1)),
        "unsupported-critical",
        "an event with an unknown critical extension",
      );
      const bundle = await resolved(mind, "a log with an event that cannot be read");
      expectLog(bundle["log"], mind.events.slice(0, 1), "a log with an event that cannot be read");
    },
  );

  await suite.check(
    {
      id: "another-minds-bundle",
      clauses: ["L1 17.1"],
      title: "A bundle published under another mind's ID is refused as an invalid record",
    },
    async () => {
      need(published, "the publication of a bundle");
      const other = fresh();
      const answer = await client.ask("PUT", path(ada.id), {
        body: other.bundle(),
        signedBy: other,
      });
      expectProblem(answer, "invalid-record", "a bundle of one mind under the ID of another");
    },
  );

  await suite.check(
    {
      id: "counting-proofs",
      clauses: ["L1 17.2"],
      title: "A proof that cannot count for an event is not served with it",
    },
    async () => {
      const mind = fresh();
      const stray = fresh();
      const { genesis } = mind;
      // A proof whose signature verifies, by a control key the event does not reveal.
      const shown = withProofs(genesis, [...genesis.proof, stray.strayProof(genesis)]);
      await publish(mind, mind.bundle({ log: [shown] }));
      const answer = await client.ask("GET", path(mind.id));
      // A resolver may refuse the bundle outright. One that takes it serves the proofs that count.
      if (answer.status === 404) return;
      const bundle = recordOf(
        answer,
        200,
        "Bundle",
        "an event shown with a proof that cannot count",
      );
      const served = Array.isArray(bundle["log"]) ? (bundle["log"][0] as unknown) : undefined;
      expect(
        same(served, genesis),
        `the genesis is served with the proof that counts and no other; got ${JSON.stringify(
          isObject(served) ? served["proof"] : served,
        )}`,
      );
    },
  );

  // Fay: two histories from one position.
  const fay = fresh();
  fay.update(stamp());
  const rival = fay.branch(1);
  rival.update(stamp(), { alsoKnownAs: [`https://rival.invalid/${word(client.random)}`] });
  rival.update(stamp());
  const duplicitous = await suite.check(
    {
      id: "duplicity",
      clauses: ["L1 17.1", "L1 7.1"],
      title: "A second valid event at a position the resolver holds is answered 409 duplicity",
    },
    async () => {
      expectStatus(await publish(fay), 202, "a mind's first history");
      expectProblem(await publish(rival), "duplicity", "a second history from the same position");
      return true;
    },
  );

  await suite.check(
    {
      id: "first-seen-wins",
      clauses: ["L1 17.1", "L1 17.2"],
      title:
        "The log served is the first valid event seen at each position, not the longer history",
    },
    async () => {
      need(duplicitous, "the publication of two histories");
      const bundle = await resolved(fay, "a duplicitous mind");
      expectLog(bundle["log"], fay.events, "a duplicitous mind");
    },
  );

  await suite.check(
    {
      id: "duplicity-evidence",
      clauses: ["L1 17.1", "L1 7.3"],
      title: "The two events are served as DuplicityEvidence",
    },
    async () => {
      need(duplicitous, "the publication of two histories");
      const answer = await client.ask("GET", `/oip/v1/duplicity/${fay.id}`);
      const evidence = recordOf(
        answer,
        200,
        "DuplicityEvidence",
        "the evidence for a duplicitous mind",
      );
      expect(evidence["mind"] === fay.address, "the evidence is of the mind asked after");
      const pairs = Array.isArray(evidence["pairs"]) ? (evidence["pairs"] as unknown[]) : [];
      const wanted = [fay.events[1], rival.events[1]];
      expect(
        pairs.some(
          (pair) =>
            Array.isArray(pair) &&
            pair.length === 2 &&
            (same(pair, wanted) || same(pair, [wanted[1], wanted[0]])),
        ),
        `a pair is the two events at position 1, each as signed; got ${describe(answer)}`,
      );
    },
  );

  await streamChecks(suite, client, {
    told: [
      ...ada.events.map((event) => ({ mind: ada.address, record: contentId(event) })),
      ...(located === undefined ? [] : [{ mind: ada.address, record: contentId(located) }]),
    ],
    publish: async () => {
      const mind = fresh();
      expectStatus(await publish(mind), 202, "a new mind while a stream is open");
      return { mind: mind.address, record: mind.id };
    },
  });

  // 17.3: a resolver may ask for signed publication. One that does is held to 13.3.
  const required = await suite.check(
    {
      id: "publication-unsigned",
      clauses: ["L1 17.3", "L1 13.3"],
      title: "A resolver that requires authenticated publication refuses an unsigned bundle",
    },
    async () => {
      const mind = fresh();
      const answer = await client.ask("PUT", path(mind.id), { body: mind.bundle() });
      if (answer.status === 202) {
        throw new NotApplicable(
          "the resolver takes unsigned bundles: it does not require authentication (17.3)",
        );
      }
      expectProblem(answer, "unauthorised", "an unsigned bundle");
      return true;
    },
  );
  if (required === true) {
    await authenticationChecks(suite, client, {
      name: "publication",
      what: "Publication",
      clause: "L1 17.3",
      request: () => {
        const mind = fresh();
        return { method: "PUT", path: path(mind.id), body: mind.bundle(), signer: mind };
      },
      taken: (answer) => answer.status === 202,
      withBody: true,
      // Signed by one mind, the bundle of another: the signer's log is not in the bundle.
      stranger: fresh(),
    });
  }

  await malformedChecks(suite, client, fresh);

  return suite.report(client.target, started, client.now());
}

/** One event of the stream, read as 17.1 gives it. */
function toldBy(event: { id: string | undefined; data: string }): Told {
  let data: unknown;
  try {
    data = JSON.parse(event.data) as unknown;
  } catch {
    data = undefined;
  }
  expect(
    isObject(data),
    `an event of the stream carries a JSON object; got ${event.data.slice(0, 200)}`,
  );
  const { cursor, mind, record } = data;
  expect(
    typeof cursor === "string" && /^[0-9]+$/u.test(cursor),
    `a cursor is a string of decimal digits; got ${JSON.stringify(cursor)}`,
  );
  expect(
    event.id === cursor,
    `an event's id is its cursor; got id ${String(event.id)} for ${cursor}`,
  );
  const id = idOf(record);
  expect(typeof mind === "string" && id !== undefined, "an event carries a mind and a record");
  return { cursor, mind, record: id };
}

/** Whether one cursor is after another: cursors are decimal numbers of any length. */
function after(one: string, other: string): boolean {
  return BigInt(one) > BigInt(other);
}

/** The stream of 17.1: what it tells, from where, and that it tells of what is new as it comes. */
async function streamChecks(
  suite: Recorder,
  client: WireClient,
  wanted: {
    /** What the suite published that the stream must tell of. */
    readonly told: readonly { mind: string; record: string }[];
    /** Publishes a new mind and says what the stream is to tell of it. */
    readonly publish: () => Promise<{ mind: string; record: string }>;
  },
): Promise<void> {
  const key = (told: { mind: string; record: string }): string => `${told.mind} ${told.record}`;
  /** Reads a stream until it has told of everything in `until`, and then until it is quiet. */
  const read = async (stream: WireStream, until: readonly string[]): Promise<Told[]> => {
    const all: Told[] = [];
    const missing = new Set(until);
    for (;;) {
      const event = await stream.next(missing.size === 0 ? 300 : client.timeoutMs);
      if (event === undefined) break;
      const told = toldBy(event);
      all.push(told);
      missing.delete(key(told));
    }
    expect(
      missing.size === 0,
      `the stream tells of each identity event and location record stored; it did not tell of ${[...missing].join("; ")}`,
    );
    return all;
  };

  const everything = await suite.check(
    {
      id: "stream",
      clauses: ["L1 17.1"],
      title:
        "The stream tells of each identity event and location record once, with rising cursors",
    },
    async () => {
      const stream = await client.stream("/oip/v1/stream");
      try {
        expect(stream.status === 200, `the stream is answered 200; got ${stream.status}`);
        const type = stream.headers.get("content-type") ?? "";
        expect(
          type.startsWith("text/event-stream"),
          `the stream is text/event-stream; got "${type}"`,
        );
        const all = await read(stream, wanted.told.map(key));
        for (let at = 1; at < all.length; at++) {
          const [earlier, later] = [present(all[at - 1]), present(all[at])];
          expect(
            after(later.cursor, earlier.cursor),
            `cursors rise; got ${earlier.cursor} then ${later.cursor}`,
          );
        }
        const keys = all.map(key);
        const twice = keys.find((told, at) => keys.indexOf(told) !== at);
        expect(
          twice === undefined,
          `each record is told of once; ${twice ?? ""} was told of twice`,
        );
        return all;
      } finally {
        stream.close();
      }
    },
  );

  for (const how of ["since", "Last-Event-ID"] as const) {
    await suite.check(
      {
        id: how === "since" ? "stream-since" : "stream-last-event-id",
        clauses: ["L1 17.1"],
        title: `A stream opened with a cursor in ${how} starts after it`,
      },
      async () => {
        const all = need(everything, "a first reading of the stream");
        // The cursor before the last thing the suite published: one event, at least, follows it.
        const last = wanted.told.at(-1);
        const at = all.findIndex((told) => last !== undefined && key(told) === key(last));
        expect(at > 0, "the stream told of what the suite published after something else");
        const from = present(all[at - 1]).cursor;
        const next = present(all[at]);
        const stream =
          how === "since"
            ? await client.stream(`/oip/v1/stream?since=${from}`)
            : await client.stream("/oip/v1/stream", { "last-event-id": from });
        try {
          const event = await stream.next();
          expect(event !== undefined, `a stream from cursor ${from} tells of what came after it`);
          const told = toldBy(event);
          expect(
            told.cursor === next.cursor && key(told) === key(next),
            `after cursor ${from} comes cursor ${next.cursor}; got ${told.cursor}`,
          );
        } finally {
          stream.close();
        }
      },
    );
  }

  await suite.check(
    {
      id: "stream-live",
      clauses: ["L1 17.1", "L1 17.2"],
      title: "An open stream tells of a new event when the resolver stores it",
    },
    async () => {
      const all = need(everything, "a first reading of the stream");
      const from = present(all.at(-1)).cursor;
      const stream = await client.stream(`/oip/v1/stream?since=${from}`);
      try {
        // Whatever others published meanwhile comes first. Then the stream waits, open.
        while ((await stream.next(300)) !== undefined);
        const made = await wanted.publish();
        for (;;) {
          const event = await stream.next();
          expect(event !== undefined, "the open stream tells of a mind published while it is open");
          if (key(toldBy(event)) === key(made)) break;
        }
      } finally {
        stream.close();
      }
    },
  );
}

/** What is not a bundle a resolver can take, and the problem it is answered with (core 10.2). */
async function malformedChecks(
  suite: Recorder,
  client: WireClient,
  fresh: () => WireMind,
): Promise<void> {
  const put = (mind: WireMind, body: unknown): Promise<WireAnswer> =>
    client.ask("PUT", `/oip/v1/resolve/${mind.id}`, { body, signedBy: mind });

  await suite.check(
    {
      id: "malformed-json",
      clauses: ["core 10.2", "core 1.1"],
      title: "A body that is not JSON is refused as an invalid record",
    },
    async () => {
      expectProblem(
        await put(fresh(), '{"oip":"1","type":"Bundle",'),
        "invalid-record",
        "a body cut short",
      );
    },
  );

  await suite.check(
    {
      id: "not-a-bundle",
      clauses: ["core 10.2", "L1 17.1"],
      title: "A record that is not a Bundle is refused as an invalid record",
    },
    async () => {
      const mind = fresh();
      const record = mind.sign(
        { oip: "1", type: "Hello", author: mind.address, created: second(client.now()) },
        {
          challenge: word(client.random, 16),
          domain: client.origin,
        },
      );
      expectProblem(
        await put(mind, record),
        "invalid-record",
        "a Hello where a Bundle is published",
      );
    },
  );

  await suite.check(
    {
      id: "fraction",
      clauses: ["core 1.2", "core 10.2"],
      title: "A bundle with a number that is not an integer is refused as an invalid record",
    },
    async () => {
      const mind = fresh();
      const text = JSON.stringify(mind.bundle()).replace(/\}$/u, ',"weight":1.5}');
      expectProblem(await put(mind, text), "invalid-record", "a bundle with the number 1.5 in it");
    },
  );

  await suite.check(
    {
      id: "duplicate-names",
      clauses: ["core 1.1"],
      level: "SHOULD",
      title: "A bundle with a member name twice is refused as an invalid record",
    },
    async () => {
      const mind = fresh();
      const text = JSON.stringify(mind.bundle()).replace(
        /\}$/u,
        `,"mind":${JSON.stringify(mind.address)}}`,
      );
      expectProblem(
        await put(mind, text),
        "invalid-record",
        "a bundle with two members named mind",
      );
    },
  );

  await suite.check(
    {
      id: "too-deep",
      clauses: ["core 1.9", "core 10.2"],
      title: "A bundle that nests more than 64 deep is refused as an invalid record",
    },
    async () => {
      const mind = fresh();
      // The bundle is at depth 1, so 64 arrays inside it reach depth 65.
      const nest = `${"[".repeat(64)}${"]".repeat(64)}`;
      const text = JSON.stringify(mind.bundle()).replace(/\}$/u, `,"nest":${nest}}`);
      expectProblem(await put(mind, text), "invalid-record", "a bundle nested 65 deep");
    },
  );

  await suite.check(
    {
      id: "too-large",
      clauses: ["core 1.6", "core 10.2", "L1 19"],
      title: "A bundle that is over 1 MiB without its records is refused as too large",
    },
    async () => {
      const mind = fresh();
      const bundle = { ...mind.bundle(), padding: "x".repeat(1024 * 1024 + 1) };
      expectProblem(
        await put(mind, bundle),
        "too-large",
        "a bundle of more than 1 MiB besides its records",
      );
    },
  );
}
