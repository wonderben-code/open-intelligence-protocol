// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The Indexer profile over the wire (Layer 1, Section 18): submission, the
 * capability query with its signed result, and brokered delivery where the
 * indexer offers it.
 */

import {
  compareDecimals,
  contentId,
  isContentId,
  isDecimal,
  isMindAddress,
  isTimestamp,
  type JsonObject,
  mindId,
  problemCode,
} from "@oip/core";

import type { WireAnswer, WireOptions } from "./client.ts";
import { describe, expectProblem, expectRefused, WireClient } from "./client.ts";
import { second, WireMind, word } from "./minds.ts";
import { expect, need, NotApplicable, Recorder, Skipped, type WireReport } from "./report.ts";
import { isObject, recordOf, same } from "./shapes.ts";
import { Verifier } from "./verifier.ts";

/** An inbox the suite can watch, for the packets an indexer forwards (Layer 1, 18.5). */
export interface WatchedInbox {
  /**
   * The base URL of an `https` endpoint (15.1) that the indexer can reach:
   * it posts to `{endpoint}/inbox`, which answers 202 with `{ "stored": true }`.
   */
  readonly endpoint: string;
  /** What has been posted to `{endpoint}/inbox` so far: each body, as JSON. */
  taken(): readonly unknown[] | Promise<readonly unknown[]>;
}

/** What the Indexer profile is given besides what every profile is. */
export interface IndexerOptions extends WireOptions {
  /**
   * Gets the `Bundle` of the indexer's own mind, by which its signatures are
   * judged. Unless given, it is asked of the indexer itself, at
   * `/.well-known/oip/mind/<mindId>`.
   */
  readonly bundle?: (address: string) => Promise<unknown>;
  /**
   * The base URL of the indexer's own endpoint, under its origin: packets
   * for brokered delivery are posted to `{endpoint}/inbox` (18.5). Unless
   * given, `/oip/v1` under the origin, as the reference indexer has it.
   */
  readonly endpoint?: string;
  /** An inbox the suite can watch. Without one, what the indexer forwards is not checked. */
  readonly inbox?: WatchedInbox;
}

const MINUTE = 60_000_000_000n;
const NOT_OFFERED = "the indexer takes no packets: it does not offer brokered delivery (18.5)";
const JSON_TYPE = "application/json";

/** One result of a `QueryResult`, read as 18.3 gives it. */
interface Found {
  readonly mind: string;
  readonly record: string;
}

/**
 * Runs the Indexer profile against an indexer. It submits a few minds of
 * its own with their profiles, so it is run against a deployment that may
 * list them. Each run uses words and tags of its own, so the records of one
 * run are not found by another.
 */
export async function indexerProfile(options: IndexerOptions): Promise<WireReport> {
  const client = new WireClient(options);
  const suite = new Recorder("indexer");
  const verifier = new Verifier();
  const started = client.now();
  const stamp = (): string => second(client.now());
  const fresh = (): WireMind => WireMind.create(client.random, stamp());
  /** A word of this run: nothing else an indexer lists has it. */
  const unique = (): string => `zq${word(client.random, 6)}`;

  const submit = (records: readonly unknown[]): Promise<WireAnswer> =>
    client.ask("POST", "/oip/v1/submit", { body: { records }, type: JSON_TYPE });
  const ask = (query: unknown): Promise<WireAnswer> =>
    client.ask("POST", "/oip/v1/query", { body: query, type: JSON_TYPE });

  /** A profile of a mind with one capability. */
  const profile = (mind: WireMind, text: string, tags: readonly string[], signer = mind) =>
    signer.sign({
      oip: "1",
      type: "Participant",
      author: mind.address,
      created: stamp(),
      name: `Conformance ${text}`,
      kind: "agent",
      summary: `A mind of the conformance suite: ${text}.`,
      capabilities: [{ id: "work", summary: `Does ${text}`, tags }],
    });

  // Three minds with a word in common, and tags that tell a prefix from what merely starts alike.
  const term = unique();
  const namespace = `x${word(client.random, 4)}`;
  const [ann, ben, cat] = [fresh(), fresh(), fresh()];
  const profiles = {
    ann: profile(ann, `${term} translation`, [`${namespace}:nlp/translation`, `${namespace}:en`]),
    ben: profile(ben, `${term} parsing`, [`${namespace}:nlp`]),
    cat: profile(cat, `${term} extraction`, [`${namespace}:nlpx`]),
  };
  const offer = ann.sign({
    oip: "1",
    type: "Offer",
    author: ann.address,
    created: stamp(),
    provides: `${term} translation of leases`,
    terms: { summary: "By the hour." },
  });
  const intent = ann.sign({
    oip: "1",
    type: "Intent",
    author: ann.address,
    created: stamp(),
    want: `${term} a notary`,
  });

  /**
   * The results of a query, each with the form 18.3 gives it.
   *
   * @throws Failed if the answer is not a `QueryResult` for the query.
   */
  const results = (answer: WireAnswer, query: unknown, when: string): Found[] => {
    const result = recordOf(answer, 200, "QueryResult", when);
    expect(isMindAddress(result["author"]), `${when}: the author is the indexer's address`);
    expect(isTimestamp(result["created"]), `${when}: created is a timestamp`);
    expect(same(result["query"], query), `${when}: the result carries the query it answers`);
    expect(Array.isArray(result["results"]), `${when}: results is an array`);
    return (result["results"] as unknown[]).map((found) => {
      expect(
        isObject(found) && isMindAddress(found["mind"]) && isContentId(found["record"]),
        `${when}: a result names a mind and the content ID of a record; got ${JSON.stringify(found)}`,
      );
      const { score, hints, capability } = found;
      expect(
        isDecimal(score) && compareDecimals(score, "0") !== -1 && compareDecimals(score, "1") !== 1,
        `${when}: a score is a decimal string from "0" to "1"; got ${JSON.stringify(score)}`,
      );
      expect(
        hints === undefined ||
          (Array.isArray(hints) && hints.every((hint) => typeof hint === "string")),
        `${when}: hints is an array of URLs; got ${JSON.stringify(hints)}`,
      );
      expect(
        capability === undefined || typeof capability === "string",
        `${when}: capability is the id of a capability; got ${JSON.stringify(capability)}`,
      );
      return { mind: found["mind"], record: found["record"] };
    });
  };
  /** Asks a query and gives its results. */
  const found = async (query: JsonObject, when: string): Promise<Found[]> =>
    results(await ask(query), query, when);
  const names = (list: readonly Found[], record: object): boolean =>
    list.some((entry) => entry.record === contentId(record));

  /**
   * Whether a record is signed by the indexer. A proof is judged by a log
   * obtained no earlier than the evidence for it (core 9.4), so the
   * indexer's own log is fetched for each record that is judged.
   *
   * @throws Skipped if the suite cannot get the log.
   * @throws Failed if the log does not verify.
   */
  const signedByIndexer = async (record: unknown, address: string): Promise<boolean> => {
    let bundle: unknown;
    try {
      bundle =
        options.bundle === undefined
          ? (await client.ask("GET", `/.well-known/oip/mind/${mindId(address) ?? ""}`)).json
          : await options.bundle(address);
    } catch (error) {
      throw new Skipped(
        `the suite could not get the indexer's own log: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!isObject(bundle) || bundle["mind"] !== address) {
      throw new Skipped(
        "the suite could not get the indexer's own log: it is not at the well-known path, and no other way was given",
      );
    }
    const now = client.now();
    expect(verifier.learns(bundle["log"], now), "the indexer's own log verifies");
    return verifier.signedBy(record, address, now);
  };

  const submitted = await suite.check(
    {
      id: "submit",
      clauses: ["L1 18.1"],
      title: "A submission of bundles, profiles, an Offer and an Intent is answered 202",
    },
    async () => {
      const records = [
        ann.bundle(),
        ben.bundle(),
        cat.bundle(),
        profiles.ann,
        profiles.ben,
        profiles.cat,
        offer,
        intent,
      ];
      const answer = await submit(records);
      expect(answer.status === 202, `a submission is answered 202; got ${describe(answer)}`);
      // The answer may say what became of each record. Here each is one an indexer can list.
      const body = isObject(answer.json) ? answer.json : {};
      if (body["refused"] !== undefined) {
        expect(
          Array.isArray(body["refused"]) &&
            body["refused"].every(
              (entry) =>
                isObject(entry) &&
                Number.isInteger(entry["index"]) &&
                problemCode(entry["type"]) !== undefined &&
                typeof entry["detail"] === "string",
            ),
          `each of refused is { "index", "type", "detail" }; got ${describe(answer)}`,
        );
      }
      if (body["taken"] !== undefined) {
        expect(
          Number.isInteger(body["taken"]) && (body["taken"] as number) >= 0,
          `taken is a count; got ${describe(answer)}`,
        );
      }
      return true as const;
    },
  );

  const query = { want: term };
  const answered = await suite.check(
    {
      id: "query",
      clauses: ["L1 18.1", "L1 18.3", "core 10.1"],
      title: "A capability query is answered with a QueryResult that carries the query",
    },
    async () => {
      need(submitted, "a submission the indexer took");
      const answer = await ask(query);
      results(answer, query, "a query for a word");
      return answer.json as JsonObject;
    },
  );

  const indexer = await suite.check(
    {
      id: "query-signed",
      clauses: ["L1 18.1", "L1 18.3"],
      title: "The QueryResult is signed by the indexer, as its own log shows",
    },
    async () => {
      const result = need(answered, "a QueryResult");
      const author = result["author"] as string;
      expect(
        await signedByIndexer(result, author),
        "the QueryResult has a proof by a valid operational key of its author",
      );
      return author;
    },
  );

  await suite.check(
    {
      id: "query-finds",
      clauses: ["L1 18.1", "L1 18.2"],
      title:
        "A query finds the profiles that were submitted, and profiles only unless it asks for more",
    },
    async () => {
      need(submitted, "a submission the indexer took");
      const list = await found(query, "a query for a word");
      for (const [name, record] of Object.entries(profiles)) {
        expect(names(list, record), `the profile of ${name}, which has the word, is found`);
      }
      expect(
        !names(list, offer) && !names(list, intent),
        "a query that names no kinds searches Participant records only",
      );
      const owner = list.find((entry) => entry.record === contentId(profiles.ann));
      expect(owner?.mind === ann.address, "a result names the mind whose record it is");
    },
  );

  await suite.check(
    {
      id: "query-kinds",
      clauses: ["L1 18.2"],
      title: "A query searches the kinds of record it names",
    },
    async () => {
      need(submitted, "a submission the indexer took");
      const offers = await found({ want: term, kinds: ["Offer"] }, "a query for Offers");
      expect(names(offers, offer), "the Offer that was submitted is found");
      expect(
        !names(offers, profiles.ann) && !names(offers, intent),
        "a query for Offers finds Offers only",
      );
      const intents = await found({ want: term, kinds: ["Intent"] }, "a query for Intents");
      expect(names(intents, intent), "the Intent that was submitted is found");
      expect(!names(intents, offer), "a query for Intents finds Intents only");
    },
  );

  await suite.check(
    {
      id: "query-tags",
      clauses: ["L1 18.2"],
      title: "A result matches every tag, and a tag ending in /* matches what begins with the rest",
    },
    async () => {
      need(submitted, "a submission the indexer took");
      const under = await found({ tags: [`${namespace}:nlp/*`] }, "a query for a tag prefix");
      expect(names(under, profiles.ann), `${namespace}:nlp/* matches ${namespace}:nlp/translation`);
      expect(!names(under, profiles.ben), `${namespace}:nlp/* does not match ${namespace}:nlp`);
      expect(!names(under, profiles.cat), `${namespace}:nlp/* does not match ${namespace}:nlpx`);
      const exact = await found({ tags: [`${namespace}:nlp`] }, "a query for a tag");
      expect(
        names(exact, profiles.ben) && !names(exact, profiles.ann) && !names(exact, profiles.cat),
        `${namespace}:nlp matches that tag and no other`,
      );
      const both = await found(
        { tags: [`${namespace}:nlp/translation`, `${namespace}:en`] },
        "a query for two tags",
      );
      expect(names(both, profiles.ann), "a record with both tags matches");
      const one = await found(
        { tags: [`${namespace}:nlp/translation`, `${namespace}:absent`] },
        "a query for a tag no record has",
      );
      expect(!names(one, profiles.ann), "a record with one of two tags does not match");
    },
  );

  await suite.check(
    {
      id: "query-verified",
      clauses: ["L1 18.1"],
      title: "A record that its author's own authority did not sign is not listed",
    },
    async () => {
      need(submitted, "a submission the indexer took");
      const other = unique();
      const [dan, mal, stranger] = [fresh(), fresh(), fresh()];
      const honest = profile(dan, `${other} auditing`, [`${namespace}:audit`]);
      const forged = profile(dan, `${other} forging`, [`${namespace}:audit`], mal);
      // Signed, by a mind whose log the indexer is never shown.
      const unknown = profile(stranger, `${other} lurking`, [`${namespace}:audit`]);
      const broken = {
        ...profile(mal, `${other} breaking`, [`${namespace}:audit`]),
        proof: honest.proof,
      };
      await submit([dan.bundle(), mal.bundle(), forged, unknown, broken, honest]);
      const list = await found(
        { want: other },
        "a query for the word of records that do not verify",
      );
      expect(names(list, honest), "the profile its author signed is found");
      expect(!names(list, forged), "a profile another mind signed is not listed");
      expect(
        !names(list, unknown),
        "a profile of a mind whose log the indexer does not hold is not listed",
      );
      expect(!names(list, broken), "a profile with the proof of another record is not listed");
    },
  );

  await suite.check(
    {
      id: "query-unchecked",
      clauses: ["L1 18.2"],
      title:
        "A query with constraints or evidence that the indexer cannot have checked gets no result",
    },
    async () => {
      need(submitted, "a submission the indexer took");
      // Names made for this run: no indexer weighs them.
      const made = `x${word(client.random, 6)}`;
      const constrained = await found(
        { want: term, constraints: { [made]: true } },
        "a query with a constraint nobody knows",
      );
      expect(
        constrained.length === 0,
        "no result is returned for a constraint that was not checked",
      );
      const evidenced = await found(
        { want: term, evidence: { [made]: 1 } },
        "a query that asks for evidence nobody knows",
      );
      expect(evidenced.length === 0, "no result is returned for evidence that was not checked");
    },
  );

  await suite.check(
    {
      id: "query-limit",
      clauses: ["L1 18.2", "core 10.2"],
      title: "A query gets at most limit results, and a limit over 100 is refused",
    },
    async () => {
      need(submitted, "a submission the indexer took");
      const one = await found({ want: term, limit: 1 }, "a query with a limit of 1");
      expect(one.length === 1, `three records match and one is returned; got ${one.length}`);
      expectProblem(await ask({ want: term, limit: 101 }), "invalid-record", "a limit of 101");
    },
  );

  await suite.check(
    {
      id: "malformed",
      clauses: ["L1 18.1", "L1 18.2", "core 10.2"],
      title: "What is no submission or no capability query is refused as an invalid record",
    },
    async () => {
      const post = (path: string, body: unknown): Promise<WireAnswer> =>
        client.ask("POST", path, { body, type: JSON_TYPE });
      expectProblem(await post("/oip/v1/query", '{"want":'), "invalid-record", "a query cut short");
      expectProblem(
        await post("/oip/v1/query", { want: 5 }),
        "invalid-record",
        "a query whose want is a number",
      );
      expectProblem(
        await post("/oip/v1/query", { want: "x".repeat(1025) }),
        "invalid-record",
        "a query whose want is longer than 1024 characters",
      );
      expectProblem(
        await post("/oip/v1/submit", '{"records":['),
        "invalid-record",
        "a submission cut short",
      );
      expectProblem(
        await post("/oip/v1/submit", { records: "none" }),
        "invalid-record",
        "a submission without records",
      );
    },
  );

  await brokerChecks(suite, client, {
    submitted,
    indexer,
    signedByIndexer,
    path: () => {
      const url = options.endpoint ?? `${client.origin}/oip/v1`;
      const path = client.pathOf(`${url}/inbox`);
      if (path === undefined) {
        throw new Skipped(`the suite asks one origin, ${client.origin}, and ${url} is at another`);
      }
      return path;
    },
    inbox: options.inbox,
    fresh,
    stamp,
    unique,
    submit,
    profile,
  });

  return suite.report(client.target, started, client.now());
}

/** Brokered delivery (18.5), which an indexer may offer. */
async function brokerChecks(
  suite: Recorder,
  client: WireClient,
  given: {
    readonly submitted: true | undefined;
    /** The indexer's address, once its signature on a result has been verified. */
    readonly indexer: string | undefined;
    /** Whether a record is signed by the indexer, judged by its log as it is now. */
    readonly signedByIndexer: (record: unknown, address: string) => Promise<boolean>;
    /** The path of the indexer's inbox. */
    readonly path: () => string;
    readonly inbox: WatchedInbox | undefined;
    readonly fresh: () => WireMind;
    readonly stamp: () => string;
    readonly unique: () => string;
    readonly submit: (records: readonly unknown[]) => Promise<WireAnswer>;
    readonly profile: (mind: WireMind, text: string, tags: readonly string[]) => object;
  },
): Promise<void> {
  const { fresh, stamp, unique } = given;
  const sender = fresh();
  const stranger = fresh();
  /** A packet to whoever matches a query. */
  const packet = (to: JsonObject) =>
    sender.sign({
      oip: "1",
      type: "Packet",
      from: sender.address,
      to,
      created: stamp(),
      expires: second(client.now() + 30n * MINUTE),
      nonce: word(client.random),
      purpose: { verb: "request" },
      content: { mediaType: "text/plain", body: `conformance ${word(client.random)}` },
    });
  const deliver = (record: unknown): Promise<WireAnswer> =>
    client.ask("POST", given.path(), { body: record });
  /** Whether an answer takes a packet as 18.5 says: 202 with `{ "stored": true }`. */
  const stored = (answer: WireAnswer): boolean =>
    answer.status === 202 && isObject(answer.json) && answer.json["stored"] === true;

  /** Whether the indexer takes packets at all. An indexer need not (18.5). */
  let offered = true;
  /**
   * What the checks of forwarding build on: an indexer that offers it.
   *
   * @throws NotApplicable if the indexer does not, and Skipped if the suite could not tell.
   */
  const offering = (): void => {
    if (!offered) throw new NotApplicable(NOT_OFFERED);
    need(brokers, "an indexer that offers brokered delivery");
  };

  const brokers = await suite.check(
    {
      id: "broker-not-listed",
      clauses: ["L1 18.5"],
      title: "A packet whose brokers do not list the indexer is refused",
    },
    async () => {
      need(given.submitted, "a submission the indexer took");
      const taken = await given.submit([sender.bundle()]);
      expect(taken.status === 202, `the sender's bundle is taken; got ${describe(taken)}`);
      const answer = await deliver(
        packet({ query: { want: unique() }, brokers: [stranger.address] }),
      );
      if (answer.status === 404 || answer.status === 405 || answer.status === 501) {
        offered = false;
        throw new NotApplicable(NOT_OFFERED);
      }
      expectRefused(answer, "a packet that names another broker and not the indexer");
      return true as const;
    },
  );

  // Three minds match a query; each is reached at the inbox the suite watches.
  const term = unique();
  const reached = [fresh(), fresh(), fresh()];
  const located = (mind: WireMind, endpoint: string) =>
    mind.bundle({
      location: mind.sign({
        oip: "1",
        type: "Location",
        author: mind.address,
        seq: 1,
        created: stamp(),
        ttl: 900,
        status: "active",
        endpoints: [{ binding: "https", url: endpoint, priority: 10 }],
      }),
    });
  /** The `Forwarded` records the watched inbox has for a packet. */
  const forwarded = async (inbox: WatchedInbox, id: string): Promise<JsonObject[]> =>
    (await inbox.taken()).filter(
      (record): record is JsonObject =>
        isObject(record) &&
        record["type"] === "Forwarded" &&
        isObject(record["packet"]) &&
        contentId(record["packet"]) === id,
    );
  /** Waits until the inbox has `count` records for a packet, or the time an answer may take is over. */
  const arrived = async (inbox: WatchedInbox, id: string, count: number): Promise<JsonObject[]> => {
    const until = Date.now() + client.timeoutMs;
    for (;;) {
      const list = await forwarded(inbox, id);
      if (list.length >= count || Date.now() > until) return list;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  };
  const watched = (): WatchedInbox => {
    if (given.inbox === undefined) {
      throw new Skipped(
        "the suite was given no inbox to watch, so it cannot see what is forwarded",
      );
    }
    return given.inbox;
  };

  const sent = packet({ query: { want: term }, maxFanout: 2 });
  const first = await suite.check(
    {
      id: "broker-forwards",
      clauses: ["L1 18.5"],
      title:
        "A packet is forwarded unchanged to matching minds, each in a Forwarded record the broker signs",
    },
    async () => {
      offering();
      const indexer = need(given.indexer, "the indexer's address and log");
      const inbox = watched();
      const records: unknown[] = [];
      for (const [at, mind] of reached.entries()) {
        records.push(located(mind, inbox.endpoint), given.profile(mind, `${term} reach ${at}`, []));
      }
      // The sender matches its own query, and is not sent its own packet.
      records.push(located(sender, inbox.endpoint), given.profile(sender, `${term} sending`, []));
      const taken = await given.submit(records);
      expect(taken.status === 202, `the minds to reach are taken; got ${describe(taken)}`);
      const answer = await deliver(sent);
      expect(
        stored(answer),
        `a packet to a query is answered 202 with { "stored": true }; got ${describe(answer)}`,
      );
      const forwarding = (answer.json as JsonObject)["forwarding"];
      expect(
        forwarding === undefined || (Number.isInteger(forwarding) && (forwarding as number) <= 2),
        `forwarding is the number of minds the packet goes to, at most maxFanout; got ${JSON.stringify(forwarding)}`,
      );
      const list = await arrived(inbox, contentId(sent), 2);
      expect(
        list.length >= 1,
        "a Forwarded record with the packet arrives at a matching mind's inbox",
      );
      for (const record of list) {
        expect(
          record["oip"] === "1" && record["broker"] === indexer,
          "a Forwarded record names its broker",
        );
        expect(same(record["packet"], sent), "the packet is forwarded unchanged");
        expect(isTimestamp(record["created"]), "a Forwarded record has a created time");
        expect(
          reached.some((mind) => mind.address === record["to"]),
          `a Forwarded record is to a mind that matches, and not to the sender; got ${JSON.stringify(record["to"])}`,
        );
        expect(
          await given.signedByIndexer(record, indexer),
          "a Forwarded record is signed by the broker",
        );
      }
      return { answer, inbox };
    },
  );

  await suite.check(
    {
      id: "broker-fanout",
      clauses: ["L1 18.5", "L1 12.1"],
      title: "A packet goes to at most maxFanout minds, each once",
    },
    async () => {
      offering();
      const { inbox } = need(first, "a packet the indexer forwarded");
      // Whatever is still on its way has time to arrive.
      await new Promise((resolve) => setTimeout(resolve, 300));
      const list = await forwarded(inbox, contentId(sent));
      const to = list.map((record) => record["to"]);
      expect(
        list.length <= 2,
        `three minds match and maxFanout is 2; the packet went to ${list.length}`,
      );
      expect(new Set(to).size === to.length, "no mind is sent the packet twice");
    },
  );

  await suite.check(
    {
      id: "broker-once",
      clauses: ["L1 18.5"],
      title: "The same packet again is answered as before and forwarded no second time",
    },
    async () => {
      offering();
      const { answer, inbox } = need(first, "a packet the indexer forwarded");
      const before = (await forwarded(inbox, contentId(sent))).length;
      const again = await deliver(sent);
      expect(
        again.status === answer.status && same(again.json, answer.json),
        `the same packet is answered as before; got ${describe(again)} after ${describe(answer)}`,
      );
      await new Promise((resolve) => setTimeout(resolve, 300));
      const after = (await forwarded(inbox, contentId(sent))).length;
      expect(after === before, `the packet is forwarded once; ${after - before} more arrived`);
    },
  );
}
