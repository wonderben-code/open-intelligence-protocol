// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Differential testing of the Mind Network against the independent Python
 * checker (M4): feeds and checkpoints, packets as a receiver judges them,
 * the chains of a session, acknowledgements, authentication, locations and
 * profiles.
 *
 * A case starts from records that test minds made rightly, and then things
 * are done to them: an entry forked, dropped, misplaced or signed by a
 * stranger, a date moved across a limit, a packet sent to someone else or
 * forwarded by a broker it does not list, a link of a chain given twice or
 * out of order. Both implementations decide every case completely, so the
 * rule is "same": the same yes or no, and the same account of what was found.
 */

import { contentId, proofDigest } from "@oip/core";
import { checkpointRoot } from "@oip/net";
import { Collective, intentBy, KeyMind, locationBy, type Mind, T } from "@oip/testkit/minds";
import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  type ChainReading,
  type JsonObject,
  loadVectors,
  type NetworkAnswer,
  type NetworkCase,
  PythonJudge,
  pythonJudgeUnavailable,
  referenceAdapter,
  type Verdict,
  viewFor,
} from "../src/index.ts";

const unavailable = pythonJudgeUnavailable();
const required = process.env["OIP_REQUIRE_PYTHON"] !== undefined;
// A short campaign with the ordinary tests; `pnpm run ci` and the nightly job set more.
const RUNS = Number(process.env["OIP_DIFFERENTIAL_NETWORK"] ?? 100);
// The limit is for a test that hangs, not for one that is slow: a machine busy with other
// work takes several times as long as an idle one.
const TIMEOUT = Math.max(480_000, RUNS * 1500);
const measured = process.env["OIP_MUTATION"] !== undefined;

const vectors = loadVectors();

type Signed = JsonObject & { proof: JsonObject[] };

// ---------------------------------------------------------------- minds

const ann = new KeyMind("net/ann");
const bo = new KeyMind("net/bo");
const cy = new KeyMind("net/cy");
/** A broker. */
const ian = new KeyMind("net/ian");
/**
 * Dee replaced her first operational key at 400, and declared it compromised
 * since 300: what that key signed before 300 stands, and nothing it signed
 * from then on.
 */
const dee = new KeyMind("net/dee");
dee.update(400, {
  keys: [{ key: dee.operational(1).publicKey }],
  revoked: [{ key: dee.operational(0).publicKey, compromisedSince: T(300) }],
});
/** Fay is a person, where the others are agents. */
const fay = new KeyMind("net/fay", 0, { kind: "person" });

/** A collective of Ann and Bo, which signs by the two of them. */
const club = new Collective("net/club", [ann, bo], 2, 5);

const MINDS = [ann, bo, cy, ian, dee, fay, club];
const LOGS = MINDS.map((mind) => mind.events);

/** How a mind signs: with which key, pinned to which event of its log, and when. */
interface Signing {
  readonly key?: number;
  readonly position?: number;
  readonly created?: string;
}

/** Dee's first key, pinned to her genesis, and her second, pinned to her update. */
const DEE_FIRST: Signing = { key: 0, position: 0 };
const DEE_SECOND: Signing = { key: 1, position: 1 };

const idOf = (record: object): string => contentId(record);

/** The same record with the signature of its first proof changed, so that the proof does not verify. */
function bent<T extends Signed>(record: T): T {
  const [first, ...rest] = record.proof;
  const value = String(first?.["proofValue"]);
  const last = value.at(-1) === "2" ? "3" : "2";
  return { ...record, proof: [{ ...first, proofValue: value.slice(0, -1) + last }, ...rest] };
}

/** A record without its proofs. */
function unsigned(record: Signed): JsonObject {
  const { proof: _, ...bare } = record;
  return bare;
}

/** A pick among choices by an index a generator made, whatever its size. */
const pick = <T>(choices: readonly T[], index: number): T => choices[index % choices.length] as T;

/** The values in an order a generator chose. */
function shuffled<T>(values: readonly T[], keys: readonly number[]): T[] {
  return values
    .map((value, index) => ({ value, key: keys[index % Math.max(keys.length, 1)] ?? 0, index }))
    .sort((a, b) => a.key - b.key || a.index - b.index)
    .map(({ value }) => value);
}

const ORDER = fc.array(fc.integer({ min: 0, max: 50 }), { minLength: 1, maxLength: 12 });

// ---------------------------------------------------------------- feeds

/** A record a feed publishes. */
const published = (author: Mind, n: number): Signed =>
  author.sign(intentBy(author, n, { want: `Thing ${n}.` }));

/** An entry of a mind's feed at `seq`, after `prev`, made at `seconds`. */
function entryOf(
  author: Mind,
  seq: number,
  prev: object | undefined,
  seconds: number,
  signing: Signing = {},
  object: Signed = published(author, seq),
  signer: Mind = author,
): Signed {
  const entry = {
    oip: "1",
    type: "Entry",
    author: author.address,
    seq,
    ...(prev === undefined ? {} : { prev: idOf(prev) }),
    created: T(seconds),
    object: idOf(object),
    objectType: String(object["type"]),
    proofs: object.proof.map((proof) => proofDigest(proof)),
  };
  // A stranger signs with its own key and names itself, whatever the entry says of its author.
  return signer.sign(entry, signing);
}

/** What is done to a feed that was made rightly. */
type FeedTwist =
  | "fork"
  | "misplace"
  | "first with a prev"
  | "stranger"
  | "drop"
  | "copy"
  | "bent copy"
  | "junk"
  | "another's entry";

const FEED_TWISTS: readonly FeedTwist[] = [
  "fork",
  "misplace",
  "first with a prev",
  "stranger",
  "drop",
  "copy",
  "bent copy",
  "junk",
  "another's entry",
];

/** A feed of `length` entries by a mind, each made 10 seconds after the one before. */
function feedOf(author: Mind, length: number, start = 10, signing: Signing = {}): Signed[] {
  const entries: Signed[] = [];
  for (let seq = 0; seq < length; seq++) {
    entries.push(entryOf(author, seq, entries[seq - 1], start + seq * 10, signing));
  }
  return entries;
}

/** The values a verifier holds of a feed after the twists. */
function twistedFeed(
  author: Mind,
  honest: readonly Signed[],
  twists: readonly (readonly [FeedTwist, number])[],
  signing: Signing = {},
): unknown[] {
  const values: unknown[] = [...honest];
  for (const [twist, n] of twists) {
    const at = n % honest.length;
    const target = honest[at]!;
    const before = honest[at - 1];
    /** Puts something in the entry's place, if the entry is still there. */
    const replace = (...by: unknown[]): void => {
      if (values.includes(target)) values.splice(values.indexOf(target), 1, ...by);
    };
    switch (twist) {
      case "fork":
        // Another entry at the same place, after the same entry: equivocation.
        values.push(entryOf(author, at, before, 900 + at, signing, published(author, 100 + n)));
        break;
      case "misplace":
        // An entry that names an entry that is not the one before its place.
        values.push(
          entryOf(author, at + 1, honest[0], 950 + at, signing, published(author, 200 + n)),
        );
        break;
      case "first with a prev":
        values.push(entryOf(author, 0, target, 5, signing, published(author, 300 + n)));
        break;
      case "stranger":
        // The same entry, signed by a mind that is not its author and by nobody else.
        replace(bo.sign(unsigned(target)));
        break;
      case "drop":
        replace();
        break;
      case "copy":
        // The same entry once more, with a proof by a stranger besides its own.
        values.push(bo.sign(target));
        break;
      case "bent copy":
        // Only a copy whose proof does not verify.
        replace(bent(target));
        break;
      case "junk":
        values.push(pick<unknown>([7, null, {}, "entry", published(author, 400 + n)], n));
        break;
      case "another's entry":
        values.push(entryOf(bo, 0, undefined, 20 + at));
        break;
    }
  }
  return values;
}

const feedTwists = fc.array(
  fc.tuple(fc.constantFrom(...FEED_TWISTS), fc.integer({ min: 0, max: 20 })),
  { maxLength: 3 },
);

// ---------------------------------------------------------------- packets

const DAY = 86_400;

/** A packet from one mind to others, made at `seconds` and good for an hour, not yet signed. */
const packetDraft = (
  from: Mind,
  to: readonly Mind[] | JsonObject,
  seconds: number,
  more: JsonObject = {},
): JsonObject => {
  const packet: Record<string, unknown> = {
    oip: "1",
    type: "Packet",
    from: from.address,
    to: Array.isArray(to) ? (to as readonly Mind[]).map((mind) => mind.address) : to,
    created: T(seconds),
    expires: T(seconds + 3600),
    nonce: "nonce-0001",
    purpose: { verb: "inform" },
    content: { mediaType: "text/plain", body: "The lease is translated." },
    ...more,
  };
  // A member given as `undefined` is left out.
  for (const [name, value] of Object.entries(packet)) if (value === undefined) delete packet[name];
  return packet;
};

/** A broker's wrapper around a packet, for one mind that matched its query (Layer 1, 18.5). */
const forwardedBy = (broker: Mind, to: Mind, packet: JsonObject, seconds: number): JsonObject => ({
  oip: "1",
  type: "Forwarded",
  broker: broker.address,
  to: to.address,
  packet,
  created: T(seconds),
});

const QUERY = { want: "A translator." };

// ---------------------------------------------------------------- sessions

const sessionOf = (members: readonly Mind[], nonce = "session-0001"): JsonObject => ({
  oip: "1",
  type: "Session",
  participants: members.map((mind) => mind.address).sort(),
  nonce,
  created: T(0),
});

/** A packet of a session: it names the session and its place in a chain, and states no `expires`. */
function sessionPacket(
  session: JsonObject,
  from: Mind,
  to: readonly Mind[],
  seq: number,
  prev: object | undefined,
  options: {
    readonly instance?: string;
    readonly carries?: boolean;
    readonly body?: string;
    readonly seconds?: number;
  } = {},
): Signed {
  const text = { mediaType: "text/plain", body: options.body ?? `Packet ${seq}.` };
  const packet = packetDraft(from, to, options.seconds ?? 10 + seq, {
    expires: undefined,
    session: idOf(session),
    seq,
    ...(prev === undefined ? {} : { prev: idOf(prev) }),
    ...(options.instance === undefined ? {} : { instance: options.instance }),
    content:
      options.carries === false
        ? text
        : { parts: [{ mediaType: "application/oip+json", body: session }, text] },
  });
  return from.sign(packet);
}

type ChainTwist =
  | "fork"
  | "misplace"
  | "first with a prev"
  | "drop"
  | "again"
  | "bent copy"
  | "outsider"
  | "short list"
  | "other session"
  | "no record";

const CHAIN_TWISTS: readonly ChainTwist[] = [
  "fork",
  "misplace",
  "first with a prev",
  "drop",
  "again",
  "bent copy",
  "outsider",
  "short list",
  "other session",
  "no record",
];

const chainTwists = fc.array(
  fc.tuple(fc.constantFrom(...CHAIN_TWISTS), fc.integer({ min: 0, max: 20 })),
  { maxLength: 3 },
);

/** The Python checker's account of one sending chain. */
interface PythonChain {
  readonly links: readonly string[];
  readonly equivocated: boolean;
  readonly places: Readonly<Record<string, readonly string[]>>;
  readonly ahead: number;
}

// ---------------------------------------------------------------- asking

/** The reference implementation's answer to a network case. */
function ours(question: NetworkCase): NetworkAnswer<unknown> {
  const view = viewFor(vectors, question);
  let answer: NetworkAnswer<unknown> | undefined;
  switch (question.kind) {
    case "feed":
      answer = referenceAdapter.feed?.(question, view);
      break;
    case "checkpoint":
      answer = referenceAdapter.checkpoint?.(question, view);
      break;
    case "receive":
      answer = referenceAdapter.receive?.(question, view);
      break;
    case "chain":
      answer = referenceAdapter.chain?.(question, view);
      break;
    case "hello":
      answer = referenceAdapter.hello?.(question, view);
      break;
    case "ack":
      answer = referenceAdapter.ack?.(question, view);
      break;
    case "location":
      answer = referenceAdapter.location?.(question, view);
      break;
    case "participant":
      answer = referenceAdapter.participant?.(question, view);
      break;
  }
  if (answer === undefined)
    throw new Error(`the reference adapter does not answer ${question.kind}`);
  return answer;
}

const shown = (value: unknown): string => JSON.stringify(value).slice(0, 8000);

describe.skipIf((unavailable !== undefined && !required) || measured)(
  "differential: the Mind Network",
  () => {
    let judge: PythonJudge;
    const tally = new Map<string, Map<string, number>>();
    const count = (campaign: string, answer: string): void => {
      const answers = tally.get(campaign) ?? new Map<string, number>();
      tally.set(campaign, answers);
      answers.set(answer, (answers.get(answer) ?? 0) + 1);
    };
    const counted = (campaign: string, answer: string): number =>
      tally.get(campaign)?.get(answer) ?? 0;

    beforeAll(() => {
      if (unavailable !== undefined) throw new Error(unavailable);
      judge = new PythonJudge();
    });

    afterAll(async () => {
      await judge.close();
      for (const [campaign, answers] of tally) {
        const listed = [...answers]
          .sort(([a], [b]) => (a < b ? -1 : 1))
          .map(([answer, times]) => `${answer} ${times}`)
          .join(", ");
        // For the log of the run: what both implementations answered, and how often.
        process.stdout.write(`differential, ${campaign}: ${listed}\n`);
      }
    });

    /**
     * Asks both, and requires the same yes or no. The value is compared too:
     * always where both give one whatever they answer (`always`), and
     * otherwise where the claim holds.
     */
    async function same(
      campaign: string,
      question: NetworkCase,
      always = false,
    ): Promise<{ readonly mine: NetworkAnswer<unknown>; readonly theirs: Verdict }> {
      const mine = ours(question);
      const theirs = await judge.judge(question);
      expect(
        { implementation: mine.holds, judge: theirs.holds, judgeError: theirs.error },
        shown(question),
      ).toStrictEqual({ implementation: theirs.holds, judge: theirs.holds, judgeError: undefined });
      if (always || mine.holds) {
        expect(mine.value, shown(question)).toStrictEqual(theirs.value ?? null);
      }
      count(campaign, mine.holds ? "holds" : "does not hold");
      return { mine, theirs };
    }

    /** Asks both about a case made by hand, and requires the answer the rule gives. */
    async function ruled(campaign: string, holds: boolean, question: NetworkCase): Promise<void> {
      const { mine } = await same(campaign, question);
      expect(mine.holds, question.name).toBe(holds);
    }

    // -------------------------------------------------------------- feeds

    it(
      `agrees with the Python checker on ${RUNS * 2} generated feeds`,
      async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.integer({ min: 1, max: 5 }),
            feedTwists,
            ORDER,
            async (length, twists, order) => {
              const honest = feedOf(ann, length);
              const entries = shuffled(twistedFeed(ann, honest, twists), order);
              const { mine } = await same(
                "feeds",
                { kind: "feed", name: "generated", author: ann.address, entries, extraLogs: LOGS },
                true,
              );
              const { equivocation } = mine.value as { equivocation: string[] };
              if (equivocation.length > 0) count("feeds", "equivocated");
            },
          ),
          { numRuns: RUNS * 2 },
        );
        if (RUNS >= 100) {
          expect(counted("feeds", "holds")).toBeGreaterThan(10);
          expect(counted("feeds", "does not hold")).toBeGreaterThan(10);
          expect(counted("feeds", "equivocated")).toBeGreaterThan(5);
        }
      },
      TIMEOUT,
    );

    it("agrees with it, and with the rule, on feeds made by hand", async () => {
      const feed = feedOf(ann, 3);
      const [first, second, third] = feed as [Signed, Signed, Signed];
      const asked = (name: string, author: Mind, entries: readonly unknown[]): NetworkCase => ({
        kind: "feed",
        name,
        author: author.address,
        entries,
        extraLogs: LOGS,
      });
      await ruled("feeds by hand", true, asked("three entries", ann, feed));
      await ruled("feeds by hand", true, asked("in another order", ann, [third, first, second]));
      await ruled("feeds by hand", true, asked("one of them twice", ann, [...feed, second]));
      await ruled("feeds by hand", false, asked("a gap", ann, [first, third]));
      await ruled("feeds by hand", false, asked("none at seq 0", ann, [second, third]));
      await ruled("feeds by hand", false, asked("of another mind", bo, feed));
      // Nothing is given, and nothing is left over.
      await ruled("feeds by hand", true, asked("no entries", ann, []));
      await ruled(
        "feeds by hand",
        false,
        asked("two at one place", ann, [
          ...feed,
          entryOf(ann, 2, second, 60, {}, published(ann, 9)),
        ]),
      );
      // 10.4: what the key signed from the time it was compromised is no entry, and no
      // equivocation. The feed goes on from the last valid entry.
      const early = feedOf(dee, 2, 100, DEE_FIRST);
      const lost = entryOf(dee, 2, early[1], 320, DEE_FIRST, published(dee, 7));
      const goesOn = entryOf(dee, 2, early[1], 450, DEE_SECOND, published(dee, 8));
      await ruled("feeds by hand", true, asked("before the compromise", dee, early));
      await ruled("feeds by hand", false, asked("after the compromise", dee, [...early, lost]));
      await ruled(
        "feeds by hand",
        true,
        asked("goes on from the last valid", dee, [...early, goesOn]),
      );
      const both = await same(
        "feeds by hand",
        asked("invalid, so no equivocation", dee, [...early, lost, goesOn]),
        true,
      );
      expect(both.mine.value).toStrictEqual({ verified: 3, equivocation: [] });
    });

    it(
      `agrees with it on ${RUNS} generated checkpoints`,
      async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.integer({ min: 1, max: 5 }),
            fc.integer({ min: 1, max: 6 }),
            fc.constantFrom("right", "another head", "another root", "stranger", "bent"),
            feedTwists,
            async (length, size, what, twists) => {
              const honest = feedOf(ann, length);
              const covered = honest.slice(0, Math.min(size, length));
              const head = what === "another head" ? honest[0] : covered.at(-1);
              const leaves = what === "another root" ? [...covered, honest[0]] : covered;
              const draft = {
                oip: "1",
                type: "Checkpoint",
                author: ann.address,
                created: T(500),
                size,
                head: idOf(head!),
                root: checkpointRoot(leaves.map((entry) => idOf(entry!))),
              };
              const signed = (what === "stranger" ? bo : ann).sign(draft) as Signed;
              await same("checkpoints", {
                kind: "checkpoint",
                name: "generated",
                checkpoint: what === "bent" ? bent(signed) : signed,
                // Only now and then a feed that does not verify in full.
                entries: twists.length > 1 ? twistedFeed(ann, honest, twists) : honest,
                extraLogs: LOGS,
              });
            },
          ),
          { numRuns: RUNS },
        );
        if (RUNS >= 100) {
          expect(counted("checkpoints", "holds")).toBeGreaterThan(5);
          expect(counted("checkpoints", "does not hold")).toBeGreaterThan(10);
        }
      },
      TIMEOUT,
    );

    // -------------------------------------------------------------- packets

    it(
      `agrees with it on ${RUNS * 3} generated arrivals`,
      async () => {
        const moments = [-1, 0, 1].flatMap((d) => [d - 300, d, d + 300]);
        await fc.assert(
          fc.asyncProperty(
            fc.record({
              to: fc.constantFrom("list", "list without", "query", "query with brokers", "subject"),
              carrier: fc.constantFrom(
                "none",
                "none",
                "broker",
                "another broker",
                "for another",
                "broker unsigned",
              ),
              life: fc.constantFrom(3600, 3600, 7 * DAY, 7 * DAY + 1, 3601, 60, undefined),
              // The receiver's clock, against the packet's `created` (0) and its `expires`.
              clock: fc.tuple(fc.constantFrom("created", "expires"), fc.constantFrom(...moments)),
              signer: fc.constantFrom(
                "sender",
                "sender",
                "sender",
                "stranger",
                "bent",
                "lost key",
                "late proof",
              ),
              receiver: fc.constantFrom("bo", "bo", "bo", "cy", "ann"),
              window: fc.constantFrom(undefined, 0, 299, 300, 301, 7200),
              holdsChain: fc.constantFrom(undefined, false, true),
              seenLate: fc.boolean(),
            }),
            async (c) => {
              const start = 1000;
              const listed = c.to === "list" ? [bo, cy] : [cy];
              const to =
                c.to === "list" || c.to === "list without"
                  ? listed
                  : c.to === "query"
                    ? { query: QUERY }
                    : c.to === "query with brokers"
                      ? { query: QUERY, brokers: [ian.address] }
                      : { subject: "leases/*" };
              // A packet with no `expires` names a session.
              const more =
                c.life === undefined
                  ? { expires: undefined, session: idOf(sessionOf([ann, bo])), seq: 0 }
                  : { expires: T(start + c.life) };
              const sender = c.signer === "lost key" ? dee : ann;
              const draft = packetDraft(sender, to, start, more);
              // A proof made 400 seconds after the packet expired, or after it was made.
              const late = { created: T(start + (c.life ?? 0) + 400) };
              let packet =
                c.signer === "stranger"
                  ? (bo.sign(draft) as Signed)
                  : c.signer === "lost key"
                    ? (dee.sign(draft, DEE_FIRST) as Signed)
                    : (ann.sign(draft, c.signer === "late proof" ? late : {}) as Signed);
              if (c.signer === "bent") packet = bent(packet);
              const receiver = { bo, cy, ann }[c.receiver];
              const broker = c.carrier === "another broker" ? cy : ian;
              const arrived =
                c.carrier === "none"
                  ? packet
                  : // Now and then the wrapper names its broker and another mind signs it.
                    ((c.carrier === "broker unsigned" ? cy : broker).sign(
                      forwardedBy(
                        broker,
                        c.carrier === "for another" ? cy : receiver,
                        packet,
                        start + 5,
                      ),
                    ) as Signed);
              const [from, offset] = c.clock;
              const at = start + offset + (from === "expires" ? (c.life ?? 0) : 0);
              // Now and then the receiver first saw the proofs long after they say they were
              // made: the packet then counts from that time (core 9.3).
              const seen = c.seenLate
                ? Object.fromEntries(packet.proof.map((proof) => [proofDigest(proof), T(at)]))
                : undefined;
              await same("arrivals", {
                kind: "receive",
                name: "generated",
                arrived,
                receiver: receiver.address,
                at: T(at),
                ...(c.window === undefined ? {} : { window: c.window }),
                ...(c.holdsChain === undefined ? {} : { holdsChain: c.holdsChain }),
                ...(seen === undefined ? {} : { seen }),
                extraLogs: LOGS,
              });
            },
          ),
          { numRuns: RUNS * 3 },
        );
        if (RUNS >= 100) {
          expect(counted("arrivals", "holds")).toBeGreaterThan(10);
          expect(counted("arrivals", "does not hold")).toBeGreaterThan(50);
        }
      },
      TIMEOUT,
    );

    it("agrees with it, and with the rule, on arrivals made by hand", async () => {
      const asked = (
        name: string,
        arrived: JsonObject,
        receiver: Mind,
        seconds: number,
        more: JsonObject = {},
      ): NetworkCase => ({
        kind: "receive",
        name,
        arrived,
        receiver: receiver.address,
        at: T(seconds),
        extraLogs: LOGS,
        ...more,
      });
      const packet = ann.sign(packetDraft(ann, [bo], 1000)) as Signed;
      await ruled("arrivals by hand", true, asked("in time", packet, bo, 1010));
      await ruled("arrivals by hand", false, asked("for another", packet, cy, 1010));
      await ruled("arrivals by hand", true, asked("300 s ahead", packet, bo, 700));
      await ruled("arrivals by hand", false, asked("301 s ahead", packet, bo, 699));
      await ruled("arrivals by hand", true, asked("expired 300 s ago", packet, bo, 4900));
      await ruled("arrivals by hand", false, asked("expired 301 s ago", packet, bo, 4901));
      const week = ann.sign(packetDraft(ann, [bo], 1000, { expires: T(1000 + 7 * DAY) })) as Signed;
      const more = ann.sign(packetDraft(ann, [bo], 1000, { expires: T(1001 + 7 * DAY) })) as Signed;
      await ruled("arrivals by hand", true, asked("seven days", week, bo, 1010));
      await ruled("arrivals by hand", false, asked("seven days and a second", more, bo, 1010));
      // To a query: only from a broker, only a listed one, and for an hour at most.
      const query = ann.sign(
        packetDraft(ann, { query: QUERY, brokers: [ian.address] }, 1000),
      ) as Signed;
      const wrapped = (broker: Mind, to: Mind, inner: JsonObject = query): Signed =>
        broker.sign(forwardedBy(broker, to, inner, 1005));
      await ruled("arrivals by hand", false, asked("a query, as itself", query, bo, 1010));
      await ruled(
        "arrivals by hand",
        true,
        asked("a query, from its broker", wrapped(ian, bo), bo, 1010),
      );
      await ruled(
        "arrivals by hand",
        false,
        asked("from a broker not listed", wrapped(cy, bo), bo, 1010),
      );
      await ruled(
        "arrivals by hand",
        false,
        asked("forwarded to another", wrapped(ian, cy), bo, 1010),
      );
      await ruled(
        "arrivals by hand",
        false,
        asked("the broker's proof bent", bent(wrapped(ian, bo)), bo, 1010),
      );
      const long = ann.sign(
        packetDraft(ann, { query: QUERY }, 1000, { expires: T(4601) }),
      ) as Signed;
      await ruled(
        "arrivals by hand",
        false,
        asked("a query for over an hour", wrapped(ian, bo, long), bo, 1010),
      );
      // By a list, the wrapper adds nothing and takes nothing away.
      await ruled(
        "arrivals by hand",
        true,
        asked("a list, wrapped", wrapped(cy, cy, packet), bo, 1010),
      );
      await ruled(
        "arrivals by hand",
        true,
        asked("wrapped, proof bent", bent(wrapped(cy, cy, packet)), bo, 1010),
      );
      // With no `expires`: within the window, or of a chain still held.
      const session = sessionOf([ann, bo]);
      const old = sessionPacket(session, ann, [bo], 0, undefined, { seconds: 1000 });
      await ruled("arrivals by hand", true, asked("within the window", old, bo, 4600));
      await ruled("arrivals by hand", false, asked("older than the window", old, bo, 4601));
      await ruled(
        "arrivals by hand",
        true,
        asked("of a chain held", old, bo, 4601, { holdsChain: true }),
      );
      await ruled(
        "arrivals by hand",
        true,
        asked("a longer window", old, bo, 4601, { window: 7200 }),
      );
    });

    // -------------------------------------------------------------- sessions

    /** Compares the two accounts of the chains of a session. */
    function sameChains(
      mine: NetworkAnswer<unknown>,
      theirs: Verdict,
      question: NetworkCase,
    ): void {
      const told = shown(question);
      const found = mine.value as Readonly<Record<string, ChainReading>>;
      const expected = (theirs.value ?? {}) as Readonly<Record<string, PythonChain>>;
      for (const key of new Set([...Object.keys(found), ...Object.keys(expected)])) {
        const here = found[key] ?? { delivered: [], equivocation: null, ahead: 0 };
        const there = expected[key] ?? { links: [], equivocated: false, places: {}, ahead: 0 };
        if (!there.equivocated) {
          // Whatever order the packets came in, the same chain and the same packets waiting.
          expect(here, told).toStrictEqual({
            delivered: there.links,
            equivocation: null,
            ahead: there.ahead,
          });
          continue;
        }
        // A receiver names the first two links it finds at one place. Which place, when a
        // chain has several, depends on the order they came in.
        expect(here.equivocation, told).not.toBeNull();
        const links = there.places[String(here.equivocation?.seq)] ?? [];
        expect(links.length, told).toBeGreaterThan(1);
        for (const id of here.equivocation?.packets ?? []) expect(links, told).toContain(id);
      }
    }

    it(
      `agrees with it on ${RUNS * 2} generated sessions`,
      async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.integer({ min: 1, max: 4 }),
            fc.integer({ min: 0, max: 3 }),
            chainTwists,
            ORDER,
            fc.boolean(),
            async (mine, others, twists, order, inOrder) => {
              const session = sessionOf([ann, bo, cy]);
              // Ann's chain, and one of Cy's from an instance it names. Only the first packet
              // of each carries the Session record, as 14.2 requires.
              const chain: Signed[] = [];
              for (let seq = 0; seq < mine; seq++) {
                chain.push(
                  sessionPacket(session, ann, [bo, cy], seq, chain[seq - 1], {
                    carries: seq === 0,
                  }),
                );
              }
              const other: Signed[] = [];
              for (let seq = 0; seq < others; seq++) {
                other.push(
                  sessionPacket(session, cy, [ann, bo], seq, other[seq - 1], {
                    instance: "phone",
                    carries: seq === 0,
                  }),
                );
              }
              const packets: JsonObject[] = [...chain, ...other];
              for (const [twist, n] of twists) {
                const at = n % chain.length;
                const target = chain[at]!;
                const before = chain[at - 1];
                const replace = (by: JsonObject): void => {
                  if (packets.includes(target)) packets.splice(packets.indexOf(target), 1, by);
                };
                switch (twist) {
                  case "fork":
                    packets.push(
                      sessionPacket(session, ann, [bo, cy], at, before, { body: `Fork ${n}.` }),
                    );
                    break;
                  case "misplace":
                    packets.push(
                      sessionPacket(session, ann, [bo, cy], at + 1, chain[0], {
                        body: `Astray ${n}.`,
                      }),
                    );
                    break;
                  case "first with a prev":
                    packets.push(
                      sessionPacket(session, ann, [bo, cy], 0, target, { body: `First ${n}.` }),
                    );
                    break;
                  case "drop":
                    if (packets.includes(target)) packets.splice(packets.indexOf(target), 1);
                    break;
                  case "again":
                    packets.push(target);
                    break;
                  case "bent copy":
                    replace(bent(target));
                    break;
                  case "outsider":
                    // A packet of the session from a mind that is no participant.
                    packets.push(sessionPacket(session, ian, [ann, bo, cy], 0, undefined));
                    break;
                  case "short list":
                    // One participant is left out of `to`.
                    packets.push(
                      sessionPacket(session, ann, [bo], at, before, { body: `Short ${n}.` }),
                    );
                    break;
                  case "other session":
                    packets.push(
                      sessionPacket(
                        sessionOf([ann, bo, cy], "session-0002"),
                        ann,
                        [bo, cy],
                        0,
                        undefined,
                      ),
                    );
                    break;
                  case "no record":
                    // The first packet without the Session record: whether it is taken
                    // depends on what came before it.
                    replace(sessionPacket(session, ann, [bo, cy], at, before, { carries: false }));
                    break;
                }
              }
              const question: NetworkCase = {
                kind: "chain",
                name: "generated",
                session,
                packets: inOrder ? packets : shuffled(packets, order),
                receiver: bo.address,
                extraLogs: LOGS,
              };
              const mineAnswer = ours(question);
              const theirs = await judge.judge(question);
              expect(
                { implementation: mineAnswer.holds, judge: theirs.holds, judgeError: theirs.error },
                shown(question),
              ).toStrictEqual({
                implementation: theirs.holds,
                judge: theirs.holds,
                judgeError: undefined,
              });
              sameChains(mineAnswer, theirs, question);
              count("sessions", mineAnswer.holds ? "holds" : "does not hold");
              const chains = Object.values((theirs.value ?? {}) as Record<string, PythonChain>);
              if (chains.some((one) => one.equivocated)) count("sessions", "equivocated");
              if (chains.some((one) => one.ahead > 0)) count("sessions", "with a gap");
            },
          ),
          { numRuns: RUNS * 2 },
        );
        if (RUNS >= 100) {
          expect(counted("sessions", "holds")).toBeGreaterThan(10);
          expect(counted("sessions", "does not hold")).toBeGreaterThan(10);
          expect(counted("sessions", "equivocated")).toBeGreaterThan(5);
          expect(counted("sessions", "with a gap")).toBeGreaterThan(5);
        }
      },
      TIMEOUT,
    );

    // -------------------------------------------------------------- hello, ack

    it(
      `agrees with it on ${RUNS} generated Hello records`,
      async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.record({
              who: fc.constantFrom("ann", "ann", "dee first", "dee second", "stranger", "bent"),
              domain: fc.constantFrom("right", "right", "another", "none"),
              challenge: fc.constantFrom("issued", "issued", "another", "none"),
              // How long ago the challenge was issued, in seconds.
              age: fc.constantFrom(0, 10, 299, 300, 301, -1),
              proofs: fc.constantFrom(1, 1, 1, 2),
            }),
            async (c) => {
              const origin = "https://host.example";
              const now = 2000;
              const mind = c.who.startsWith("dee") ? dee : ann;
              const signing =
                c.who === "dee first" ? DEE_FIRST : c.who === "dee second" ? DEE_SECOND : {};
              const draft = { oip: "1", type: "Hello", author: mind.address, created: T(now - 1) };
              const more = {
                ...(c.challenge === "none"
                  ? {}
                  : { challenge: c.challenge === "issued" ? "nonce-a" : "nonce-b" }),
                ...(c.domain === "none"
                  ? {}
                  : { domain: c.domain === "right" ? origin : "https://other.example" }),
              };
              let hello = (c.who === "stranger" ? bo : mind).sign(draft, {
                ...signing,
                more,
              }) as Signed;
              if (c.proofs === 2) hello = mind.sign(hello, { ...signing, more, created: T(now) });
              if (c.who === "bent") hello = bent(hello);
              await same("hellos", {
                kind: "hello",
                name: "generated",
                hello,
                origin,
                issued: { "nonce-a": T(now - c.age) },
                at: T(now),
                extraLogs: LOGS,
              });
            },
          ),
          { numRuns: RUNS },
        );
        if (RUNS >= 100) {
          expect(counted("hellos", "holds")).toBeGreaterThan(3);
          expect(counted("hellos", "does not hold")).toBeGreaterThan(20);
        }
      },
      TIMEOUT,
    );

    it(
      `agrees with it on ${RUNS} generated acknowledgements`,
      async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.record({
              to: fc.constantFrom("list", "list", "query", "subject", "others"),
              by: fc.constantFrom(
                "recipient",
                "recipient",
                "recipient",
                "stranger",
                "bent",
                "sender",
              ),
              names: fc.constantFrom("packet", "packet", "another"),
              lists: fc.constantFrom("own", "own", "none", "another", "both"),
              content: fc.constantFrom("text", "record", "parts", "bent record"),
            }),
            async (c) => {
              const carried = ann.sign(intentBy(ann, 990)) as Signed;
              const body = c.content === "bent record" ? bent(carried) : carried;
              const content =
                c.content === "text"
                  ? { mediaType: "text/plain", body: "Hello." }
                  : c.content === "parts"
                    ? {
                        parts: [
                          { mediaType: "application/oip+json", body },
                          { mediaType: "application/json", body: bo.sign(intentBy(bo, 991)) },
                        ],
                      }
                    : { mediaType: "application/oip+json", body };
              const to =
                c.to === "list"
                  ? [bo, cy]
                  : c.to === "others"
                    ? [cy]
                    : c.to === "query"
                      ? { query: QUERY }
                      : { subject: "leases/*" };
              const packet = ann.sign(packetDraft(ann, to, 1000, { content })) as Signed;
              const other = ann.sign(packetDraft(ann, [bo], 1001)) as Signed;
              const own = packet.proof.map((proof) => proofDigest(proof));
              const another = other.proof.map((proof) => proofDigest(proof));
              const proofs = { own, none: undefined, another, both: [...own, ...another] }[c.lists];
              const draft = {
                oip: "1",
                type: "Ack",
                author: (c.by === "sender" ? ann : bo).address,
                packet: idOf(c.names === "packet" ? packet : other),
                received: T(1002),
                created: T(1003),
                ...(proofs === undefined ? {} : { proofs }),
              };
              let ack = (c.by === "stranger" ? cy : c.by === "sender" ? ann : bo).sign(
                draft,
              ) as Signed;
              if (c.by === "bent") ack = bent(ack);
              await same("acknowledgements", {
                kind: "ack",
                name: "generated",
                ack,
                packet,
                extraLogs: LOGS,
              });
            },
          ),
          { numRuns: RUNS },
        );
        if (RUNS >= 100) {
          expect(counted("acknowledgements", "holds")).toBeGreaterThan(10);
          expect(counted("acknowledgements", "does not hold")).toBeGreaterThan(10);
        }
      },
      TIMEOUT,
    );

    // -------------------------------------------------------------- collectives

    it("agrees with it, and with the rule, on the records of a collective", async () => {
      // The club signs by Ann and Bo together (Layer 1, 9.5). Each may have sent the copy
      // of a record that carries its own proof: held together, the copies are one record
      // with both proofs (core 3.1). What arrives is judged by the proofs it came with.
      const by = (record: JsonObject, ...signers: Mind[]): Signed =>
        signers.reduce<JsonObject>((signed, mind) => mind.sign(signed), record) as Signed;
      const asked = (question: Record<string, unknown>): NetworkCase =>
        ({ ...question, extraLogs: LOGS }) as unknown as NetworkCase;

      const where = { ...locationBy(club, 600), seq: 1 };
      const located = (name: string, ...records: Signed[]): NetworkCase => {
        const [record = by(where, ann), ...others] = records;
        return asked({ kind: "location", name, record, records: others });
      };
      await ruled("collectives", true, located("a location both signed", by(where, ann, bo)));
      await ruled("collectives", false, located("a location one signed", by(where, ann)));
      await ruled(
        "collectives",
        true,
        located("a location in two copies", by(where, ann), by(where, bo)),
      );
      await ruled(
        "collectives",
        false,
        located("a location one signed, twice", by(where, ann), by(where, ann)),
      );

      const published = by(intentBy(club, 610), ann, bo);
      const entry = {
        oip: "1",
        type: "Entry",
        author: club.address,
        seq: 0,
        created: T(620),
        object: idOf(published),
        objectType: "Intent",
        proofs: published.proof.map((proof) => proofDigest(proof)),
      };
      const feed = (name: string, ...entries: Signed[]): NetworkCase =>
        asked({ kind: "feed", name, author: club.address, entries });
      await ruled("collectives", true, feed("an entry both signed", by(entry, bo, ann)));
      await ruled("collectives", false, feed("an entry one signed", by(entry, bo)));
      await ruled(
        "collectives",
        true,
        feed("an entry in two copies", by(entry, ann), by(entry, bo)),
      );
      const checkpoint = {
        oip: "1",
        type: "Checkpoint",
        author: club.address,
        created: T(630),
        size: 1,
        head: idOf(entry),
        root: checkpointRoot([idOf(entry)]),
      };
      const covers = (name: string, signed: Signed): NetworkCase =>
        asked({ kind: "checkpoint", name, checkpoint: signed, entries: [by(entry, ann, bo)] });
      await ruled("collectives", true, covers("a checkpoint both signed", by(checkpoint, ann, bo)));
      await ruled("collectives", false, covers("a checkpoint one signed", by(checkpoint, ann)));

      const profile = {
        oip: "1",
        type: "Participant",
        author: club.address,
        created: T(640),
        name: "The club",
        kind: "collective",
      };
      const names = by({ ...where, seq: 2, participant: idOf(profile) }, ann, bo);
      const current = (name: string, ...records: Signed[]): NetworkCase => {
        const [record = by(profile, ann), ...others] = records;
        return asked({ kind: "participant", name, record, records: others, locations: [names] });
      };
      await ruled("collectives", true, current("a profile both signed", by(profile, ann, bo)));
      await ruled("collectives", false, current("a profile one signed", by(profile, bo)));
      await ruled(
        "collectives",
        true,
        current("a profile in two copies", by(profile, bo), by(profile, ann)),
      );

      const packet = packetDraft(club, [cy], 650);
      const arrives = (name: string, arrived: Signed): NetworkCase =>
        asked({ kind: "receive", name, arrived, receiver: cy.address, at: T(660) });
      await ruled("collectives", true, arrives("a packet both signed", by(packet, ann, bo)));
      await ruled("collectives", false, arrives("a packet one signed", by(packet, ann)));

      const toClub = by(packetDraft(cy, [club], 670), cy);
      const ack = {
        oip: "1",
        type: "Ack",
        author: club.address,
        packet: idOf(toClub),
        received: T(671),
        created: T(672),
      };
      const acknowledged = (name: string, signed: Signed): NetworkCase =>
        asked({ kind: "ack", name, ack: signed, packet: toClub });
      await ruled("collectives", true, acknowledged("an Ack both signed", by(ack, ann, bo)));
      await ruled("collectives", false, acknowledged("an Ack one signed", by(ack, bo)));

      // A collective does not authenticate with a Hello: a key of the mind signs one, and
      // a threshold is no key (Layer 1, 6.1; OEP-0004).
      const more = { challenge: "nonce-a", domain: "https://host.example" };
      const hello = { oip: "1", type: "Hello", author: club.address, created: T(680) };
      await ruled(
        "collectives",
        false,
        asked({
          kind: "hello",
          name: "a Hello of a collective",
          hello: ann.sign(hello, { more }),
          origin: more.domain,
          issued: { "nonce-a": T(679) },
          at: T(681),
        }),
      );
    });

    // -------------------------------------------------------------- locations, profiles

    /** A location record of a mind with a `seq`, as it signs it. */
    const locationOf = (
      mind: Mind,
      seq: number,
      signing: Signing = {},
      more: JsonObject = {},
    ): Signed => mind.sign({ ...locationBy(mind, 500 + seq), seq, ...more }, signing);

    /** A profile of a mind, as it signs it. */
    const profileOf = (mind: Mind, name: string, signing: Signing = {}, kind = "agent"): Signed =>
      mind.sign(
        { oip: "1", type: "Participant", author: mind.address, created: T(450), name, kind },
        signing,
      );

    it(
      `agrees with it on ${RUNS} generated sets of location records`,
      async () => {
        const make = fc.record({
          seq: fc.integer({ min: 0, max: 3 }),
          how: fc.constantFrom(
            "own",
            "own",
            "own",
            "lost key",
            "stranger",
            "bent",
            "another's",
            "url",
          ),
        });
        await fc.assert(
          fc.asyncProperty(fc.array(make, { minLength: 1, maxLength: 5 }), async (made) => {
            const records = made.map(({ seq, how }) => {
              switch (how) {
                case "lost key":
                  // The key Dee removed: however high its `seq`, the record counts no longer.
                  return locationOf(dee, seq + 5, DEE_FIRST);
                case "stranger":
                  return bo.sign({ ...locationBy(dee, 500 + seq), seq: seq + 5 });
                case "bent":
                  return bent(locationOf(dee, seq + 5, DEE_SECOND));
                case "another's":
                  return locationOf(ann, seq + 5);
                case "url":
                  // Another record with the same `seq`: the lower content ID is current.
                  return locationOf(dee, seq, DEE_SECOND, { ttl: 600 });
                default:
                  return locationOf(dee, seq, DEE_SECOND);
              }
            });
            const [record = records[0]!, ...others] = records;
            await same(
              "locations",
              { kind: "location", name: "generated", record, records: others, extraLogs: LOGS },
              true,
            );
          }),
          { numRuns: RUNS },
        );
        if (RUNS >= 100) {
          expect(counted("locations", "holds")).toBeGreaterThan(5);
          expect(counted("locations", "does not hold")).toBeGreaterThan(10);
        }
      },
      TIMEOUT,
    );

    it(
      `agrees with it on ${RUNS} generated profiles`,
      async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.record({
              who: fc.constantFrom("dee", "dee", "fay"),
              profile: fc.constantFrom("own", "own", "own", "lost key", "bent", "wrong kind"),
              location: fc.constantFrom(
                "names it",
                "names another",
                "names none",
                "none",
                "lost key",
              ),
              feed: fc.constantFrom(
                "publishes it",
                "publishes both",
                "publishes another",
                "none",
                "gap",
              ),
            }),
            async (c) => {
              const mind = c.who === "dee" ? dee : fay;
              const signing = mind === dee ? DEE_SECOND : {};
              const kind = mind === dee ? "agent" : "person";
              const other = profileOf(mind, "Another name", signing, kind);
              const drafted =
                c.profile === "lost key" && mind === dee
                  ? profileOf(dee, "Dee", DEE_FIRST)
                  : profileOf(
                      mind,
                      "A name",
                      signing,
                      c.profile === "wrong kind" ? "organization" : kind,
                    );
              const record = c.profile === "bent" ? bent(drafted) : drafted;
              const named = { "names it": record, "names another": other }[c.location as string];
              const locations =
                c.location === "none"
                  ? []
                  : [
                      locationOf(
                        mind,
                        1,
                        c.location === "lost key" && mind === dee ? DEE_FIRST : signing,
                        named === undefined ? {} : { participant: idOf(named) },
                      ),
                    ];
              const publish = (seq: number, prev: Signed | undefined, object: Signed): Signed =>
                entryOf(mind, seq, prev, 460 + seq, signing, object);
              const first = publish(0, undefined, c.feed === "publishes another" ? other : record);
              const second = publish(1, first, other);
              const entries =
                c.feed === "none"
                  ? []
                  : c.feed === "publishes both"
                    ? [first, second]
                    : c.feed === "gap"
                      ? [publish(1, first, record)]
                      : [first];
              await same(
                "profiles",
                {
                  kind: "participant",
                  name: "generated",
                  record,
                  records: [other],
                  locations,
                  entries,
                  extraLogs: LOGS,
                },
                true,
              );
            },
          ),
          { numRuns: RUNS },
        );
        if (RUNS >= 100) {
          expect(counted("profiles", "holds")).toBeGreaterThan(5);
          expect(counted("profiles", "does not hold")).toBeGreaterThan(10);
        }
      },
      TIMEOUT,
    );
  },
);
