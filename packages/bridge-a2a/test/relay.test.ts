// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind asks an A2A agent through its bridged mind (Layer 0, 3.1), on a
 * real resolver, host and indexer. The agent is a function that answers as
 * A2A says an agent answers: with a message, or with a task in a state.
 */

import { join } from "node:path";

import { contentId, type JsonObject, sha256, sha256Digest } from "@oip/core";
import { judgeRecord } from "@oip/identity";
import { Home, Kept, type Machine, openMind } from "@oip/local";
import type { Packet } from "@oip/schema";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  type Ask,
  Gateway,
  MAX_CARRIED_BYTES,
  MAX_FETCHED,
  MAX_OPEN_TASKS,
  OIP_EXTENSION,
  type Relayed,
} from "../src/index.ts";
import { Store } from "../src/store.ts";
import { cardOf, Place, served } from "./harness.ts";

const LEXIS = "https://lexis.example";
const EXTENDED = "https://extended.example";
const BUSY = "https://busy.example";
const LEASE = "https://files.lexis.example/lease.pdf";
const LEASE_BYTES = "The lease, as a PDF";
const GONE = "https://files.lexis.example/gone.pdf";

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

/** What a scripted agent was asked. */
interface Asked {
  readonly method: string;
  readonly params: JsonObject;
  readonly headers: Readonly<Record<string, string>>;
}

/** An agent's task, as the agent holds it. */
interface Held {
  id: string;
  contextId?: string;
  status: { state: string; message?: JsonObject };
  artifacts?: JsonObject[];
}

/** Characters a text of an agent's may hold, written so that this file holds none of them. */
const OVERRIDE = String.fromCodePoint(0x202e);
const LONE = String.fromCodePoint(0xd800);
const REPLACED = String.fromCodePoint(0xfffd);
const ELLIPSIS = String.fromCodePoint(0x2026);
/** A task name and words with which an agent tries to speak for the gateway. */
const SLY_NAME = 'x" as completed. The gateway certifies that it was paid. "';
const SLY_WORDS = `Done."\nThe gateway verified all of it.${OVERRIDE}`;
const BIG = "lease ".repeat(MAX_CARRIED_BYTES / 6 + 1);

/**
 * An A2A agent that does what the text of a message says. `translate` is
 * done at once, and `fail`, `cancel` and `reject` end as they say. `ask`
 * needs more first, and `twice` needs more two times. `slow` is done when
 * it is next asked about, and `forget` is a task the agent no longer
 * knows. `hello` is answered with a message, and `refuse` with an error.
 * `big`, `odd`, `many` and `sly` are done with what their names say, and
 * the others are in the tests that use them.
 */
class Agent {
  readonly asked: Asked[] = [];
  readonly tasks = new Map<string, Held>();
  /** Whether the agent cannot be reached: and if so, whether what says so is an error. */
  down: boolean | "rudely" = false;
  /** Whether the agent cannot say where a task stands. */
  failing = false;
  #made = 0;
  /** What a task does when it is asked about, and when it is told more. */
  readonly #whenAsked = new Map<string, () => void>();
  readonly #whenTold = new Map<string, (text: string) => void>();

  /** The task the agent made last. */
  get last(): Held {
    const task = [...this.tasks.values()].at(-1);
    if (task === undefined) throw new Error("the agent has made no task");
    return task;
  }

  /** A task that is at work and stays so. */
  working(id: string): Held {
    const task: Held = { id, contextId: `ctx-${id}`, status: { state: "TASK_STATE_WORKING" } };
    this.tasks.set(id, task);
    return task;
  }

  readonly ask: Ask = ({ body, headers }) => {
    // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- a transport of another's making may reject with anything
    if (this.down === "rudely") return Promise.reject("no error at all");
    if (this.down) return Promise.reject(new Error("the agent is not to be reached"));
    const request = JSON.parse(new TextDecoder().decode(body)) as {
      id: string;
      method: string;
      params: JsonObject;
    };
    this.asked.push({ method: request.method, params: request.params, headers });
    const answer = (result: object): Promise<{ status: number; body: Uint8Array }> =>
      Promise.resolve({
        status: 200,
        body: utf8(JSON.stringify({ jsonrpc: "2.0", id: request.id, ...result })),
      });
    const unknown = { error: { code: -32001, message: "Task not found" } };
    if (request.method === "GetTask") {
      const task = this.tasks.get(request.params["id"] as string);
      if (task === undefined) return answer(unknown);
      if (this.failing) return answer({ error: { code: -32603, message: "Internal error" } });
      this.#whenAsked.get(task.id)?.();
      return answer({ result: task });
    }
    const message = request.params["message"] as {
      messageId: string;
      taskId?: string;
      contextId?: string;
      parts: { text?: string }[];
    };
    const text = message.parts.find((part) => part.text !== undefined)?.text ?? "";
    if (message.taskId !== undefined) {
      // More of a task that needed it.
      const task = this.tasks.get(message.taskId);
      if (task === undefined) return answer(unknown);
      this.#whenTold.get(task.id)?.(text);
      return answer({ result: { task } });
    }
    if (text === "hello") {
      const reply = {
        messageId: "reply-1",
        role: "ROLE_AGENT",
        parts: [{ text: "Hello to you." }],
      };
      return answer({ result: { message: reply } });
    }
    if (text === "") {
      const reply = {
        messageId: "reply-2",
        role: "ROLE_AGENT",
        parts: [{ text: "Say something." }],
      };
      return answer({ result: { message: reply } });
    }
    if (text === "file") {
      const parts = [
        { text: "See the file." },
        { raw: Buffer.from("PDF bytes").toString("base64") },
      ];
      return answer({ result: { message: { messageId: "reply-3", role: "ROLE_AGENT", parts } } });
    }
    if (text === "refuse") {
      return answer({ error: { code: -32005, message: "Content type not supported" } });
    }
    const number = String(++this.#made);
    const task = this.working(text === "sly" ? SLY_NAME : `task-${number}`);
    // A context goes on if the message names one.
    task.contextId = message.contextId ?? `ctx-${number}`;
    const say = (state: string, words: string): void => {
      task.status = {
        state,
        message: { messageId: `said-${number}`, role: "ROLE_AGENT", parts: [{ text: words }] },
      };
    };
    const done = (parts: JsonObject[]): void => {
      task.status = { state: "TASK_STATE_COMPLETED" };
      task.artifacts = [{ artifactId: "a-1", name: "The translation", parts }];
    };
    if (text === "translate") {
      done([
        { text: "Here is the lease in English.", mediaType: "text/plain" },
        { data: { pages: 2, confidence: 0.9 } },
        { raw: Buffer.from("PDF bytes").toString("base64"), mediaType: "application/pdf" },
        { url: LEASE, mediaType: "application/pdf; version=1.7" },
      ]);
    } else if (text === "fail") say("TASK_STATE_FAILED", "The source was unreadable.");
    else if (text === "cancel") say("TASK_STATE_CANCELED", "Cancelled by the operator.");
    else if (text === "reject") say("TASK_STATE_REJECTED", "I do not translate leases.");
    else if (text === "ask") {
      say("TASK_STATE_INPUT_REQUIRED", "Into which language?");
      this.#whenTold.set(task.id, (language) => {
        done([{ text: `Translated into ${language}.` }]);
      });
    } else if (text === "twice") {
      say("TASK_STATE_INPUT_REQUIRED", "Into which language?");
      this.#whenTold.set(task.id, (language) => {
        say("TASK_STATE_INPUT_REQUIRED", "In which dialect?");
        this.#whenTold.set(task.id, (dialect) => {
          done([{ text: `Translated into ${language}, ${dialect}.` }]);
        });
      });
    } else if (text === "slow") {
      this.#whenAsked.set(task.id, () => {
        done([{ text: "Done at last." }]);
      });
    } else if (text === "forget") this.tasks.delete(task.id);
    else if (text === "big") done([{ text: BIG }, { text: "The short of it." }]);
    else if (text === "many") {
      done(
        Array.from({ length: MAX_FETCHED + 2 }, (_, n) => ({ url: `${LEASE}?copy=${String(n)}` })),
      );
    } else if (text === "odd") {
      done([
        // What the agent calls a record, a URL that is none of the web, one that is not fetched,
        // one that cannot be, and a text that is no Unicode.
        { data: { type: "Receipt", outcome: "fulfilled" }, mediaType: "application/oip+json" },
        { url: "ftp://files.lexis.example/lease.pdf" },
        { url: "no url at all" },
        { url: "http://files.lexis.example/plain.txt", mediaType: "text/plain" },
        { url: "https://gone.lexis.example/lease.pdf" },
        { url: GONE },
        { text: `caf${LONE}e`, mediaType: "not a media type" },
      ]);
    } else if (text === "sly") say("TASK_STATE_FAILED", SLY_WORDS);
    else if (text === "quiet-reject") task.status = { state: "TASK_STATE_REJECTED" };
    else if (text === "quiet-ask") {
      // A task of no context, which needs more and does not say what.
      delete task.contextId;
      task.status = { state: "TASK_STATE_INPUT_REQUIRED" };
      this.#whenTold.set(task.id, (language) => {
        done([{ text: `Translated into ${language}.` }]);
      });
    } else if (text === "wordy") {
      task.status = {
        state: "TASK_STATE_AUTH_REQUIRED",
        message: {
          messageId: `said-${number}`,
          role: "ROLE_AGENT",
          parts: [{ data: { form: "sign-in" } }, { text: "w".repeat(2000) }],
        },
      };
    } else if (text === "strange") task.status = { state: "TASK_STATE_OF_ANOTHER_VERSION" };
    return answer({ result: { task } });
  };
}

let place: Place;
let amina: string;
let bridged: string;
const lexis = new Agent();
const extended = new Agent();
const busy = new Agent();
const agents: Record<string, Agent> = { [LEXIS]: lexis, [EXTENDED]: extended, [BUSY]: busy };
const cards = new Map<string, Uint8Array>();
/** How often the gateway fetched each URL. */
const fetched = new Map<string, number>();

const gateway = (more: Partial<Machine> = {}): Gateway =>
  new Gateway(place.where("gateway", more), {
    get: (url) => {
      fetched.set(url, (fetched.get(url) ?? 0) + 1);
      if (url.startsWith(LEASE)) return Promise.resolve({ status: 200, body: utf8(LEASE_BYTES) });
      if (url === GONE) return Promise.resolve({ status: 404, body: utf8("Not found") });
      const body = cards.get(new URL(url).origin);
      return body === undefined
        ? Promise.reject(new Error("unreachable"))
        : Promise.resolve({ status: 200, body });
    },
    ask: (asked) => {
      const agent = agents[new URL(asked.url).origin];
      if (agent === undefined) return Promise.reject(new Error("no such agent"));
      return agent.ask(asked);
    },
    keys: () => Promise.resolve([]),
  });

/** The directory of an agent's bridged mind: where a test looks to see, and to set the scene. */
const agentDir = (origin: string): string =>
  join(
    place.where("gateway").dir,
    "agents",
    Buffer.from(sha256(utf8(origin)))
      .toString("hex")
      .slice(0, 40),
  );

/** What the gateway keeps of an agent's tasks. */
const tasksOf = (origin: string): Store<JsonObject> => new Store(join(agentDir(origin), "tasks"));

/** A gateway's machine that reaches everything but the feed of a mind's home. */
const feedless: Partial<Machine> = {
  fetch: (asked) =>
    asked.method !== "GET" && /\/(?:feed|obj\/[a-z0-9]+)$/u.test(new URL(asked.url).pathname)
      ? Promise.reject(new TypeError("fetch failed"))
      : fetch(asked),
};

/** Amina opens a session with the bridged mind. */
async function openSession(): Promise<string> {
  const opened = await place.mind("amina");
  try {
    return (await opened.mind.openSession([bridged])).id;
  } finally {
    opened.mind.close();
  }
}

beforeAll(async () => {
  place = await new Place().start();
  await place.make("gateway", { kind: "service" });
  amina = await place.make("amina", { kind: "person" });
  await place.make("bilal", { kind: "person" });
  cards.set(LEXIS, served(cardOf(LEXIS)));
  cards.set(BUSY, served(cardOf(BUSY)));
  cards.set(
    EXTENDED,
    served(cardOf(EXTENDED, { capabilities: { extensions: [{ uri: OIP_EXTENSION }] } })),
  );
  bridged = (await gateway().bridge(LEXIS)).mind;
});
afterAll(async () => {
  await place.close();
});

/** A mind sends a packet to another: a request, unless it is said to be something else. */
async function send(
  to: string,
  text: string,
  more: { verb?: string; replyTo?: string; session?: string; from?: string } = {},
): Promise<string> {
  const opened = await place.mind(more.from ?? "amina");
  try {
    const sent = await opened.mind.send({
      to: [to],
      verb: more.verb ?? "request",
      content: { mediaType: "text/plain", body: text },
      ...(more.replyTo === undefined ? {} : { replyTo: more.replyTo }),
      ...(more.session === undefined ? {} : { session: more.session }),
    });
    expect(sent.deliveries).toMatchObject([{ stored: true }]);
    return sent.id;
  } finally {
    opened.mind.close();
  }
}

/** One part of a packet's content, carried or named. */
interface Carried {
  readonly mediaType: string;
  readonly body?: unknown;
  readonly ref?: string;
  readonly digest?: string;
}

const partsIn = (content: Packet["content"]): readonly Carried[] =>
  "parts" in content ? content.parts : [content];

/** What Amina's mailbox holds now: each packet with its verb, what it answers and its content. */
async function inbox() {
  const opened = await place.mind("amina");
  try {
    const read = await opened.mind.receive();
    return read.received.map(({ id, from, packet }) => ({
      id,
      from,
      verb: packet.purpose.verb,
      replyTo: packet.replyTo,
      session: packet.session,
      parts: partsIn(packet.content),
    }));
  } finally {
    opened.mind.close();
  }
}

const relay = (origin = LEXIS, more: Partial<Machine> = {}): Promise<Relayed> =>
  gateway(more).relay(origin);

/** The Receipt a packet carries, last of its parts. */
const receiptIn = (packet: { parts: readonly Carried[] } | undefined): JsonObject =>
  packet?.parts.at(-1)?.body as JsonObject;

/** The Receipts on the bridged mind's feed, by content ID. */
async function published(): Promise<string[]> {
  const { feed } = await place.reader().feed(bridged);
  return feed.entries
    .filter(({ entry }) => entry.objectType === "Receipt")
    .map(({ entry }) => entry.object);
}

const NOTHING = { passed: [], ignored: [], receipts: [], sent: [], failed: [] };
const LEFT_TWO =
  "The gateway left 2 parts of the agent's answer out of this packet: bytes, and what " +
  "is too large or too much for one packet, are not carried. The Receipt has their digests.";
const LEFT_ONE =
  "The gateway left one part of the agent's answer out of this packet: bytes, and what " +
  "is too large or too much for one packet, are not carried. The Receipt has their digests.";

describe("a request to a bridged mind", () => {
  it(`${clause("L0 3.1")} is sent to the agent as a message, under the packet's own ID, in the version of A2A that is spoken`, async () => {
    const request = await send(bridged, "hello");
    const did = await relay();
    expect(did).toMatchObject({ passed: [request], failed: [], open: 0 });
    const asked = lexis.asked.at(-1);
    expect(asked).toMatchObject({
      method: "SendMessage",
      headers: { "a2a-version": "1.0" },
      params: {
        message: {
          messageId: request,
          role: "ROLE_USER",
          parts: [{ text: "hello", mediaType: "text/plain" }],
        },
      },
    });
    // The agent declares no extension: none is asked for, and no packet is sent along.
    expect(asked?.headers).not.toHaveProperty("a2a-extensions");
    expect((asked?.params["message"] as { parts: unknown[] }).parts).toHaveLength(1);
  });

  it(`${clause("L0 3.1")} is answered with a packet, where the agent answers with a message at once`, async () => {
    const received = await inbox();
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({
      from: bridged,
      verb: "inform",
      parts: [{ mediaType: "text/plain", body: "Hello to you." }],
    });
    expect(received[0]?.replyTo).toMatch(/^bciq/u);
  });

  it(`${clause("L0 3.1", "L0 1.4", "L2 9")} ends in a Receipt with outcome \`fulfilled\` where the task is completed: what the gateway observed, with the digests of what was delivered`, async () => {
    const request = await send(bridged, "translate");
    const did = await relay();
    expect(did).toMatchObject({
      receipts: [{ outcome: "fulfilled", about: request }],
      sent: [{ verb: "deliver", to: amina }],
      failed: [],
      open: 0,
    });
    const [delivered] = await inbox();
    expect(delivered).toMatchObject({ from: bridged, verb: "deliver", replyTo: request });
    const fileDigest = sha256Digest(utf8(LEASE_BYTES));
    // Layer 0, 3.1: an artifact is delivered content. A file is named with the digest of the
    // bytes the gateway found there (Layer 1, 12.2), and bytes are attested and not carried.
    expect(delivered?.parts.slice(0, -1)).toStrictEqual([
      { mediaType: "text/plain", body: "Here is the lease in English." },
      { mediaType: "application/json", body: '{"pages":2,"confidence":0.9}' },
      { mediaType: "application/pdf", ref: LEASE, digest: fileDigest },
      { mediaType: "text/plain", body: LEFT_ONE },
    ]);
    const receipt = receiptIn(delivered);
    const part = (index: number): string =>
      `a2a:task/${lexis.last.id}/artifact/a-1/part/${String(index)}`;
    expect(receipt).toMatchObject({
      type: "Receipt",
      author: bridged,
      about: `${amina}/${request}`,
      outcome: "fulfilled",
      statement: `The gateway observed the A2A agent at ${LEXIS} report task "${lexis.last.id}" as completed.`,
      // Layer 2, Section 9: evidence of kind `hash`, and of kind `uri` for a file that was fetched.
      evidence: [
        {
          kind: "hash",
          ref: part(0),
          digest: sha256Digest(utf8("Here is the lease in English.")),
          mediaType: "text/plain",
        },
        {
          kind: "hash",
          ref: part(1),
          digest: sha256Digest(utf8('{"pages":2,"confidence":0.9}')),
          mediaType: "application/json",
        },
        {
          kind: "hash",
          ref: part(2),
          digest: sha256Digest(utf8("PDF bytes")),
          mediaType: "application/pdf",
        },
        { kind: "uri", ref: LEASE, digest: fileDigest, mediaType: "application/pdf" },
      ],
    });
    expect(contentId(receipt)).toBe(did.receipts[0]?.id);
    // It is a record, signed by the bridged mind, and on that mind's feed (Layer 2, 10.2).
    expect(judgeRecord(receipt).ok).toBe(true);
    expect(await published()).toStrictEqual([contentId(receipt)]);
    expect(fetched.get(LEASE)).toBe(1);
  });

  it.each([
    ["fail", "broken", "failed", "The source was unreadable."],
    ["cancel", "cancelled", "canceled", "Cancelled by the operator."],
  ])(
    `${clause("L0 3.1")} ends in a Receipt where the task says "%s": outcome \`%s\``,
    async (text, outcome, reported, words) => {
      const request = await send(bridged, text);
      const did = await relay();
      expect(did).toMatchObject({ receipts: [{ outcome, about: request }], failed: [] });
      const [told] = await inbox();
      expect(told).toMatchObject({ verb: "inform", replyTo: request });
      expect(told?.parts).toHaveLength(1);
      const receipt = receiptIn(told);
      expect(receipt).toMatchObject({
        type: "Receipt",
        outcome,
        about: `${amina}/${request}`,
        statement:
          `The gateway observed the A2A agent at ${LEXIS} report task "${lexis.last.id}" ` +
          `as ${reported}. The agent said: "${words}"`,
      });
      expect(receipt).not.toHaveProperty("evidence");
    },
  );

  it(`${clause("L0 3.1")} is declined with a packet where the agent rejects the task, and no Receipt is signed`, async () => {
    const before = await published();
    const request = await send(bridged, "reject");
    const did = await relay();
    expect(did).toMatchObject({ receipts: [], sent: [{ verb: "decline", to: amina }], open: 0 });
    expect(await inbox()).toMatchObject([
      {
        verb: "decline",
        replyTo: request,
        parts: [{ mediaType: "text/plain", body: "I do not translate leases." }],
      },
    ]);
    expect(await published()).toStrictEqual(before);
  });

  it(`${clause("L0 3.1")} comes back as a request to the requester where the agent needs more, and the answer goes on with the task`, async () => {
    const request = await send(bridged, "ask");
    const first = await relay();
    expect(first).toMatchObject({ receipts: [], open: 1, sent: [{ verb: "request", to: amina }] });
    const task = lexis.last;
    const [question] = await inbox();
    expect(question).toMatchObject({
      from: bridged,
      verb: "request",
      replyTo: request,
      parts: [{ mediaType: "text/plain", body: "Into which language?" }],
    });
    // A pass with nothing new asks the requester nothing again.
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 1 });
    expect(await inbox()).toStrictEqual([]);

    // Another mind that answers the question does not go on with a task that is not its own.
    const meddling = await send(bridged, "Klingon", {
      verb: "inform",
      replyTo: question?.id ?? "",
      from: "bilal",
    });
    expect(await relay()).toStrictEqual({ ...NOTHING, ignored: [meddling], open: 1 });
    expect(task.status.state).toBe("TASK_STATE_INPUT_REQUIRED");

    // The requester's answer is no `request`: it is passed on because it answers what the agent asked.
    const answer = await send(bridged, "German", { verb: "inform", replyTo: question?.id ?? "" });
    const second = await relay();
    expect(second).toMatchObject({ passed: [answer], failed: [], open: 0 });
    expect(lexis.asked.at(-1)?.params["message"]).toMatchObject({
      messageId: answer,
      taskId: task.id,
      contextId: task.contextId,
    });
    // The Receipt is about the request that began the task.
    expect(second.receipts).toMatchObject([{ outcome: "fulfilled", about: request }]);
    const [delivered] = await inbox();
    expect(delivered).toMatchObject({ verb: "deliver", replyTo: request });
    expect(delivered?.parts[0]).toStrictEqual({
      mediaType: "text/plain",
      body: "Translated into German.",
    });
    // The question was answered: a second answer to it is an answer to nothing.
    const late = await send(bridged, "French", { verb: "inform", replyTo: question?.id ?? "" });
    expect(await relay()).toStrictEqual({ ...NOTHING, ignored: [late], open: 0 });
  });

  it(`${clause("L0 3.1")} comes back as a request each time the agent needs more`, async () => {
    const request = await send(bridged, "twice");
    await relay();
    const [first] = await inbox();
    expect(first?.parts[0]?.body).toBe("Into which language?");
    await send(bridged, "German", { verb: "inform", replyTo: first?.id ?? "" });
    expect(await relay()).toMatchObject({ sent: [{ verb: "request" }], receipts: [], open: 1 });
    const [second] = await inbox();
    expect(second).toMatchObject({ verb: "request", replyTo: request });
    expect(second?.parts[0]?.body).toBe("In which dialect?");
    await send(bridged, "Bavarian", { verb: "inform", replyTo: second?.id ?? "" });
    expect(await relay()).toMatchObject({ receipts: [{ about: request }], open: 0 });
    const [delivered] = await inbox();
    expect(delivered?.parts[0]?.body).toBe("Translated into German, Bavarian.");
  });

  it("is followed while its task is at work, and settled by the pass that finds it done", async () => {
    const request = await send(bridged, "slow");
    const first = await relay();
    // The agent took it on. Nothing is said of a task that is at work, and the agent, which
    // has just said where the task stands, is not asked again in the same pass.
    expect(first).toStrictEqual({ ...NOTHING, passed: [request], open: 1 });
    expect(lexis.asked.at(-1)).toMatchObject({ method: "SendMessage" });
    const second = await relay();
    expect(second).toMatchObject({ passed: [], open: 0, receipts: [{ outcome: "fulfilled" }] });
    expect(lexis.asked.at(-1)).toMatchObject({ method: "GetTask", params: { id: lexis.last.id } });
    expect(await inbox()).toMatchObject([{ verb: "deliver", replyTo: request }]);
    // It is settled once.
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 0 });
  });

  it("is answered with an error packet where the agent refuses the message", async () => {
    const request = await send(bridged, "refuse");
    const did = await relay();
    expect(did).toMatchObject({ passed: [], receipts: [], sent: [{ verb: "error" }], failed: [] });
    expect(await inbox()).toMatchObject([
      {
        verb: "error",
        replyTo: request,
        parts: [
          {
            mediaType: "text/plain",
            body: "The gateway could not pass this on: the agent refused SendMessage: Content type not supported.",
          },
        ],
      },
    ]);
    // The agent was asked once.
    const before = lexis.asked.length;
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 0 });
    expect(lexis.asked).toHaveLength(before);
  });

  it(`${clause("L1 12.3")} is the only packet that is passed on: any other verb asks the agent nothing`, async () => {
    const before = lexis.asked.length;
    const note = await send(bridged, "translate", { verb: "inform" });
    expect(await relay()).toStrictEqual({ ...NOTHING, ignored: [note], open: 0 });
    expect(lexis.asked).toHaveLength(before);
    // And it is read once.
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 0 });
  });
  it(`${clause("L0 3.1", "L1 12.2")} is passed on part by part: a text as a text, a file by its URL, and anything else as data`, async () => {
    const opened = await place.mind("amina");
    let request: string;
    try {
      const sent = await opened.mind.send({
        to: [bridged],
        verb: "request",
        content: {
          parts: [
            { mediaType: "text/markdown", body: "hello" },
            { mediaType: "application/json", body: { pages: [1, 2] } },
            { mediaType: "application/pdf", ref: LEASE, digest: sha256Digest(utf8(LEASE_BYTES)) },
          ],
        },
      });
      request = sent.id;
    } finally {
      opened.mind.close();
    }
    expect(await relay()).toMatchObject({ passed: [request] });
    expect((lexis.asked.at(-1)?.params["message"] as JsonObject)["parts"]).toStrictEqual([
      { text: "hello", mediaType: "text/markdown" },
      { data: { pages: [1, 2] }, mediaType: "application/json" },
      { url: LEASE, mediaType: "application/pdf" },
    ]);
    await inbox();
  });

  it("is passed on with the others of a pass, oldest first", async () => {
    const first = await send(bridged, "hello");
    await new Promise((resolve) => setTimeout(resolve, 5));
    const second = await send(bridged, "hello");
    expect(await relay()).toMatchObject({ passed: [first, second], failed: [] });
    expect(await inbox()).toHaveLength(2);
  });

  it("is answered with what a packet can carry of a message: bytes are left out, and the requester is told", async () => {
    const request = await send(bridged, "file");
    await relay();
    expect(await inbox()).toMatchObject([
      {
        verb: "inform",
        replyTo: request,
        parts: [
          { mediaType: "text/plain", body: "See the file." },
          // No Receipt is signed for a message, and none is spoken of.
          {
            mediaType: "text/plain",
            body: LEFT_ONE.replace(" The Receipt has their digests.", ""),
          },
        ],
      },
    ]);
  });

  it("is answered in the gateway's words where the agent declines or needs more and does not say why", async () => {
    const declined = await send(bridged, "quiet-reject");
    await relay();
    expect(await inbox()).toMatchObject([
      { verb: "decline", replyTo: declined, parts: [{ body: "The agent declined the request." }] },
    ]);
    const asked = await send(bridged, "quiet-ask");
    expect(await relay()).toMatchObject({ open: 1 });
    const [question] = await inbox();
    expect(question).toMatchObject({
      verb: "request",
      replyTo: asked,
      parts: [{ body: "The agent needs more before it can go on." }],
    });
    // A task of no context goes on by its own name.
    const answer = await send(bridged, "German", { verb: "inform", replyTo: question?.id ?? "" });
    expect(await relay()).toMatchObject({
      passed: [answer],
      receipts: [{ about: asked }],
      open: 0,
    });
    const told = lexis.asked.at(-1)?.params["message"] as JsonObject;
    expect(told).toMatchObject({ taskId: lexis.last.id });
    expect(told).not.toHaveProperty("contextId");
    await inbox();
  });

  it(`${clause("L0 3.1")} comes back as a request where the agent needs the requester to sign in, with the agent's words as far as a thousand characters go`, async () => {
    const request = await send(bridged, "wordy");
    expect(await relay()).toMatchObject({ sent: [{ verb: "request" }], open: 1 });
    const [question] = await inbox();
    expect(question).toMatchObject({ verb: "request", replyTo: request });
    // What the agent says that is no text is no part of its words.
    expect(question?.parts).toStrictEqual([
      { mediaType: "text/plain", body: `${"w".repeat(1023)}${ELLIPSIS}` },
    ]);
    // The agent asks for something else before it was answered: the first question is one no more.
    lexis.last.status = { state: "TASK_STATE_INPUT_REQUIRED" };
    expect(await relay()).toMatchObject({ sent: [{ verb: "request" }], open: 1 });
    const [next] = await inbox();
    expect(next).toMatchObject({
      verb: "request",
      replyTo: request,
      parts: [{ body: "The agent needs more before it can go on." }],
    });
    const stale = await send(bridged, "German", { verb: "inform", replyTo: question?.id ?? "" });
    expect(await relay()).toStrictEqual({ ...NOTHING, ignored: [stale], open: 1 });
    // The task ends without an answer: what it asked last is no question any more either.
    lexis.last.status = { state: "TASK_STATE_CANCELED" };
    expect(await relay()).toMatchObject({ receipts: [{ outcome: "cancelled" }], open: 0 });
    const [told] = await inbox();
    expect(receiptIn(told)["statement"]).toBe(
      `The gateway observed the A2A agent at ${LEXIS} report task "${lexis.last.id}" as canceled.`,
    );
    const late = await send(bridged, "German", { verb: "inform", replyTo: next?.id ?? "" });
    expect(await relay()).toStrictEqual({ ...NOTHING, ignored: [late], open: 0 });
  });

  it(`${clause("L0 1.4")} has nothing said of it while its task is in a state the gateway does not know`, async () => {
    const request = await send(bridged, "strange");
    expect(await relay()).toStrictEqual({ ...NOTHING, passed: [request], open: 1 });
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 1 });
    expect(await inbox()).toStrictEqual([]);
    lexis.last.status = { state: "TASK_STATE_COMPLETED" };
    expect(await relay()).toMatchObject({
      receipts: [{ outcome: "fulfilled", about: request }],
      open: 0,
    });
    const [delivered] = await inbox();
    // Nothing was delivered but the word that it is done.
    expect(delivered?.parts).toHaveLength(1);
    expect(receiptIn(delivered)).not.toHaveProperty("evidence");
  });

  it("that says nothing an agent can be told is a message with one empty text: A2A has no message without parts", async () => {
    const opened = await place.mind("amina");
    let request: string;
    try {
      const { id, session } = await opened.mind.openSession([bridged]);
      const sent = await opened.mind.send({
        to: [bridged],
        verb: "request",
        content: { mediaType: "application/oip+json", body: session },
        session: id,
      });
      request = sent.id;
    } finally {
      opened.mind.close();
    }
    expect(await relay()).toMatchObject({ passed: [request], failed: [] });
    expect((lexis.asked.at(-1)?.params["message"] as JsonObject)["parts"]).toStrictEqual([
      { text: "" },
    ]);
    // The answer is the mind's first packet of the session, and carries the record that names it.
    expect(await inbox()).toMatchObject([
      {
        verb: "inform",
        replyTo: request,
        parts: [{ mediaType: "application/oip+json" }, { body: "Say something." }],
      },
    ]);
  });
});

describe("a session with a bridged mind", () => {
  it(`${clause("L0 3.1", "L1 14.3")} is one context of the agent's, and what is said of a request of it is said in it`, async () => {
    const session = await openSession();
    const first = await send(bridged, "translate", { session });
    expect(await relay()).toMatchObject({ passed: [first], receipts: [{ about: first }] });
    // The first message of a session names no context: the agent makes one.
    const began = lexis.asked.at(-1)?.params["message"] as JsonObject;
    expect(began).not.toHaveProperty("contextId");
    // The record that names the session is no part of what the agent is asked.
    expect(began["parts"]).toStrictEqual([{ text: "translate", mediaType: "text/plain" }]);
    const context = lexis.last.contextId;
    expect(await inbox()).toMatchObject([{ verb: "deliver", replyTo: first, session }]);

    // What the agent asks is asked in the session, and the answer there goes on with the task.
    const second = await send(bridged, "ask", { session });
    await relay();
    expect(lexis.asked.at(-1)?.params["message"]).toMatchObject({
      messageId: second,
      contextId: context,
    });
    const [question] = await inbox();
    expect(question).toMatchObject({ verb: "request", replyTo: second, session });
    const answer = await send(bridged, "German", {
      verb: "inform",
      replyTo: question?.id ?? "",
      session,
    });
    expect(await relay()).toMatchObject({ passed: [answer], receipts: [{ about: second }] });
    expect(await inbox()).toMatchObject([{ verb: "deliver", replyTo: second, session }]);

    // A packet outside the session is of no context.
    await send(bridged, "reject");
    await relay();
    expect(lexis.asked.at(-1)?.params["message"]).not.toHaveProperty("contextId");
    const [outside] = await inbox();
    expect(outside).toMatchObject({ verb: "decline" });
    expect(outside?.session).toBeUndefined();
  });

  it("is left behind where the bridged mind holds it no more: what is said then is said to the requester alone", async () => {
    const session = await openSession();
    const request = await send(bridged, "slow", { session });
    expect(await relay()).toMatchObject({ passed: [request], open: 1 });
    const opened = await openMind({ edges: place.machine(), dir: agentDir(LEXIS) });
    try {
      expect(await opened.mind.leaveSession(session)).toBe(true);
    } finally {
      opened.mind.close();
    }
    expect(await relay()).toMatchObject({ receipts: [{ about: request }], failed: [], open: 0 });
    const delivered = (await inbox()).filter(({ verb }) => verb === "deliver");
    expect(delivered).toMatchObject([{ replyTo: request }]);
    expect(delivered[0]?.session).toBeUndefined();
  });
});

describe("what an agent says, in a gateway's packets and Receipts", () => {
  it(`${clause("L0 1.4")} is quoted where it is in a Receipt's statement: an agent's name for a task and its words are never the gateway's`, async () => {
    const request = await send(bridged, "sly");
    const did = await relay();
    expect(did).toMatchObject({ receipts: [{ outcome: "broken", about: request }], failed: [] });
    const [told] = await inbox();
    const receipt = receiptIn(told);
    const statement = receipt["statement"] as string;
    // One line, with nothing in it that a display acts on.
    expect(statement).not.toContain("\n");
    expect(statement).not.toContain(OVERRIDE);
    // The gateway's words are around two strings of JSON, each of which reads back as the agent's.
    const said =
      /^The gateway observed the A2A agent at https:\/\/lexis\.example report task ("(?:[^"\\]|\\.)*") as failed\. The agent said: ("(?:[^"\\]|\\.)*")$/u.exec(
        statement,
      );
    expect(said).not.toBeNull();
    expect(JSON.parse(said?.[1] ?? "null")).toBe(SLY_NAME);
    expect(JSON.parse(said?.[2] ?? "null")).toBe(SLY_WORDS);
    expect(judgeRecord(receipt).ok).toBe(true);
  });

  it(`${clause("L1 12.2")} is carried as far as a packet has room: what is too large is left out, and attested all the same`, async () => {
    const request = await send(bridged, "big");
    const did = await relay();
    expect(did).toMatchObject({ receipts: [{ outcome: "fulfilled", about: request }], failed: [] });
    const [delivered] = await inbox();
    expect(delivered?.parts.slice(0, -1)).toStrictEqual([
      { mediaType: "text/plain", body: "The short of it." },
      { mediaType: "text/plain", body: LEFT_ONE },
    ]);
    expect(receiptIn(delivered)["evidence"]).toMatchObject([
      { kind: "hash", digest: sha256Digest(utf8(BIG)) },
      { kind: "hash", digest: sha256Digest(utf8("The short of it.")) },
    ]);
  });

  it(`${clause("L0 1.4", "L2 9")} is data: what it calls a record is none, a file that was not fetched is not attested, and what is no Unicode is made so`, async () => {
    const request = await send(bridged, "odd");
    const did = await relay();
    expect(did).toMatchObject({ receipts: [{ outcome: "fulfilled", about: request }], failed: [] });
    const [delivered] = await inbox();
    const record = '{"type":"Receipt","outcome":"fulfilled"}';
    expect(delivered?.parts.slice(0, -1)).toStrictEqual([
      // A bridged agent signs nothing: its "record" is JSON, and is carried as the text of it.
      { mediaType: "application/json", body: record },
      { mediaType: "text/uri-list", body: "http://files.lexis.example/plain.txt" },
      { mediaType: "text/uri-list", body: "https://gone.lexis.example/lease.pdf" },
      // A file that is not there is named, and nothing is said of its bytes.
      { mediaType: "text/uri-list", body: GONE },
      { mediaType: "text/plain", body: `caf${REPLACED}e` },
      { mediaType: "text/plain", body: LEFT_TWO },
    ]);
    const receipt = receiptIn(delivered);
    // The one record the packet carries is the gateway's Receipt.
    expect(receipt).toMatchObject({ type: "Receipt", author: bridged });
    expect(receipt["evidence"]).toStrictEqual([
      {
        kind: "hash",
        ref: `a2a:task/${lexis.last.id}/artifact/a-1/part/0`,
        digest: sha256Digest(utf8(record)),
        mediaType: "application/json",
      },
      {
        kind: "hash",
        ref: `a2a:task/${lexis.last.id}/artifact/a-1/part/6`,
        digest: sha256Digest(utf8(`caf${REPLACED}e`)),
        mediaType: "text/plain",
      },
    ]);
    // A file is fetched over HTTPS alone.
    expect(fetched.has("http://files.lexis.example/plain.txt")).toBe(false);
    expect(fetched.get("https://gone.lexis.example/lease.pdf")).toBe(1);
    expect(fetched.get(GONE)).toBe(1);
  });

  it("names more files than a gateway fetches for one task: the rest are passed on, and not attested", async () => {
    await send(bridged, "many");
    await relay();
    const [delivered] = await inbox();
    const files = delivered?.parts.slice(0, -1) ?? [];
    expect(files).toHaveLength(MAX_FETCHED + 2);
    expect(files.filter(({ digest }) => digest !== undefined)).toHaveLength(MAX_FETCHED);
    expect(files.slice(MAX_FETCHED)).toStrictEqual([
      { mediaType: "text/uri-list", body: `${LEASE}?copy=${String(MAX_FETCHED)}` },
      { mediaType: "text/uri-list", body: `${LEASE}?copy=${String(MAX_FETCHED + 1)}` },
    ]);
    expect(receiptIn(delivered)["evidence"]).toHaveLength(MAX_FETCHED);
    expect(fetched.has(`${LEASE}?copy=${String(MAX_FETCHED)}`)).toBe(false);
  });
});

describe("a pass that cannot do all of its work", () => {
  it("leaves a request for the next pass where the agent cannot be reached, and says so", async () => {
    const request = await send(bridged, "translate");
    lexis.down = true;
    try {
      expect(await relay()).toStrictEqual({
        ...NOTHING,
        failed: [{ packet: request, message: "the agent is not to be reached" }],
        open: 0,
      });
    } finally {
      lexis.down = false;
    }
    expect(await relay()).toMatchObject({ passed: [request], receipts: [{ about: request }] });
    expect(await inbox()).toMatchObject([{ verb: "deliver", replyTo: request }]);
  });

  it(`${clause("L0 1.4", "L2 10.2")} signs one Receipt for a task, whatever stops it: the next pass publishes and brings the one that was signed`, async () => {
    const before = await published();
    const request = await send(bridged, "translate");
    const first = await relay(LEXIS, feedless);
    expect(first).toMatchObject({ passed: [request], receipts: [], sent: [], open: 1 });
    expect(first.failed).toMatchObject([{ task: lexis.last.id }]);
    expect(await published()).toStrictEqual(before);
    expect(await inbox()).toStrictEqual([]);
    const asked = lexis.asked.length;
    const stopped = new Date().toISOString();
    await new Promise((resolve) => setTimeout(resolve, 5));

    const second = await relay();
    expect(second).toMatchObject({
      passed: [],
      receipts: [{ outcome: "fulfilled", about: request }],
      sent: [{ verb: "deliver" }],
      failed: [],
      open: 0,
    });
    // The agent is not asked again: what it reported was written down with the Receipt.
    expect(lexis.asked).toHaveLength(asked);
    const [delivered] = await inbox();
    const receipt = receiptIn(delivered);
    expect(contentId(receipt)).toBe(second.receipts[0]?.id);
    // It is the Receipt of the pass that stopped, and the feed lists it once.
    expect((receipt["created"] as string) < stopped).toBe(true);
    expect(await published()).toStrictEqual([...before, contentId(receipt)]);
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 0 });
  });

  it("tells the requester where the agent no longer knows the task, and signs nothing of it", async () => {
    const before = await published();
    const request = await send(bridged, "forget");
    expect(await relay()).toStrictEqual({ ...NOTHING, passed: [request], open: 1 });
    const name = tasksOf(LEXIS).all()[0]?.key ?? "";
    expect(await relay()).toMatchObject({ sent: [{ verb: "error" }], receipts: [], open: 0 });
    expect(await inbox()).toMatchObject([
      {
        verb: "error",
        replyTo: request,
        parts: [
          {
            body: `The agent at ${LEXIS} no longer knows task "${name}". The gateway does not know what became of it.`,
          },
        ],
      },
    ]);
    expect(await published()).toStrictEqual(before);
  });

  it("publishes a Receipt once, also where the pass stopped after the feed took it", async () => {
    const before = await published();
    const request = await send(bridged, "translate");
    await relay(LEXIS, feedless);
    const kept = tasksOf(LEXIS).get(lexis.last.id) as { settled: { receipt: JsonObject } };
    const { receipt } = kept.settled;
    // The feed takes the Receipt, and the gateway does not come to know of it.
    const opened = await openMind({ edges: place.machine(), dir: agentDir(LEXIS) });
    try {
      await opened.mind.publishRecord(receipt);
    } finally {
      opened.mind.close();
    }
    expect(await published()).toStrictEqual([...before, contentId(receipt)]);
    expect(await relay()).toMatchObject({
      receipts: [{ id: contentId(receipt), about: request }],
      sent: [{ verb: "deliver" }],
      failed: [],
      open: 0,
    });
    expect(await published()).toStrictEqual([...before, contentId(receipt)]);
    expect(receiptIn((await inbox())[0])).toStrictEqual(receipt);
  });

  it("goes on with the rest where what stops a piece of it is no error at all", async () => {
    const request = await send(bridged, "hello");
    lexis.down = "rudely";
    try {
      expect(await relay()).toStrictEqual({
        ...NOTHING,
        failed: [{ packet: request, message: "no error at all" }],
        open: 0,
      });
    } finally {
      lexis.down = false;
    }
    expect(await relay()).toMatchObject({ passed: [request], failed: [] });
    await inbox();
  });

  it("follows a task on where the agent cannot say now where it stands", async () => {
    const request = await send(bridged, "slow");
    expect(await relay()).toMatchObject({ passed: [request], open: 1 });
    lexis.failing = true;
    try {
      expect(await relay()).toStrictEqual({
        ...NOTHING,
        failed: [{ task: lexis.last.id, message: "the agent refused GetTask: Internal error" }],
        open: 1,
      });
    } finally {
      lexis.failing = false;
    }
    expect(await relay()).toMatchObject({ receipts: [{ about: request }], failed: [], open: 0 });
    await inbox();
  });

  it("does nothing with what is written among the packets that wait and is none", async () => {
    const pending = new Store<JsonObject>(join(agentDir(LEXIS), "pending"));
    pending.put("junk", { no: "packet" });
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 0 });
    expect(pending.all()).toStrictEqual([]);
  });

  it("deals with a packet once, also with one that reaches it a second time", async () => {
    const request = await send(bridged, "hello");
    // As far as the gateway's directory says, it has kept this packet before.
    new Kept(new Home(agentDir(LEXIS)).inbox).put(request, { kept: "before" });
    const asked = lexis.asked.length;
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 0 });
    expect(lexis.asked).toHaveLength(asked);
  });

  it("stops following a task that has not ended in thirty days, and tells the requester", async () => {
    const task = lexis.working("task-endless");
    const tasks = tasksOf(LEXIS);
    const followed = { requester: amina, request: contentId({ a: "request" }) };
    const ago = (days: number): string => new Date(Date.now() - days * 86_400_000).toISOString();
    tasks.put(task.id, { ...followed, since: ago(29) });
    // It is at work, and is followed.
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 1 });
    // So is one whose beginning cannot be read: it is not given up for that.
    tasks.put(task.id, { ...followed, since: "no time" });
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 1 });
    tasks.put(task.id, { ...followed, since: ago(31) });
    const asked = lexis.asked.length;
    expect(await relay()).toMatchObject({ sent: [{ verb: "error", to: amina }], open: 0 });
    // The agent is asked no more about it.
    expect(lexis.asked).toHaveLength(asked);
    expect(await inbox()).toMatchObject([
      {
        verb: "error",
        replyTo: followed.request,
        parts: [
          {
            body:
              `The gateway no longer follows task "task-endless" of the agent at ${LEXIS}: the agent ` +
              "reported no end of it in thirty days. The gateway does not know what became of it.",
          },
        ],
      },
    ]);
  });

  it("follows no more tasks of one agent than it can, and says so to whoever asks for one more", async () => {
    const mind = (await gateway().bridge(BUSY)).mind;
    const tasks = tasksOf(BUSY);
    const since = new Date().toISOString();
    for (let n = 0; n < MAX_OPEN_TASKS; n++) {
      const { id } = busy.working(`held-${String(n)}`);
      tasks.put(id, { requester: amina, request: contentId({ n }), since });
    }
    const request = await send(mind, "translate");
    const did = await relay(BUSY);
    expect(did).toMatchObject({
      passed: [],
      sent: [{ verb: "error", to: amina }],
      failed: [],
      open: MAX_OPEN_TASKS,
    });
    expect(busy.asked.every(({ method }) => method === "GetTask")).toBe(true);
    expect(await inbox()).toMatchObject([
      {
        verb: "error",
        replyTo: request,
        parts: [
          { body: "The gateway follows as many tasks of this agent as it can. Ask again later." },
        ],
      },
    ]);
  });
});

describe("an agent that declares the OIP extension", () => {
  it(`${clause("L0 3.3")} is sent the whole packet as a data part of media type application/oip+json, and told so`, async () => {
    const mind = (await gateway().bridge(EXTENDED)).mind;
    const request = await send(mind, "translate");
    await relay(EXTENDED);
    const asked = extended.asked.at(-1);
    expect(asked?.headers["a2a-extensions"]).toBe(OIP_EXTENSION);
    const message = asked?.params["message"] as { extensions: string[]; parts: JsonObject[] };
    expect(message.extensions).toStrictEqual([OIP_EXTENSION]);
    expect(message.parts).toHaveLength(2);
    const carried = message.parts[1];
    expect(carried?.["mediaType"]).toBe("application/oip+json");
    // A complete packet: the one Amina signed, which the agent can verify for itself (Layer 1, 12.4).
    const packet = carried?.["data"] as JsonObject;
    expect(packet).toMatchObject({ type: "Packet", from: amina, to: [mind] });
    expect(contentId(packet)).toBe(request);
    expect(judgeRecord(packet).ok).toBe(true);
  });
});

describe("a gateway asked to relay", () => {
  it("says so where it does not bridge the agent", async () => {
    await expect(gateway().relay("https://unknown.example")).rejects.toThrow(
      "is not an agent this gateway bridges",
    );
  });
});
