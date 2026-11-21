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
import { Home, Kept, type Machine, openMind, Store } from "@oip/local";
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
/**
 * A task name and words with which an agent tries to speak for the gateway:
 * with ASCII's quotation mark, with typographic ones, with a letter mark
 * that turns the line, a space of no width, and a character no record holds.
 */
const SLY_NAME = `x" as completed.${String.fromCodePoint(0x201d)} The gateway certifies that it was paid. ${String.fromCodePoint(0x201c, 0x61c, 0x200b, 0xfffe)}"`;
const SLY_WORDS = `Done."\nThe gateway verified all of it.${OVERRIDE}`;
/** A character no record holds (core 1.1), and one that is six bytes of a record's canonical form. */
const NONCHARACTER = String.fromCodePoint(0xfffe);
const CONTROL = String.fromCodePoint(0x01);
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
  /** How often the agent was tried, reached or not. */
  tried = 0;
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
    this.tried += 1;
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
    if (text === "garbled" || text === "flood" || text === "deep") {
      // An answer at once, of what a record does not hold, or not so much of, or not so deep.
      let deep: unknown = 1;
      for (let level = 0; level < 100_000; level++) deep = [deep];
      const parts = {
        garbled: [
          { text: `caf${NONCHARACTER}${LONE}e` },
          { url: `https://files.lexis.example/a${LONE}b` },
        ],
        flood: [{ text: CONTROL.repeat(200_000) }, { text: "After the flood." }],
        deep: [{ data: deep }, { text: "After the deep." }],
      }[text];
      // Written by hand: half a pair of surrogates is no JSON text that a parser makes, and data
      // so deep is none that `JSON.stringify` writes.
      const written =
        text === "deep"
          ? `[{"data":${"[".repeat(100_000)}1${"]".repeat(100_000)}},{"text":"After the deep."}]`
          : JSON.stringify(parts);
      return Promise.resolve({
        status: 200,
        body: utf8(
          `{"jsonrpc":"2.0","id":${JSON.stringify(request.id)},"result":{"message":{"messageId":"reply-4","role":"ROLE_AGENT","parts":${written}}}}`,
        ),
      });
    }
    if (text === "reuse") {
      // The agent answers with a task it took on for another request.
      return answer({ result: { task: this.last } });
    }
    const number = String(++this.#made);
    const task = this.working(
      text === "sly" || text === "sly-files" ? `${SLY_NAME}${number}` : `task-${number}`,
    );
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
    else if (text === "seventy") {
      // More parts than a packet carries, and more than a Receipt has evidence items for.
      task.status = { state: "TASK_STATE_COMPLETED" };
      task.artifacts = [0, 1, 2].map((artifact) => ({
        artifactId: `a-${String(artifact)}`,
        parts: Array.from({ length: 24 }, (_, part) => ({
          text: `Part ${String(artifact * 24 + part)}.`,
        })),
      }));
    } else if (text === "many") {
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
    else if (text === "sly-files") {
      done(Array.from({ length: 3 }, (_, n) => ({ url: `${LEASE}?sly=${String(n)}` })));
    } else if (text === "sign-in") {
      // What the requester needs is a URL, and the agent's words are beside it.
      task.status = {
        state: "TASK_STATE_AUTH_REQUIRED",
        message: {
          messageId: `said-${number}`,
          role: "ROLE_AGENT",
          parts: [{ text: "Sign in first." }, { url: "https://lexis.example/sign-in?task=1" }],
        },
      };
    } else if (text === "quiet-reject") task.status = { state: "TASK_STATE_REJECTED" };
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

/**
 * A gateway's machine that reaches the network until the agent has been
 * asked, and nothing after: a pass that stops in the middle of its work.
 */
const cutOffOnceAsked = (agent: Agent): Partial<Machine> => {
  const before = agent.asked.length;
  return {
    fetch: (asked) =>
      agent.asked.length > before ? Promise.reject(new TypeError("fetch failed")) : fetch(asked),
  };
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
  more: {
    verb?: string;
    replyTo?: string;
    session?: string;
    from?: string;
    expiresIn?: number;
  } = {},
): Promise<string> {
  const opened = await place.mind(more.from ?? "amina");
  try {
    const sent = await opened.mind.send({
      to: [to],
      verb: more.verb ?? "request",
      content: { mediaType: "text/plain", body: text },
      ...(more.replyTo === undefined ? {} : { replyTo: more.replyTo }),
      ...(more.session === undefined ? {} : { session: more.session }),
      ...(more.expiresIn === undefined ? {} : { expiresIn: more.expiresIn }),
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

/** What a mind's mailbox holds now, Amina's unless another is named: each packet with its verb, what it answers and its content. */
async function inbox(name = "amina") {
  const opened = await place.mind(name);
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

const relay = (
  origin = LEXIS,
  more: Partial<Machine> = {},
  spent?: () => boolean,
): Promise<Relayed> => gateway(more).relay(origin, spent);

/** The Receipt a packet carries, last of its parts. */
const receiptIn = (packet: { parts: readonly Carried[] } | undefined): JsonObject =>
  packet?.parts.at(-1)?.body as JsonObject;

/** What the bridged mind's feed lists, by the type of each record. */
async function published(): Promise<string[]> {
  const { feed } = await place.reader().feed(bridged);
  return feed.entries.map(({ entry }) => entry.objectType);
}

const NOTHING = { passed: [], ignored: [], receipts: [], sent: [], failed: [] };
/** What a packet says of parts it does not carry, where no Receipt comes with it. */
const left = (parts: string): string =>
  `The gateway left ${parts} of the agent's answer out of this packet: bytes, and what ` +
  "is too large or too much for one packet, are not carried.";
const LEFT_ONE = `${left("one part")} The Receipt has its digest.`;

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
    // It is a record, signed by the bridged mind, and the requester's to show to whom it will.
    expect(judgeRecord(receipt).ok).toBe(true);
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
      // The agent's words are in the packet, as what the agent said. The Receipt has their digest.
      expect(told?.parts.slice(0, -1)).toStrictEqual([{ mediaType: "text/plain", body: words }]);
      const receipt = receiptIn(told);
      expect(receipt).toMatchObject({
        type: "Receipt",
        outcome,
        about: `${amina}/${request}`,
        // The statement is the gateway's own sentence, and nothing of the agent's but the task's name.
        statement: `The gateway observed the A2A agent at ${LEXIS} report task "${lexis.last.id}" as ${reported}.`,
        evidence: [
          {
            kind: "hash",
            ref: `a2a:task/${lexis.last.id}/status/part/0`,
            digest: sha256Digest(utf8(words)),
            mediaType: "text/plain",
          },
        ],
      });
    },
  );

  it(`${clause("L0 3.1")} is declined with a packet where the agent rejects the task, and no Receipt is signed`, async () => {
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
      // A file is named as its URL names it.
      { url: LEASE, mediaType: "application/pdf", filename: "lease.pdf" },
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
            body: left("one part"),
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

  it(`${clause("L0 3.1")} comes back as a request where the agent needs the requester to sign in, with all the agent gives: a form or a URL as much as its words`, async () => {
    const signIn = await send(bridged, "sign-in");
    expect(await relay()).toMatchObject({ sent: [{ verb: "request" }], open: 1 });
    expect(await inbox()).toMatchObject([
      {
        verb: "request",
        replyTo: signIn,
        parts: [
          { mediaType: "text/plain", body: "Sign in first." },
          // A URL that nothing attests is passed on as the text it is.
          { mediaType: "text/uri-list", body: "https://lexis.example/sign-in?task=1" },
        ],
      },
    ]);
    lexis.last.status = { state: "TASK_STATE_REJECTED" };
    await relay();
    await inbox();

    const request = await send(bridged, "wordy");
    expect(await relay()).toMatchObject({ sent: [{ verb: "request" }], open: 1 });
    const [question] = await inbox();
    expect(question).toMatchObject({ verb: "request", replyTo: request });
    expect(question?.parts).toStrictEqual([
      { mediaType: "application/json", body: '{"form":"sign-in"}' },
      { mediaType: "text/plain", body: "w".repeat(2000) },
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

  it("is a context of each requester's own: two minds in one session share nothing of what the agent keeps", async () => {
    // A session of three: Amina, Bilal and the bridged mind.
    const bilal = await place.mind("bilal");
    const amina_ = await place.mind("amina");
    let session: string;
    try {
      session = (await amina_.mind.openSession([bridged, bilal.mind.address])).id;
      const first = await amina_.mind.send({
        to: [bridged, bilal.mind.address],
        verb: "request",
        content: { mediaType: "text/plain", body: "reject" },
        session,
      });
      expect(await relay()).toMatchObject({ passed: [first.id], failed: [] });
      // The agent made a context for Amina's request, and the gateway keeps it for her next.
      const context = lexis.last.contextId;
      expect(lexis.asked.at(-1)?.params["message"]).not.toHaveProperty("contextId");
      // Bilal has the session now, and asks in it.
      await bilal.mind.receive();
      const second = await bilal.mind.send({
        // A packet of a session is for everyone else in it (Layer 1, 14.3).
        to: [bridged, amina],
        verb: "request",
        content: { mediaType: "text/plain", body: "reject" },
        session,
      });
      expect(await relay()).toMatchObject({ passed: [second.id], failed: [] });
      // His request is of no context yet: what the agent keeps for Amina is not his.
      expect(lexis.asked.at(-1)?.params["message"]).not.toHaveProperty("contextId");
      expect(lexis.last.contextId).not.toBe(context);
      // Amina's next is of hers.
      const third = await amina_.mind.send({
        to: [bridged, bilal.mind.address],
        verb: "request",
        content: { mediaType: "text/plain", body: "reject" },
        session,
      });
      expect(await relay()).toMatchObject({ passed: [third.id], failed: [] });
      expect(lexis.asked.at(-1)?.params["message"]).toMatchObject({ contextId: context });
      await bilal.mind.receive();
    } finally {
      bilal.mind.close();
      amina_.mind.close();
    }
    await inbox();
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
  it(`${clause("L0 1.4")} is quoted where it is in a Receipt's statement: an agent's name for a task is never the gateway's words, and the agent's words are not in the statement at all`, async () => {
    const request = await send(bridged, "sly");
    const did = await relay();
    expect(did).toMatchObject({ receipts: [{ outcome: "broken", about: request }], failed: [] });
    const [told] = await inbox();
    const receipt = receiptIn(told);
    const statement = receipt["statement"] as string;
    // One line of printable ASCII: nothing in it that a display acts on, turns round or hides,
    // and no quotation mark but ASCII's own, which is escaped.
    expect(statement).toMatch(/^[\x20-\x7e]+$/u);
    // The gateway's words are around one string of JSON, which reads back as the agent's.
    const said =
      /^The gateway observed the A2A agent at https:\/\/lexis\.example report task ("(?:[^"\\]|\\.)*") as failed\.$/u.exec(
        statement,
      );
    expect(said).not.toBeNull();
    expect(JSON.parse(said?.[1] ?? "null")).toBe(lexis.last.id);
    expect(lexis.last.id.startsWith(SLY_NAME)).toBe(true);
    // What the agent said is what the agent delivered: content of the packet, and its digest in the Receipt.
    expect(told?.parts.slice(0, -1)).toStrictEqual([{ mediaType: "text/plain", body: SLY_WORDS }]);
    expect(receipt["evidence"]).toMatchObject([
      { kind: "hash", digest: sha256Digest(utf8(SLY_WORDS)) },
    ]);
    // Where the evidence names the task, the name is ASCII too.
    expect((receipt["evidence"] as { ref: string }[])[0]?.ref).toMatch(
      /^a2a:task\/[\x21-\x7e]+\/status\/part\/0$/u,
    );
    expect(judgeRecord(receipt).ok).toBe(true);
  });

  it(`${clause("core 1.1", "core 1.6")} is made what a record holds where it is not: a requester is answered whatever the agent wrote`, async () => {
    // A character no record holds, and half a pair of surrogates, in a text and in a URL.
    const garbled = await send(bridged, "garbled");
    expect(await relay()).toMatchObject({
      passed: [garbled],
      sent: [{ verb: "inform" }],
      failed: [],
    });
    expect(await inbox()).toMatchObject([
      {
        verb: "inform",
        replyTo: garbled,
        parts: [
          { mediaType: "text/plain", body: `caf${REPLACED}${REPLACED}e` },
          { mediaType: "text/uri-list", body: "https://files.lexis.example/a%EF%BF%BDb" },
        ],
      },
    ]);
    // 200,000 control characters are 1.2 MB of a record's canonical form: more than a packet is.
    const flood = await send(bridged, "flood");
    expect(await relay()).toMatchObject({
      passed: [flood],
      sent: [{ verb: "inform" }],
      failed: [],
    });
    const noReceipt = left("one part");
    expect(await inbox()).toMatchObject([
      {
        replyTo: flood,
        parts: [
          { mediaType: "text/plain", body: "After the flood." },
          { mediaType: "text/plain", body: noReceipt },
        ],
      },
    ]);
    // Data nested deeper than can be walked has no JSON text.
    const deep = await send(bridged, "deep");
    expect(await relay()).toMatchObject({ passed: [deep], sent: [{ verb: "inform" }], failed: [] });
    expect(await inbox()).toMatchObject([
      {
        replyTo: deep,
        parts: [
          { mediaType: "text/plain", body: "After the deep." },
          { mediaType: "text/plain", body: noReceipt },
        ],
      },
    ]);
    // Each was asked of the agent once, and nothing waits.
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 0 });
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
      // What is no URL of the web is left out, and nothing attests it: the packet does not say
      // that the Receipt does.
      { mediaType: "text/plain", body: left("2 parts") },
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

  it(`${clause("L0 1.4", "L2 6.1")} says of what a packet leaves out what the Receipt has of it, and no more: a Receipt has room for so many evidence items`, async () => {
    const request = await send(bridged, "seventy");
    const did = await relay();
    expect(did).toMatchObject({ receipts: [{ outcome: "fulfilled", about: request }], failed: [] });
    const [delivered] = await inbox();
    // Thirty parts are carried, with the word about the rest and the Receipt: thirty-two in all.
    expect(delivered?.parts).toHaveLength(32);
    expect(delivered?.parts[29]).toStrictEqual({ mediaType: "text/plain", body: "Part 29." });
    // Seventy-two parts, sixty-four evidence items: of the forty-two left out, thirty-four have one.
    expect(delivered?.parts[30]).toStrictEqual({
      mediaType: "text/plain",
      body: `${left("42 parts")} The Receipt has the digests of 34 of them.`,
    });
    const receipt = receiptIn(delivered);
    const evidence = receipt["evidence"] as { digest: string }[];
    expect(evidence).toHaveLength(64);
    expect(evidence[63]?.digest).toBe(sha256Digest(utf8("Part 63.")));
    expect(judgeRecord(receipt).ok).toBe(true);
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

  it(`${clause("L0 1.4")} signs one Receipt for a task, whatever stops it: the next pass brings the one that was signed, and the agent's files are fetched once`, async () => {
    const request = await send(bridged, "sly-files");
    const urls = [0, 1, 2].map((n) => `${LEASE}?sly=${String(n)}`);
    const first = await relay(LEXIS, cutOffOnceAsked(lexis));
    // The agent was asked, the task had ended, and nothing could be sent.
    expect(first).toMatchObject({ passed: [request], receipts: [], sent: [], open: 1 });
    expect(first.failed).toMatchObject([{ task: lexis.last.id }]);
    expect(await inbox()).toStrictEqual([]);
    expect(urls.map((url) => fetched.get(url))).toStrictEqual([1, 1, 1]);
    const kept = tasksOf(LEXIS).get(lexis.last.id) as { settled?: { receipt: JsonObject } };
    const asked = lexis.asked.length;

    const second = await relay();
    expect(second).toMatchObject({
      passed: [],
      receipts: [{ outcome: "fulfilled", about: request }],
      sent: [{ verb: "deliver" }],
      failed: [],
      open: 0,
    });
    // The agent is not asked again, and its files are not fetched again: what it reported was
    // written down when the gateway saw it.
    expect(lexis.asked).toHaveLength(asked);
    expect(urls.map((url) => fetched.get(url))).toStrictEqual([1, 1, 1]);
    const [delivered] = await inbox();
    const receipt = receiptIn(delivered);
    expect(contentId(receipt)).toBe(second.receipts[0]?.id);
    // It is the Receipt of the pass that stopped, if that pass came to sign one.
    if (kept.settled !== undefined) expect(receipt).toStrictEqual(kept.settled.receipt);
    expect(receipt["evidence"]).toHaveLength(3);
    expect(judgeRecord(receipt).ok).toBe(true);
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 0 });
  });

  it("brings an answer that the agent gave at once, though the pass stopped before it was sent: the agent is not asked twice", async () => {
    const request = await send(bridged, "hello");
    const first = await relay(LEXIS, cutOffOnceAsked(lexis));
    expect(first).toMatchObject({ passed: [request], sent: [], open: 0 });
    expect(first.failed).toMatchObject([{ packet: request }]);
    expect(await inbox()).toStrictEqual([]);
    const asked = lexis.asked.length;
    expect(await relay()).toMatchObject({ passed: [], sent: [{ verb: "inform" }], failed: [] });
    expect(lexis.asked).toHaveLength(asked);
    expect(await inbox()).toMatchObject([
      { verb: "inform", replyTo: request, parts: [{ body: "Hello to you." }] },
    ]);
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 0 });
  });

  it("tells the requester where the agent no longer knows the task, and signs nothing of it", async () => {
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

  it("asks an agent that cannot be reached once in a pass, and not again for each request that waits", async () => {
    const first = await send(bridged, "hello");
    await new Promise((resolve) => setTimeout(resolve, 5));
    const second = await send(bridged, "hello");
    const slow = lexis.working("task-waiting");
    tasksOf(LEXIS).put(slow.id, {
      requester: amina,
      request: contentId({ a: "request that waits" }),
      since: new Date().toISOString(),
    });
    const tried = lexis.tried;
    lexis.down = true;
    try {
      // One try, one failure: the second request and the task wait without a word.
      expect(await relay()).toStrictEqual({
        ...NOTHING,
        failed: [{ packet: first, message: "the agent is not to be reached" }],
        open: 1,
      });
      expect(lexis.tried).toBe(tried + 1);
    } finally {
      lexis.down = false;
    }
    expect(await relay()).toMatchObject({ passed: [first, second], failed: [], open: 1 });
    expect(await inbox()).toHaveLength(2);
    tasksOf(LEXIS).delete(slow.id);
  });

  it("does as much in a pass as the pass has time for, and leaves the rest for the next", async () => {
    const first = await send(bridged, "hello");
    await new Promise((resolve) => setTimeout(resolve, 5));
    const second = await send(bridged, "hello");
    const tried = lexis.tried;
    // A pass that has no time reads the mailbox, so that nothing is lost, and asks nothing.
    expect(await relay(LEXIS, {}, () => true)).toStrictEqual({ ...NOTHING, open: 0 });
    expect(lexis.tried).toBe(tried);
    // One that has time for one piece of work does one.
    let pieces = 0;
    expect(await relay(LEXIS, {}, () => pieces++ >= 1)).toMatchObject({ passed: [first] });
    expect(await relay()).toMatchObject({ passed: [second], failed: [] });
    expect(await inbox()).toHaveLength(2);
  });

  it(`${clause("L1 12.4")} tells a requester whose request expired before the agent could be reached, and does not ask the agent for what nobody waits for`, async () => {
    const request = await send(bridged, "translate", { expiresIn: 60 });
    lexis.down = true;
    try {
      expect(await relay()).toMatchObject({ failed: [{ packet: request }], open: 0 });
    } finally {
      lexis.down = false;
    }
    const tried = lexis.tried;
    // Within the allowance a receiver makes for two clocks, it is asked still. Here it would
    // be: so the look is taken with a pass that has no time to ask.
    const soon = { now: () => BigInt(Date.now() + 200_000) * 1_000_000n };
    expect(await relay(LEXIS, { clock: soon }, () => true)).toMatchObject({ sent: [], open: 0 });
    // Ten minutes on, the request has expired, with the allowance.
    const later = { now: () => BigInt(Date.now() + 600_000) * 1_000_000n };
    const did = await relay(LEXIS, { clock: later });
    expect(did).toMatchObject({ passed: [], sent: [{ verb: "error", to: amina }], open: 0 });
    expect(lexis.tried).toBe(tried);
    // It waits no more.
    expect(new Store<JsonObject>(join(agentDir(LEXIS), "pending")).all()).toStrictEqual([]);
    expect(await relay()).toMatchObject({ passed: [], open: 0 });
    expect(lexis.tried).toBe(tried);
  });

  it(`${clause("L1 12.1")} lets a request that names no time of its own wait a day, and no longer`, async () => {
    const session = await openSession();
    const request = await send(bridged, "hello", { session });
    lexis.down = true;
    try {
      expect(await relay()).toMatchObject({ failed: [{ packet: request }] });
    } finally {
      lexis.down = false;
    }
    // As far as the gateway's directory says, the packet came two days ago.
    const pending = new Store<JsonObject>(join(agentDir(LEXIS), "pending"));
    const kept = pending.get(request);
    expect(kept?.["packet"]).not.toHaveProperty("expires");
    pending.put(request, {
      ...kept,
      time: new Date(Date.now() - 2 * 86_400_000).toISOString().replace("Z", "000000Z"),
    });
    const tried = lexis.tried;
    expect(await relay()).toMatchObject({ passed: [], sent: [{ verb: "error" }], failed: [] });
    expect(lexis.tried).toBe(tried);
    expect(await inbox()).toMatchObject([
      {
        verb: "error",
        replyTo: request,
        session,
        parts: [
          {},
          {
            body: `The gateway could not pass this request on to the agent at ${LEXIS} before it expired. The agent was not asked.`,
          },
        ],
      },
    ]);
  });

  it("tells a requester whose request the agent answers with a task it took on for another, and follows that task for the first alone", async () => {
    const first = await send(bridged, "slow");
    expect(await relay()).toMatchObject({ passed: [first], open: 1 });
    const task = lexis.last.id;
    const second = await send(bridged, "reuse", { from: "bilal" });
    // The second requester is told at once. The task is followed on in the same pass, and has
    // ended meanwhile: the first requester has its Receipt.
    expect(await relay()).toMatchObject({
      passed: [second],
      sent: [{ verb: "error" }, { verb: "deliver", to: amina }],
      receipts: [{ about: first }],
      open: 0,
    });
    expect(await inbox("bilal")).toMatchObject([
      {
        verb: "error",
        replyTo: second,
        parts: [
          {
            body: `The agent at ${LEXIS} answered this request with a task it took on for another. The gateway does not follow it for this one.`,
          },
        ],
      },
    ]);
    // The task was the first requester's still, and ended for the first alone.
    expect(tasksOf(LEXIS).get(task)).toBeUndefined();
    expect(await inbox()).toMatchObject([{ verb: "deliver", replyTo: first }]);
    expect(await inbox("bilal")).toStrictEqual([]);
  });

  it("says in its own words what it cannot carry, where what was written down is nothing a record holds: nothing is tried for ever", async () => {
    const answers = new Store<JsonObject>(join(agentDir(LEXIS), "answers"));
    const tasks = tasksOf(LEXIS);
    const since = new Date().toISOString();
    const unsound = [{ mediaType: "text/plain", body: `caf${NONCHARACTER}e` }];
    // An answer, a task that ended, and a task with its Receipt signed, each as a gateway of
    // another day might have written them down.
    const answered = contentId({ a: "request answered" });
    answers.put(answered, { requester: amina, request: answered, since, content: unsound });
    const ended = contentId({ a: "request of a task that ended" });
    tasks.put("task-unsound", {
      requester: amina,
      request: ended,
      since,
      ended: {
        outcome: "fulfilled",
        reported: "completed",
        content: [],
        evidence: [{ kind: "hash", ref: `a${NONCHARACTER}`, digest: sha256Digest(utf8("x")) }],
      },
    });
    const settled = contentId({ a: "request of a task with a Receipt" });
    const opened = await openMind({ edges: place.machine(), dir: agentDir(LEXIS) });
    let receipt: JsonObject;
    try {
      receipt = (await opened.mind.receipt({
        about: `${amina}/${settled}`,
        outcome: "fulfilled",
        statement: "The gateway observed the agent report a task as completed.",
      })) as unknown as JsonObject;
    } finally {
      opened.mind.close();
    }
    tasks.put("task-settled", {
      requester: amina,
      request: settled,
      since,
      settled: { receipt, outcome: "fulfilled", verb: "deliver", content: unsound },
    });
    const tried = lexis.tried;
    const did = await relay();
    expect(did).toMatchObject({
      receipts: [{ id: contentId(receipt), about: settled }],
      failed: [],
      open: 0,
    });
    // In whatever order the tasks were come to.
    expect(did.sent.map(({ verb }) => verb).sort()).toStrictEqual(["deliver", "error", "error"]);
    // The agent was asked nothing: each was past asking.
    expect(lexis.tried).toBe(tried);
    const cannot = `The agent at ${LEXIS} answered, and the gateway cannot carry its answer: it is nothing a packet holds.`;
    const told = await inbox();
    expect(told.find(({ replyTo }) => replyTo === answered)).toMatchObject({
      verb: "error",
      parts: [{ body: cannot }],
    });
    expect(told.find(({ replyTo }) => replyTo === ended)).toMatchObject({
      verb: "error",
      parts: [
        {
          body: `The agent at ${LEXIS} reported task "task-unsound" as completed, and the gateway could not make a Receipt of what it was shown.`,
        },
      ],
    });
    // The Receipt that was signed is brought all the same.
    const brought = told.find(({ replyTo }) => replyTo === settled);
    expect(brought).toMatchObject({ verb: "deliver", parts: [{ body: cannot }, {}] });
    expect(receiptIn(brought)).toStrictEqual(receipt);
    expect(answers.all()).toStrictEqual([]);
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 0 });
  });

  it("brings no more what it could not bring in thirty days", async () => {
    const answers = new Store<JsonObject>(join(agentDir(LEXIS), "answers"));
    const tasks = tasksOf(LEXIS);
    const long = new Date(Date.now() - 31 * 86_400_000).toISOString();
    const request = contentId({ a: "request of long ago" });
    const said = [{ mediaType: "text/plain", body: "An answer of long ago." }];
    answers.put(request, { requester: amina, request, since: long, content: said });
    tasks.put("task-of-long-ago", {
      requester: amina,
      request,
      since: long,
      settled: {
        receipt: { type: "Receipt" },
        outcome: "fulfilled",
        verb: "deliver",
        content: said,
      },
    });
    expect(await relay()).toStrictEqual({ ...NOTHING, open: 0 });
    expect(answers.all()).toStrictEqual([]);
    expect(await inbox()).toStrictEqual([]);
  });

  it(`${clause("L2 10.2")} publishes nothing of what it relayed: a Receipt is the requester's, and the feed does not say who asked`, async () => {
    // Every Receipt of the tests above was brought to its requester. None is on the feed, where
    // anyone would read who asked the agent, when, and the agent's name for the task.
    const listed = await published();
    expect(listed.filter((type) => type === "Receipt" || type === "Packet")).toStrictEqual([]);
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
