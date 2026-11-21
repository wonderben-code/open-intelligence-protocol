// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind served as an A2A agent (Layer 0, 3.2), on a real resolver, host
 * and indexer: an A2A client asks over JSON-RPC, the gateway says it to
 * the mind in packets, and the mind answers as any mind does.
 */

import { carried, type Message, type Received, systemClock } from "@oip/client";
import { contentId, type JsonObject } from "@oip/core";
import { judgeRecord } from "@oip/identity";
import { fileNameOf, type Opened, openMind } from "@oip/local";
import { join } from "node:path";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Book, MAX_TASKS } from "../src/book.ts";
import { A2aServer, Front, MAX_REQUEST_BYTES, OIP_EXTENSION } from "../src/index.ts";
import { wrongAs } from "./conformance.ts";
import { Place } from "./harness.ts";

const BASE = "https://gateway.example/a2a";
const ERROR_INFO = "type.googleapis.com/google.rpc.ErrorInfo";

let place: Place;
let gateway: Opened;
let front: Front;
let server: A2aServer;
/** The gateway's address, and the address and the ID of the mind it serves. */
let own: string;
let mina: string;
let id: string;
/** What went wrong inside the gateway, as it was told to whoever logs. */
const failures: unknown[] = [];

const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

beforeAll(async () => {
  place = await new Place().start();
  own = await place.make("gateway", { kind: "service" });
  mina = await place.make("mina", { kind: "agent" });
  id = mina.slice("did:oip:".length);
  const opened = await place.mind("mina");
  try {
    // The mind asks to be served: its profile lists the card this gateway serves for it.
    await opened.mind.publishProfile({
      name: "Mina",
      summary: "Translates legal texts between Swahili and English.",
      capabilities: [
        { id: "translate", summary: "Translates a lease", tags: ["legal:translation"] },
        {
          id: "certify",
          summary:
            "Certifies that a translation of a legal text says what the text it was made of says.",
        },
      ],
      interfaces: { a2a: `${BASE}/${id}/.well-known/agent-card.json` },
    });
  } finally {
    opened.mind.close();
  }
  // A mind with a profile that asks for nothing.
  await place.make("bilal", { profile: { name: "Bilal" } });
  gateway = await place.mind("gateway");
  // A client that waits is kept waiting for as long as the gateway lets one wait where nobody
  // says how long: every mind of these tests answers long before that.
  front = new Front({ opened: gateway, base: BASE, version: "1.2.3", clock: systemClock });
  server = new A2aServer(front, "/a2a", (error) => failures.push(error));
});
afterAll(async () => {
  gateway.mind.close();
  await place.close();
});

interface Reply {
  jsonrpc: string;
  id: unknown;
  result?: Record<string, unknown>;
  error?: { code: number; message: string; data?: Record<string, unknown>[] };
}

/** Asks the mind's A2A interface, as a client that speaks A2A 1.0. */
async function ask(
  method: string,
  params: unknown,
  headers: Record<string, string> = { "a2a-version": "1.0" },
  path = `/a2a/${id}`,
): Promise<Reply> {
  const answer = await server.handle({
    method: "POST",
    path,
    headers: { "content-type": "application/json", ...headers },
    body: utf8(JSON.stringify({ jsonrpc: "2.0", id: 7, method, params })),
  });
  expect(answer.status).toBe(200);
  expect(answer.headers["content-type"]).toBe("application/json");
  const reply = JSON.parse(new TextDecoder().decode(answer.body)) as Reply;
  // Every result is held against the A2A project's own schema of it.
  const shape = SHAPES[method];
  if (reply.result !== undefined && shape !== undefined) {
    expect(
      wrongAs(shape, reply.result),
      `${method}: ${JSON.stringify(reply.result)}`,
    ).toStrictEqual([]);
  }
  return reply;
}

/** What the result of each method is, by the title the A2A project's schema gives it. */
const SHAPES: Readonly<Record<string, string>> = {
  SendMessage: "Send Message Response",
  GetTask: "Task",
  CancelTask: "Task",
  ListTasks: "List Tasks Response",
};

let sent = 0;
/** A message of a client's, with a text. */
const message = (text: string, more: Record<string, unknown> = {}): Record<string, unknown> => ({
  messageId: `m-${String(++sent)}`,
  role: "ROLE_USER",
  parts: [{ text }],
  ...more,
});

/** What the mind does with a packet that reached it: what it answers with, if it answers. */
type Answering = (got: Received) => Pick<Message, "verb" | "content"> | undefined;

/** What reached the mind, and the packets it answered with, by content ID. */
interface Heard {
  readonly reached: Received[];
  readonly answers: string[];
}

/**
 * The mind reads its mailbox until something is there, answers each
 * packet, and the gateway reads its own mailbox after.
 */
async function minaAnswers(answering: Answering): Promise<Heard> {
  const opened = await place.mind("mina");
  try {
    for (let tries = 0; tries < 200; tries++) {
      const { received } = await opened.mind.receive();
      const answers: string[] = [];
      for (const got of received) {
        const answer = answering(got);
        if (answer === undefined) continue;
        const sent = await opened.mind.send({
          ...answer,
          to: [got.from],
          replyTo: got.id,
          ...(got.packet.session === undefined ? {} : { session: got.packet.session }),
        });
        answers.push(sent.id);
      }
      if (received.length > 0) {
        await front.pump();
        return { reached: [...received], answers };
      }
      await sleep(20);
    }
    throw new Error("nothing reached the mind");
  } finally {
    opened.mind.close();
  }
}

/** The first packet that reaches a mind that is open. */
async function firstTo(opened: Opened): Promise<Received> {
  for (;;) {
    const [first] = (await opened.mind.receive()).received;
    if (first !== undefined) return first;
    await sleep(20);
  }
}

/**
 * A front for the gateway's mind with some of what the mind does done
 * otherwise: for what a real network does not do when asked.
 */
function frontWith(otherwise: Record<string, unknown>): Front {
  const mind = new Proxy(gateway.mind, {
    get: (target, name) => {
      if (typeof name === "string" && name in otherwise) return otherwise[name];
      const value: unknown = Reflect.get(target, name, target);
      return typeof value === "function" ? (value.bind(target) as unknown) : value;
    },
  });
  return new Front({ opened: { ...gateway, mind }, base: BASE, version: "1", clock: systemClock });
}

const text = (body: string): Pick<Message, "content"> => ({
  content: { mediaType: "text/plain", body },
});

/** A client sends a message and waits, and the mind answers it. */
async function exchange(
  params: Record<string, unknown>,
  answering: Answering,
): Promise<Heard & { reply: Reply }> {
  const asking = ask("SendMessage", params);
  const heard = await minaAnswers(answering);
  return { reply: await asking, ...heard };
}

const taskOf = (reply: Reply): { id: string; contextId: string; status: { state: string } } =>
  reply.result?.["task"] as { id: string; contextId: string; status: { state: string } };

describe("the Agent Card of a mind", () => {
  const card = (path: string, headers: Record<string, string> = {}, method = "GET") =>
    server.handle({ method, path, headers, body: new Uint8Array() });

  it(`${clause("L0 3.2")} is made of the mind's profile, at a URL of the mind's own: capabilities are skills, and the host gives the version, the interface and the modes`, async () => {
    const answer = await card(`/a2a/${id}/.well-known/agent-card.json`);
    expect(answer.status).toBe(200);
    expect(answer.headers["content-type"]).toBe("application/json");
    // It is a card as the A2A project's own schema has one.
    expect(wrongAs("Agent Card", JSON.parse(new TextDecoder().decode(answer.body)))).toStrictEqual(
      [],
    );
    expect(JSON.parse(new TextDecoder().decode(answer.body))).toStrictEqual({
      name: "Mina",
      description: "Translates legal texts between Swahili and English.",
      supportedInterfaces: [
        { url: `${BASE}/${id}`, protocolBinding: "JSONRPC", protocolVersion: "1.0" },
      ],
      version: "1.2.3",
      capabilities: {
        streaming: false,
        pushNotifications: false,
        extensions: [
          {
            uri: OIP_EXTENSION,
            description:
              "A message may carry a whole, signed OIP packet as a data part of media type application/oip+json.",
            required: false,
          },
        ],
      },
      defaultInputModes: ["text/plain", "application/json", "application/oip+json"],
      defaultOutputModes: ["text/plain", "application/json", "application/oip+json"],
      skills: [
        // A capability's summary is the skill's name too where it is short enough to be one.
        {
          id: "translate",
          name: "Translates a lease",
          description: "Translates a lease",
          tags: ["legal:translation"],
        },
        {
          id: "certify",
          name: "certify",
          description:
            "Certifies that a translation of a legal text says what the text it was made of says.",
          tags: [],
        },
      ],
    });
  });

  it("is served so that a cache can keep it, and is not sent again to one that has it", async () => {
    const answer = await card(`/a2a/${id}/.well-known/agent-card.json`);
    const { etag = "" } = answer.headers;
    expect(answer.headers).toMatchObject({ "cache-control": "public, max-age=300" });
    expect(etag).toMatch(/^"[0-9a-f]{32}"$/u);
    expect(new Date(answer.headers["last-modified"] ?? "").getTime()).toBeGreaterThan(0);
    const again = await card(`/a2a/${id}/.well-known/agent-card.json`, { "if-none-match": etag });
    expect(again).toMatchObject({ status: 304, headers: { etag } });
    expect(again.body).toHaveLength(0);
    const other = await card(`/a2a/${id}/.well-known/agent-card.json`, {
      "if-none-match": '"another"',
    });
    expect(other.status).toBe(200);
  });

  it(`${clause("L0 3.2")} is served for no mind that does not list it in its profile: a gateway speaks for no mind that did not ask`, async () => {
    const bilal = (await place.mind("bilal")).mind;
    const other = bilal.address.slice("did:oip:".length);
    bilal.close();
    expect((await card(`/a2a/${other}/.well-known/agent-card.json`)).status).toBe(404);
    const asked = await server.handle({
      method: "POST",
      path: `/a2a/${other}`,
      headers: { "a2a-version": "1.0" },
      body: utf8('{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"t"}}'),
    });
    expect(asked.status).toBe(404);
    // No mind at all, and what is no ID of one.
    const nobody = contentId({ nobody: true });
    expect((await card(`/a2a/${nobody}/.well-known/agent-card.json`)).status).toBe(404);
    expect((await card("/a2a/not-a-mind/.well-known/agent-card.json")).status).toBe(404);
  });

  it("is served for no mind that has retired: such a mind asks nothing more of anyone", async () => {
    const address = await place.make("gone");
    const gone = address.slice("did:oip:".length);
    const opened = await place.mind("gone");
    try {
      await opened.mind.publishProfile({
        name: "Gone",
        interfaces: { a2a: `${BASE}/${gone}/.well-known/agent-card.json` },
      });
      // It asked, and is served. What was found out of a mind is gone by for a minute.
      expect((await card(`/a2a/${gone}/.well-known/agent-card.json`)).status).toBe(200);
      await opened.mind.retire({ control: opened.lock });
    } finally {
      opened.mind.close();
    }
    expect((await card(`/a2a/${gone}/.well-known/agent-card.json`)).status).toBe(200);
    // A gateway that asks afresh finds the mind retired.
    const fresh = new A2aServer(
      new Front({ opened: gateway, base: BASE, version: "1", clock: systemClock }),
      "/a2a",
    );
    const answer = await fresh.handle({
      method: "GET",
      path: `/a2a/${gone}/.well-known/agent-card.json`,
      headers: {},
      body: new Uint8Array(),
    });
    expect(answer.status).toBe(404);
  });

  it("is not answered for where the mind's records cannot be asked for: that is no answer of no", async () => {
    // A gateway that cannot reach its resolver.
    const cut = { off: false };
    const opened = await openMind(
      place.where("gateway", {
        fetch: (asked) =>
          cut.off && new URL(asked.url).pathname.includes("/resolve/")
            ? Promise.reject(new TypeError("fetch failed"))
            : fetch(asked),
      }),
    );
    // The mind is open: from here on its resolver is away.
    cut.off = true;
    try {
      const away = new A2aServer(
        new Front({ opened, base: BASE, version: "1", clock: systemClock }),
        "/a2a",
        (error) => failures.push(error),
      );
      const answer = await away.handle({
        method: "GET",
        path: `/a2a/${id}/.well-known/agent-card.json`,
        headers: {},
        body: new Uint8Array(),
      });
      expect(answer.status).toBe(500);
      expect(failures.splice(0)).toHaveLength(1);
    } finally {
      opened.mind.close();
    }
  });

  it("is at its path alone, and is fetched with GET", async () => {
    expect((await card(`/a2a/${id}/agent-card.json`)).status).toBe(404);
    expect((await card(`/elsewhere/${id}/.well-known/agent-card.json`)).status).toBe(404);
    expect((await card("/a2a")).status).toBe(404);
    expect((await card(`/a2a/${id}/.well-known/agent-card.json`, {}, "POST")).status).toBe(405);
    // The interface itself takes POST alone.
    expect((await card(`/a2a/${id}`)).status).toBe(405);
  });
});

describe("a message of an A2A client for a mind", () => {
  it(`${clause("L0 3.2", "L0 3.1", "L0 1.4")} is said to the mind in a packet of the gateway's with verb \`request\`, in a session of its own, and the gateway says whose words it carries`, async () => {
    const asked = message("Please translate the lease.");
    const { reply, reached } = await exchange({ message: asked }, () => ({
      verb: "deliver",
      ...text("Here is the lease in English."),
    }));
    expect(reached).toHaveLength(1);
    const [first] = reached;
    if (first === undefined) throw new Error("nothing reached the mind");
    const { from, packet } = first;
    expect(from).toBe(own);
    const task = taskOf(reply);
    expect(packet).toMatchObject({
      type: "Packet",
      from: own,
      to: [mina],
      purpose: {
        verb: "request",
        goal: "A message of an A2A client, passed on by the gateway.",
      },
      // The task is the thread, and the message it stands for is named.
      thread: task.id,
      context: { refs: [`a2a:message/${String(asked["messageId"])}`] },
      seq: 0,
    });
    // Layer 0, 3.1: a context is a session. The first packet of one carries the record that names it.
    expect(packet.session).toMatch(/^bciq/u);
    expect(packet.content).toMatchObject({
      parts: [
        { mediaType: "application/oip+json", body: { type: "Session" } },
        { mediaType: "text/plain", body: "Please translate the lease." },
      ],
    });
    expect(judgeRecord(packet).ok).toBe(true);
  });

  it(`${clause("L0 3.1")} is a task that is completed where the mind answers with verb \`deliver\`, and what it delivered is an artifact`, async () => {
    const asked = message("Translate.");
    const { reply, reached, answers } = await exchange({ message: asked }, () => ({
      verb: "deliver",
      content: {
        parts: [
          { mediaType: "text/plain", body: "The lease in English." },
          { mediaType: "application/json", body: { pages: 2 } },
          {
            mediaType: "application/pdf",
            ref: "https://files.example/out/lease%20en.pdf",
            digest: `sha256:${"ab".repeat(32)}`,
          },
        ],
      },
    }));
    expect(reply).toMatchObject({ jsonrpc: "2.0", id: 7 });
    const task = reply.result?.["task"] as Record<string, unknown>;
    expect(task["id"]).toMatch(/^[0-9a-f-]{36}$/u);
    expect(task["contextId"]).toMatch(/^[0-9a-f-]{36}$/u);
    const status = task["status"] as Record<string, unknown>;
    expect(status).toStrictEqual({ state: "TASK_STATE_COMPLETED", timestamp: status["timestamp"] });
    expect(status["timestamp"]).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u);
    const [answer] = answers;
    expect(task["artifacts"]).toStrictEqual([
      {
        // The mind's packet names the artifact.
        artifactId: answer,
        parts: [
          { text: "The lease in English.", mediaType: "text/plain" },
          { data: { pages: 2 }, mediaType: "application/json" },
          {
            url: "https://files.example/out/lease%20en.pdf",
            mediaType: "application/pdf",
            filename: "lease en.pdf",
          },
        ],
      },
    ]);
    // What the client said is the task's history.
    expect(task["history"]).toStrictEqual([
      { ...asked, contextId: task["contextId"], taskId: task["id"] },
    ]);
    expect(reached).toHaveLength(1);
  });

  it(`${clause("L0 3.2")} is answered with a message, and no task, where the mind answers with verb \`inform\``, async () => {
    const { reply, answers } = await exchange(
      { message: message("What do you translate?") },
      () => ({ verb: "inform", ...text("Leases, between Swahili and English.") }),
    );
    expect(reply.result).toStrictEqual({
      message: {
        messageId: answers[0],
        role: "ROLE_AGENT",
        parts: [{ text: "Leases, between Swahili and English.", mediaType: "text/plain" }],
        // A2A, 3.4.1: the context the agent made for the message is in the answer.
        contextId: (reply.result?.["message"] as JsonObject)["contextId"],
      },
    });
    expect((reply.result?.["message"] as JsonObject)["contextId"]).toMatch(/^[0-9a-f-]{36}$/u);
  });

  it.each([
    ["decline", "TASK_STATE_REJECTED", "I translate no wills."],
    ["error", "TASK_STATE_FAILED", "The text could not be read."],
    ["request", "TASK_STATE_INPUT_REQUIRED", "Into which language?"],
  ])(
    `${clause("L0 3.1")} is a task where the mind answers with verb \`%s\`: %s, with the mind's words`,
    async (verb, state, words) => {
      const { reply, answers } = await exchange({ message: message("Translate.") }, () => ({
        verb,
        ...text(words),
      }));
      const task = reply.result?.["task"] as Record<string, unknown>;
      const said = {
        messageId: answers[0],
        role: "ROLE_AGENT",
        parts: [{ text: words, mediaType: "text/plain" }],
        contextId: task["contextId"],
        taskId: task["id"],
      };
      expect(task["status"]).toMatchObject({ state, message: said });
      expect(task).not.toHaveProperty("artifacts");
      expect((task["history"] as unknown[]).at(-1)).toStrictEqual(said);
    },
  );

  it.each([
    ["fulfilled", "deliver", "TASK_STATE_COMPLETED"],
    ["broken", "inform", "TASK_STATE_FAILED"],
    ["cancelled", "inform", "TASK_STATE_CANCELED"],
  ])(
    `${clause("L0 3.1")} is a task that ends as a Receipt of the mind's about the request says: outcome \`%s\``,
    async (outcome, verb, state) => {
      const asking = ask("SendMessage", { message: message("Translate.") });
      const opened = await place.mind("mina");
      try {
        const got = await firstTo(opened);
        const receipt = await opened.mind.receipt({
          about: `${own}/${got.id}`,
          outcome,
        });
        await opened.mind.send({
          to: [own],
          verb,
          content: { parts: [{ mediaType: "text/plain", body: "So it went." }, carried(receipt)] },
          replyTo: got.id,
          ...(got.packet.session === undefined ? {} : { session: got.packet.session }),
        });
      } finally {
        opened.mind.close();
      }
      await front.pump();
      expect(taskOf(await asking).status.state).toBe(state);
    },
  );

  it("is not answered for a Receipt that is another's, or about another record: the verb decides then", async () => {
    const asking = ask("SendMessage", { message: message("Translate.") });
    const opened = await place.mind("mina");
    try {
      const got = await firstTo(opened);
      const elsewhere = await opened.mind.receipt({
        about: `${own}/${contentId({ another: "record" })}`,
        outcome: "broken",
      });
      await opened.mind.send({
        to: [own],
        verb: "deliver",
        content: {
          parts: [
            carried(elsewhere),
            { mediaType: "application/oip+json", body: { type: "Receipt", outcome: "broken" } },
          ],
        },
        replyTo: got.id,
        ...(got.packet.session === undefined ? {} : { session: got.packet.session }),
      });
    } finally {
      opened.mind.close();
    }
    await front.pump();
    const task = (await asking).result?.["task"] as Record<string, unknown>;
    expect(task["status"]).toMatchObject({ state: "TASK_STATE_COMPLETED" });
    // What a packet carries that is a record goes on as the data it is.
    const [{ parts }] = task["artifacts"] as [{ parts: Record<string, unknown>[] }];
    expect(parts).toMatchObject([
      { mediaType: "application/oip+json", data: { type: "Receipt", outcome: "broken" } },
      { mediaType: "application/oip+json", data: { type: "Receipt", outcome: "broken" } },
    ]);
  });
});

describe("a Receipt in a mind's answer", () => {
  it(`${clause("L0 3.1")} ends a task only where it is the mind's own, about the request that began the task`, async () => {
    const reply = await ask("SendMessage", {
      message: message("Translate, and I shall ask again."),
      configuration: { returnImmediately: true },
    });
    const task = taskOf(reply);
    const { reached } = await minaAnswers(() => undefined);
    const request = reached[0]?.id ?? "";
    const session = reached[0]?.packet.session;
    // Another mind signs that the request was fulfilled. It is a true record, and not the mind's.
    const bilal = await place.mind("bilal");
    let anothers: JsonObject;
    try {
      anothers = (await bilal.mind.receipt({
        about: `${own}/${request}`,
        outcome: "fulfilled",
      })) as unknown as JsonObject;
    } finally {
      bilal.mind.close();
    }
    const opened = await place.mind("mina");
    try {
      // The mind passes it on with a word that it is at work: the task is at work, and has not ended.
      await opened.mind.send({
        to: [own],
        verb: "ack",
        content: { parts: [{ mediaType: "text/plain", body: "On it." }, carried(anothers)] },
        replyTo: request,
        ...(session === undefined ? {} : { session }),
      });
      await front.pump();
      expect((await ask("GetTask", { id: task.id })).result).toMatchObject({
        status: { state: "TASK_STATE_WORKING" },
      });
      // The mind's own Receipt about that request ends it, whatever the verb.
      const mine = await opened.mind.receipt({ about: `${own}/${request}`, outcome: "broken" });
      await opened.mind.send({
        to: [own],
        verb: "ack",
        content: carried(mine),
        replyTo: request,
        ...(session === undefined ? {} : { session }),
      });
    } finally {
      opened.mind.close();
    }
    await front.pump();
    expect((await ask("GetTask", { id: task.id })).result).toMatchObject({
      status: { state: "TASK_STATE_FAILED" },
    });
  });
});

describe("a task of a mind's", () => {
  it(`${clause("L0 3.2")} that needs input goes on with the client's next message: it answers what the mind asked, in the task's session`, async () => {
    const first = message("Translate the lease.");
    const began = await exchange({ message: first }, () => ({
      verb: "request",
      ...text("Into which language?"),
    }));
    const task = taskOf(began.reply);
    expect(task.status.state).toBe("TASK_STATE_INPUT_REQUIRED");
    const [question] = began.answers;
    // The client names the task alone: the context is the task's (A2A, 3.4.3).
    const second = message("Into English.", { taskId: task.id });
    const went = await exchange({ message: second }, () => ({
      verb: "deliver",
      ...text("The lease in English."),
    }));
    expect(went.reached[0]?.packet).toMatchObject({
      purpose: { verb: "request" },
      replyTo: question,
      thread: task.id,
      session: began.reached[0]?.packet.session,
      seq: 1,
    });
    const done = went.reply.result?.["task"] as Record<string, unknown>;
    expect(done).toMatchObject({
      id: task.id,
      contextId: task.contextId,
      status: { state: "TASK_STATE_COMPLETED" },
    });
    // The history has what was said, by both, in order.
    expect(
      (done["history"] as { parts: { text: string }[] }[]).map((said) => said.parts[0]?.text),
    ).toStrictEqual(["Translate the lease.", "Into which language?", "Into English."]);
    expect(done["artifacts"]).toMatchObject([{ parts: [{ text: "The lease in English." }] }]);
  });

  it("is given to a client that does not wait as it stands, and is asked about after", async () => {
    const reply = await ask("SendMessage", {
      message: message("Translate, I shall ask again."),
      configuration: { returnImmediately: true },
    });
    const task = taskOf(reply);
    // The mind has the message, and has said nothing yet.
    expect(task.status.state).toBe("TASK_STATE_SUBMITTED");
    expect((await ask("GetTask", { id: task.id })).result).toMatchObject({
      id: task.id,
      status: { state: "TASK_STATE_SUBMITTED" },
    });
    // The mind says that it is at work, and then delivers.
    await minaAnswers(() => ({ verb: "ack", ...text("On it.") }));
    expect((await ask("GetTask", { id: task.id })).result).toMatchObject({
      status: { state: "TASK_STATE_WORKING" },
    });
    const opened = await place.mind("mina");
    try {
      await opened.mind.send({ to: [own], verb: "inform", thread: task.id, ...text("Done.") });
    } finally {
      opened.mind.close();
    }
    await front.pump();
    // A client was told of the task: an answer with verb `inform` completes it, with the mind's words.
    const done = (await ask("GetTask", { id: task.id })).result;
    expect(done).toMatchObject({
      status: {
        state: "TASK_STATE_COMPLETED",
        message: { role: "ROLE_AGENT", parts: [{ text: "Done." }] },
      },
    });
    expect(done).not.toHaveProperty("artifacts");
  });

  it("is given as it stands to a client that waited as long as the gateway lets one wait", async () => {
    const patient = new Front({
      opened: gateway,
      base: BASE,
      version: "1",
      clock: systemClock,
      waitMs: 50,
    });
    const served = await patient.served(id);
    if (served === undefined) throw new Error("the mind is served");
    const answered = await patient.send(served, {
      messageId: "m-slow",
      role: "ROLE_USER",
      parts: [{ text: "Take your time." }],
    });
    expect(answered).toMatchObject({ task: { state: "TASK_STATE_SUBMITTED", announced: true } });
    // The mind answers later, to a task that a client was told of.
    await minaAnswers(() => ({ verb: "deliver", ...text("At last.") }));
    const { id: task } = (answered as { task: { id: string } }).task;
    expect((await ask("GetTask", { id: task })).result).toMatchObject({
      status: { state: "TASK_STATE_COMPLETED" },
    });
  });

  it(`${clause("L0 3.1", "L0 1.4")} is cancelled for a client with a Receipt of the gateway's that says what the gateway observed`, async () => {
    const { reply, reached } = await exchange({ message: message("Translate.") }, () => ({
      verb: "request",
      ...text("Into which language?"),
    }));
    const task = taskOf(reply);
    const cancelled = await ask("CancelTask", { id: task.id });
    expect(cancelled.result).toMatchObject({
      id: task.id,
      contextId: task.contextId,
      status: { state: "TASK_STATE_CANCELED" },
    });
    // The mind is told, in the task's session, with a Receipt about the request that began the task.
    const {
      reached: [told],
    } = await minaAnswers(() => undefined);
    expect(told?.packet).toMatchObject({
      from: own,
      purpose: { verb: "inform" },
      thread: task.id,
      session: reached[0]?.packet.session,
      content: {
        mediaType: "application/oip+json",
        body: {
          type: "Receipt",
          author: own,
          about: `${own}/${String(reached[0]?.id)}`,
          outcome: "cancelled",
          statement: `The gateway observed an A2A client cancel task "${task.id}".`,
        },
      },
    });
    expect(judgeRecord((told?.packet.content as { body: unknown }).body).ok).toBe(true);
    // A task that has ended is cancelled no more, and takes no more messages.
    expect((await ask("CancelTask", { id: task.id })).error).toMatchObject({ code: -32002 });
    expect(
      (await ask("SendMessage", { message: message("And now?", { taskId: task.id }) })).error,
    ).toMatchObject({ code: -32004 });
    // What the mind says of it after is said of a task that has its end.
    const opened = await place.mind("mina");
    try {
      await opened.mind.send({ to: [own], verb: "deliver", thread: task.id, ...text("Too late.") });
    } finally {
      opened.mind.close();
    }
    expect(await front.pump()).toBe(0);
    expect((await ask("GetTask", { id: task.id })).result).toMatchObject({
      status: { state: "TASK_STATE_CANCELED" },
    });
  });

  it("is cancelled outside its session where the gateway holds the session no more", async () => {
    const { reply, reached } = await exchange({ message: message("Translate.") }, () => ({
      verb: "request",
      ...text("Into which language?"),
    }));
    const task = taskOf(reply);
    expect(await gateway.mind.leaveSession(reached[0]?.packet.session ?? "")).toBe(true);
    expect((await ask("CancelTask", { id: task.id })).result).toMatchObject({
      status: { state: "TASK_STATE_CANCELED" },
    });
    const told = (await minaAnswers(() => undefined)).reached.find(
      ({ packet }) => packet.thread === task.id,
    );
    expect(told?.packet).toMatchObject({ purpose: { verb: "inform" }, thread: task.id });
    expect(told?.packet.session).toBeUndefined();
  });

  it("is forgotten in time: the gateway looks for what it keeps no longer once an hour", async () => {
    const book = new Book(join(gateway.home.dir, "front"));
    const old = new Date(Date.now() - 2 * 86_400_000).toISOString();
    book.put({
      id: "untold-long-ago",
      mind: mina,
      contextId: "ctx",
      state: "TASK_STATE_SUBMITTED",
      at: old,
      artifacts: [],
      history: [],
      session: "bciqsession",
      request: "bciqrequest",
      announced: false,
    });
    let ahead = 0n;
    const keeper = new Front({
      opened: gateway,
      base: BASE,
      version: "1",
      clock: { now: () => systemClock.now() + ahead },
    });
    await keeper.pump();
    expect(book.get(mina, "untold-long-ago")).toBeDefined();
    // Not an hour later.
    ahead = 3_000_000_000_000n;
    await keeper.pump();
    expect(book.get(mina, "untold-long-ago")).toBeDefined();
    ahead = 3_700_000_000_000n;
    await keeper.pump();
    expect(book.get(mina, "untold-long-ago")).toBeUndefined();
  });

  it("is not begun where the mind cannot be given the message, and the client is told so", async () => {
    // A gateway whose packets reach nobody, and will not: its mind says so of each.
    const failing = (delivery: object): Front =>
      frontWith({
        send: async (given: Message) => {
          const sent = await gateway.mind.send({ ...given, queue: false });
          return { ...sent, deliveries: [{ to: mina, sealed: true, ...delivery }] };
        },
      });
    const served = await front.served(id);
    if (served === undefined) throw new Error("the mind is served");
    const said = { messageId: "m-lost", role: "ROLE_USER" as const, parts: [{ text: "Hello?" }] };
    await expect(
      failing({ stored: false, failure: "forbidden" }).send(served, said),
    ).rejects.toMatchObject({
      code: -32603,
      message: "The mind could not be given the message: forbidden.",
    });
    await expect(failing({ stored: false }).send(served, said)).rejects.toMatchObject({
      code: -32603,
      message: "The mind could not be given the message: none of its endpoints took it.",
    });
    // The packets that did arrive all the same are read and let be.
    await minaAnswers(() => undefined);
  });

  it("is answered in by the mind it is asked of alone, and by a packet with a verb that says something of it", async () => {
    const reply = await ask("SendMessage", {
      message: message("Translate."),
      configuration: { returnImmediately: true },
    });
    const task = taskOf(reply);
    const {
      reached: [reached],
    } = await minaAnswers(() => undefined);
    // Another mind names the task, and answers the gateway's packet.
    const bilal = await place.mind("bilal");
    try {
      for (const more of [{ thread: task.id }, { replyTo: reached?.id ?? "" }]) {
        await bilal.mind.send({ to: [own], verb: "deliver", ...more, ...text("Mine.") });
      }
    } finally {
      bilal.mind.close();
    }
    // And the mind says what is nothing about a task, and names a task that is none.
    const opened = await place.mind("mina");
    try {
      await opened.mind.send({ to: [own], verb: "propose", thread: task.id, ...text("A deal?") });
      await opened.mind.send({ to: [own], verb: "deliver", thread: "no-task", ...text("?") });
      await opened.mind.send({ to: [own], verb: "deliver", ...text("About nothing.") });
    } finally {
      opened.mind.close();
    }
    expect(await front.pump()).toBe(0);
    expect((await ask("GetTask", { id: task.id })).result).toMatchObject({
      status: { state: "TASK_STATE_SUBMITTED" },
    });
    expect(failures).toStrictEqual([]);
  });
});

describe("the context of a task", () => {
  it(`${clause("L0 3.1")} is a session: the tasks of one context are in one, and another context has another`, async () => {
    const first = await exchange(
      { message: message("One.", { contextId: "a client's own context" }) },
      () => ({ verb: "deliver", ...text("Done.") }),
    );
    // A2A, 3.4.1: a context the client names is taken, and is the task's.
    expect(taskOf(first.reply).contextId).toBe("a client's own context");
    const second = await exchange(
      { message: message("Two.", { contextId: "a client's own context" }) },
      () => ({ verb: "deliver", ...text("Done.") }),
    );
    expect(taskOf(second.reply).contextId).toBe("a client's own context");
    expect(taskOf(second.reply).id).not.toBe(taskOf(first.reply).id);
    const third = await exchange({ message: message("Three.") }, () => ({
      verb: "deliver",
      ...text("Done."),
    }));
    const [one, two, three] = [first, second, third].map(({ reached }) => reached[0]?.packet);
    expect(two?.session).toBe(one?.session);
    expect(two?.seq).toBe((one?.seq ?? 0) + 1);
    expect(three?.session).not.toBe(one?.session);
    expect(three?.seq).toBe(0);
  });

  it("is the task's: a message that names a task and another context is refused", async () => {
    const { reply } = await exchange({ message: message("Translate.") }, () => ({
      verb: "request",
      ...text("Into which language?"),
    }));
    const task = taskOf(reply);
    const refused = await ask("SendMessage", {
      message: message("English.", { taskId: task.id, contextId: "another context" }),
    });
    expect(refused.error).toStrictEqual({
      code: -32602,
      message: "contextId is not the context of the task the message names.",
    });
    // With the task's own context it goes on.
    const went = await exchange(
      { message: message("English.", { taskId: task.id, contextId: task.contextId }) },
      () => ({ verb: "deliver", ...text("Done.") }),
    );
    expect(taskOf(went.reply)).toMatchObject({
      id: task.id,
      status: { state: "TASK_STATE_COMPLETED" },
    });
  });
});

describe("what a client sends", () => {
  it(`${clause("L1 12.2")} is carried part by part: a text as a text, data as JSON, and bytes that are a text as that text`, async () => {
    const { reached } = await exchange(
      {
        message: {
          messageId: "m-parts",
          role: "ROLE_USER",
          parts: [
            { text: "A note.", mediaType: "text/markdown" },
            { data: { pages: [1, 2], ratio: 0.5 } },
            { raw: Buffer.from("col,umn\n1,2\n").toString("base64"), mediaType: "text/csv" },
            { raw: Buffer.from('{"a":1}').toString("base64"), mediaType: "application/ld+json" },
            { url: "https://files.example/in.pdf", mediaType: "application/pdf" },
          ],
        },
      },
      () => ({ verb: "deliver", ...text("Read.") }),
    );
    const { parts } = reached[0]?.packet.content as { parts: unknown[] };
    expect(parts.slice(1)).toStrictEqual([
      { mediaType: "text/markdown", body: "A note." },
      // Data may hold what a record cannot, a fraction for one: it is carried as its JSON text.
      { mediaType: "application/json", body: '{"pages":[1,2],"ratio":0.5}' },
      { mediaType: "text/csv", body: "col,umn\n1,2\n" },
      { mediaType: "application/ld+json", body: '{"a":1}' },
      // A file is named. The gateway fetched nothing, and says nothing of its bytes.
      { mediaType: "text/uri-list", body: "https://files.example/in.pdf" },
    ]);
  });

  it.each([
    ["bytes that are no text", { raw: "dGNr", mediaType: "application/x-unsupported-tck-type" }],
    ["bytes of no media type", { raw: "dGNr" }],
    ["bytes called a text that are none", { raw: "//79", mediaType: "text/plain" }],
  ])("is refused where a part is %s: a packet has no place for bytes", async (_, part) => {
    const refused = await ask("SendMessage", {
      message: { messageId: "m-raw", role: "ROLE_USER", parts: [part] },
    });
    expect(refused.error).toMatchObject({
      code: -32005,
      data: [
        { "@type": ERROR_INFO, reason: "CONTENT_TYPE_NOT_SUPPORTED", domain: "a2a-protocol.org" },
      ],
    });
    expect(refused.error?.message).toMatch(/cannot be given to this agent/u);
  });

  it.each([
    ["no message", {}, "message is no message of A2A: a message is no object."],
    [
      "a message with no ID",
      { message: { role: "ROLE_USER", parts: [{ text: "x" }] } },
      "message is no message of A2A: a message has no ID.",
    ],
    [
      "a message of an agent's",
      { message: { messageId: "m", role: "ROLE_AGENT", parts: [{ text: "x" }] } },
      "A client's message has the role of a user.",
    ],
    [
      "a message with no parts",
      { message: { messageId: "m", role: "ROLE_USER", parts: [] } },
      "A message has one part at least.",
    ],
    [
      "a part that is two things",
      { message: { messageId: "m", role: "ROLE_USER", parts: [{ text: "x", data: 1 }] } },
      "message is no message of A2A: a part holds one of a text, bytes, a URL or data.",
    ],
    [
      "a URL that is none of the web",
      { message: { messageId: "m", role: "ROLE_USER", parts: [{ url: "file:///etc/passwd" }] } },
      "The message holds more than a packet carries, or a URL that is none of the web.",
    ],
    [
      "a configuration that is none",
      { message: { messageId: "m", role: "ROLE_USER", parts: [{ text: "x" }] }, configuration: 3 },
      "configuration is an object.",
    ],
    [
      "a history length that is no count",
      {
        message: { messageId: "m", role: "ROLE_USER", parts: [{ text: "x" }] },
        configuration: { historyLength: -1 },
      },
      "historyLength is a whole number, zero or more.",
    ],
  ])("is refused before the mind hears of it where it is %s", async (_, params, why) => {
    expect((await ask("SendMessage", params)).error).toStrictEqual({ code: -32602, message: why });
  });

  it("is refused where it names a task that is none, or asks for what this agent does not do", async () => {
    const unknown = await ask("SendMessage", { message: message("x", { taskId: "no-such-task" }) });
    expect(unknown.error).toStrictEqual({
      code: -32001,
      message: "There is no such task.",
      data: [{ "@type": ERROR_INFO, reason: "TASK_NOT_FOUND", domain: "a2a-protocol.org" }],
    });
    const pushed = await ask("SendMessage", {
      message: message("x"),
      configuration: { taskPushNotificationConfig: { url: "https://client.example/hook" } },
    });
    expect(pushed.error).toMatchObject({ code: -32003 });
  });
});

describe("a packet that a message carries", () => {
  /** A packet a mind signs itself, and posts nowhere. */
  async function packetBy(
    name: string,
    more: Record<string, unknown> = {},
    said = "Could you translate a lease?",
  ): Promise<JsonObject> {
    const opened = await place.mind(name);
    try {
      const now = Date.now();
      return (await opened.mind.sign({
        oip: "1",
        type: "Packet",
        from: opened.mind.address,
        to: [mina],
        created: new Date(now).toISOString(),
        expires: new Date(now + 3_600_000).toISOString(),
        nonce: `nonce-${String(now)}-${String(++sent)}`,
        purpose: { verb: "request" },
        content: { mediaType: "text/plain", body: said },
        ...more,
      })) as unknown as JsonObject;
    } finally {
      opened.mind.close();
    }
  }

  const carrying = (...packets: unknown[]): Record<string, unknown> => ({
    message: {
      messageId: `m-${String(++sent)}`,
      role: "ROLE_USER",
      parts: [
        { text: "For those who do not read packets: a request to translate a lease." },
        ...packets.map((data) => ({ data, mediaType: "application/oip+json" })),
      ],
    },
  });

  /** What is in the mind's mailbox now. */
  async function minaHas(): Promise<Received[]> {
    const opened = await place.mind("mina");
    try {
      return [...(await opened.mind.receive()).received];
    } finally {
      opened.mind.close();
    }
  }

  it(`${clause("L0 3.3", "L1 12.4")} is verified as the mind it is for will verify it, and brought to that mind as it is: its sender's own, and no task of the gateway's`, async () => {
    const bilal = (await place.mind("bilal")).mind;
    bilal.close();
    const packet = await packetBy("bilal");
    const reply = await ask("SendMessage", carrying(packet));
    // The client is told that the packet was brought, with a message. There is no task.
    const answer = reply.result?.["message"] as {
      parts: Record<string, unknown>[];
      contextId: string;
    };
    expect(reply.error).toBeUndefined();
    expect(reply.result).not.toHaveProperty("task");
    expect(answer.parts[0]).toStrictEqual({
      text: "The packet was brought to the mind it is for. What the mind answers, it answers to the packet's sender, as a packet.",
    });
    expect(answer.contextId).toMatch(/^[0-9a-f-]{36}$/u);
    // The mind has the packet: the one its sender signed, from its sender, and sealed on the way.
    const received = await minaHas();
    expect(received).toMatchObject([{ id: contentId(packet), from: bilal.address, sealed: true }]);
    expect(received[0]?.packet).toStrictEqual(packet);
    // Nothing of it is the gateway's: the plain parts beside the packet went nowhere.
    expect(received).toHaveLength(1);
  });

  it(`${clause("L1 12.4")} is brought once: a packet that was brought before is not brought again, and its sender is told the same`, async () => {
    const packet = await packetBy("bilal");
    const first = await ask("SendMessage", carrying(packet));
    expect(await minaHas()).toHaveLength(1);
    const again = await ask("SendMessage", carrying(packet));
    expect((again.result?.["message"] as { parts: unknown[] }).parts[0]).toStrictEqual(
      (first.result?.["message"] as { parts: unknown[] }).parts[0],
    );
    expect(await minaHas()).toStrictEqual([]);
  });

  it(`${clause("L1 12.4")} is remembered by the gateway itself: one that was brought is not carried to the mind a second time`, async () => {
    // The mind would discard a second copy. The gateway does not rest on that: it carries none.
    const carried: unknown[] = [];
    const counting = frontWith({
      pass: (packet: unknown, to: string) => {
        carried.push(packet);
        return gateway.mind.pass(packet, to);
      },
    });
    const served = await counting.served(id);
    if (served === undefined) throw new Error("the mind is served");
    const packet = await packetBy("bilal");
    const said = (): Parameters<Front["send"]>[1] =>
      carrying(packet)["message"] as Parameters<Front["send"]>[1];
    await counting.send(served, said());
    await counting.send(served, said());
    // Another front on the gateway's directory, as after a restart, remembers it too.
    await frontWith({
      pass: (again: unknown) => {
        carried.push(again);
        return Promise.reject(new Error("carried a third time"));
      },
    }).send(served, said());
    expect(carried).toStrictEqual([packet]);
    expect(await minaHas()).toHaveLength(1);
  });

  it(`${clause("L0 3.3", "L1 12.4")} is not brought where it does not verify, is not for this mind, or is out of its time, and the client is told why`, async () => {
    const good = await packetBy("bilal");
    const refused = async (packet: unknown): Promise<string> => {
      const reply = await ask("SendMessage", carrying(packet));
      expect(reply.error?.code).toBe(-32602);
      return reply.error?.message ?? "";
    };
    // Its content was changed after it was signed.
    expect(
      await refused({ ...good, content: { mediaType: "text/plain", body: "Pay me." } }),
    ).toMatch(/^The packet the message carries is not taken: .* \(L1 12\.4\)\.$/u);
    // It is for the gateway, and not for the mind that is asked.
    expect(await refused(await packetBy("bilal", { to: [own] }))).toMatch(
      /^The packet the message carries is not taken: .* \(L1 12\.4\)\.$/u,
    );
    // It was to be delivered an hour ago, at the latest.
    const past = Date.now() - 7_200_000;
    expect(
      await refused(
        await packetBy("bilal", {
          created: new Date(past).toISOString(),
          expires: new Date(past + 60_000).toISOString(),
        }),
      ),
    ).toMatch(/expires.*\(L1 12\.4\)\.$/u);
    // Its sender is no mind anyone can resolve.
    const nobody = `did:oip:${contentId({ no: "mind" })}`;
    expect(await refused({ ...good, from: nobody })).toMatch(/is not taken/u);
    // It is no packet at all, or one of a session.
    expect(await refused({ type: "Receipt", outcome: "fulfilled" })).toMatch(
      /^What the message carries is no packet: /u,
    );
    expect(await refused("a packet")).toMatch(/^What the message carries is no packet: /u);
    expect(await refused({ ...good, session: contentId({ a: "session" }), seq: 0 })).toBe(
      "A packet of a session is brought by its sender: its place in the session is the sender's to keep.",
    );
    // Nothing of any of them reached the mind.
    expect(await minaHas()).toStrictEqual([]);
  });

  it("is one, and is no part of a task of the gateway's", async () => {
    const [one, two] = [await packetBy("bilal"), await packetBy("bilal")];
    expect((await ask("SendMessage", carrying(one, two))).error).toStrictEqual({
      code: -32602,
      message: "A message carries one packet at most.",
    });
    const params = carrying(one);
    (params["message"] as Record<string, unknown>)["taskId"] = "a-task";
    expect((await ask("SendMessage", params)).error).toStrictEqual({
      code: -32602,
      message: "A packet is its sender's own message: it goes on with no task of this agent's.",
    });
    expect(await minaHas()).toStrictEqual([]);
  });

  it(`${clause("L1 13.2")} is answered with the mind's own acknowledgement of it, where the mind's endpoint gives one`, async () => {
    const packet = await packetBy("bilal");
    const ack = { oip: "1", type: "Ack", packet: contentId(packet) };
    const acked = frontWith({
      pass: () => Promise.resolve({ to: mina, sealed: true, stored: true, ack }),
    });
    const served = await front.served(id);
    if (served === undefined) throw new Error("the mind is served");
    const answered = await acked.send(served, {
      messageId: "m-ack",
      role: "ROLE_USER",
      parts: [{ data: packet, mediaType: "application/oip+json" }],
    });
    expect(answered).toMatchObject({
      message: {
        role: "ROLE_AGENT",
        parts: [
          { text: expect.stringContaining("was brought") as string },
          // It is a record, and says so itself: the client verifies it as any record.
          { data: ack, mediaType: "application/oip+json" },
        ],
      },
    });
  });

  it("is not judged where its sender's records cannot be asked for: that is the gateway's fault, and no verdict", async () => {
    const cut = { off: false };
    const opened = await openMind(
      place.where("gateway", {
        fetch: (asked) =>
          cut.off && new URL(asked.url).pathname.includes("/resolve/")
            ? Promise.reject(new TypeError("fetch failed"))
            : fetch(asked),
      }),
    );
    // The mind is open: from here on its resolver is away.
    cut.off = true;
    try {
      const away = new Front({ opened, base: BASE, version: "1", clock: systemClock });
      const served = await front.served(id);
      if (served === undefined) throw new Error("the mind is served");
      const packet = await packetBy("bilal");
      await expect(
        away.send(served, {
          messageId: "m-cut",
          role: "ROLE_USER",
          parts: [{ data: packet, mediaType: "application/oip+json" }],
        }),
      ).rejects.toMatchObject({ name: "TransportError" });
    } finally {
      opened.mind.close();
    }
  });

  it("is said not to have been brought where the mind cannot be reached", async () => {
    // A gateway that reaches everything but the places a mind takes packets at.
    const opened = await openMind(
      place.where("gateway", {
        fetch: (asked) =>
          asked.method === "POST" && /\/(?:inbox|mailbox)$/u.test(new URL(asked.url).pathname)
            ? Promise.reject(new TypeError("fetch failed"))
            : fetch(asked),
      }),
    );
    try {
      const away = new Front({ opened, base: BASE, version: "1", clock: systemClock });
      const served = await away.served(id);
      if (served === undefined) throw new Error("the mind is served");
      const packet = await packetBy("bilal");
      await expect(
        away.send(served, {
          messageId: "m-away",
          role: "ROLE_USER",
          parts: [{ data: packet, mediaType: "application/oip+json" }],
        }),
      ).rejects.toMatchObject({
        code: -32603,
        message: "The mind could not be given the packet: unreachable.",
      });
      // What was not brought can be brought yet.
      expect((await ask("SendMessage", carrying(packet))).result).toHaveProperty("message");
      expect(await minaHas()).toHaveLength(1);
    } finally {
      opened.mind.close();
    }
  });
});

describe("the JSON-RPC interface of a mind", () => {
  const raw = async (body: Uint8Array | string, headers: Record<string, string> = {}) => {
    const answer = await server.handle({
      method: "POST",
      path: `/a2a/${id}`,
      headers: { "content-type": "application/json", "a2a-version": "1.0", ...headers },
      body: typeof body === "string" ? utf8(body) : body,
    });
    return {
      status: answer.status,
      reply: JSON.parse(new TextDecoder().decode(answer.body)) as Reply,
    };
  };

  it("answers what is no request of JSON-RPC 2.0 with the error that says so", async () => {
    expect((await raw("{ no json")).reply).toStrictEqual({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "The request is not JSON." },
    });
    expect((await raw(new Uint8Array([0xff, 0xfe]))).reply.error?.code).toBe(-32700);
    for (const request of ["[]", '"SendMessage"', '{"jsonrpc":"1.0","id":1,"method":"GetTask"}']) {
      expect((await raw(request)).reply).toStrictEqual({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "The request is no JSON-RPC 2.0 request." },
      });
    }
    expect(
      (await raw('{"jsonrpc":"2.0","method":"GetTask","params":{}}')).reply.error,
    ).toStrictEqual({
      code: -32600,
      message: "The request has no id: every method of A2A is answered.",
    });
    // From here on the answer names the request.
    expect((await raw('{"jsonrpc":"2.0","id":"r-1","method":7}')).reply).toStrictEqual({
      jsonrpc: "2.0",
      id: "r-1",
      error: { code: -32600, message: "The request names no method." },
    });
    expect(
      (await raw('{"jsonrpc":"2.0","id":2,"method":"GetTask","params":[1]}')).reply.error,
    ).toStrictEqual({
      code: -32602,
      message: "params is an object.",
    });
  });

  it("has no method but those of A2A", async () => {
    expect((await ask("NonExistentMethod", {})).error).toStrictEqual({
      code: -32601,
      message: "There is no method NonExistentMethod.",
    });
  });

  it.each([
    ["99.0", "99.0"],
    ["", "0.3"],
    ["0.3", "0.3"],
    ["1.1", "1.1"],
    ["10.0", "10.0"],
  ])(
    "answers a client that speaks another version of A2A (%s) that it does not",
    async (version, read) => {
      const refused = await ask("GetTask", { id: "t" }, { "a2a-version": version });
      expect(refused.error).toStrictEqual({
        code: -32009,
        message: `This agent speaks A2A 1.0, and was asked in ${read}: send the header A2A-Version: 1.0.`,
        data: [
          { "@type": ERROR_INFO, reason: "VERSION_NOT_SUPPORTED", domain: "a2a-protocol.org" },
        ],
      });
    },
  );

  it("takes the version from the header or from the query, and a patch number decides nothing", async () => {
    // A2A, 3.6.2: no version given is 0.3.
    expect((await ask("GetTask", { id: "t" }, {})).error?.code).toBe(-32009);
    expect((await ask("GetTask", { id: "t" }, { "a2a-version": "1.0.1" })).error?.code).toBe(
      -32001,
    );
    expect((await ask("GetTask", { id: "t" }, {}, `/a2a/${id}?A2A-Version=1.0`)).error?.code).toBe(
      -32001,
    );
    // A version that begins as this one does is another: 1.01 is not 1.0, and neither is 1.0x.
    for (const version of ["1.01", "1.0x", "1.0.", "1.0.1.2", "1", "1.1", "2.0", "0.3", "v1.0"]) {
      const refused = await ask("GetTask", { id: "t" }, { "a2a-version": version });
      expect(refused.error?.code, version).toBe(-32009);
    }
  });

  it("says of what this agent does not do that it does not: streams, push notifications, an extended card", async () => {
    for (const method of ["SendStreamingMessage", "SubscribeToTask", "GetExtendedAgentCard"]) {
      expect((await ask(method, { id: "t" })).error).toMatchObject({
        code: -32004,
        data: [{ reason: "UNSUPPORTED_OPERATION" }],
      });
    }
    for (const method of [
      "CreateTaskPushNotificationConfig",
      "GetTaskPushNotificationConfig",
      "ListTaskPushNotificationConfigs",
      "DeleteTaskPushNotificationConfig",
    ]) {
      expect((await ask(method, { taskId: "t" })).error).toMatchObject({
        code: -32003,
        data: [{ reason: "PUSH_NOTIFICATION_NOT_SUPPORTED" }],
      });
    }
  });

  it("names a task by a text, and has none for a name it did not give", async () => {
    for (const method of ["GetTask", "CancelTask"]) {
      expect((await ask(method, {})).error).toStrictEqual({
        code: -32602,
        message: "id names the task: a text.",
      });
      expect((await ask(method, { id: "x".repeat(300) })).error?.code).toBe(-32602);
      expect((await ask(method, { id: "no-such-task" })).error?.code).toBe(-32001);
    }
    expect((await ask("GetTask", { id: "t", historyLength: 1.5 })).error?.code).toBe(-32602);
  });

  it("reads no request that is larger than a packet can be", async () => {
    const answer = await server.handle({
      method: "POST",
      path: `/a2a/${id}`,
      headers: { "content-type": "application/json", "a2a-version": "1.0" },
      body: new Uint8Array(MAX_REQUEST_BYTES + 1),
    });
    expect(answer.status).toBe(413);
  });

  it("says nothing of its inside where the fault is its own, and tells who logs", async () => {
    const broken = new A2aServer(
      {
        served: () => Promise.reject(new Error("the resolver's secret")),
      } as unknown as Front,
      "/a2a",
      (error) => failures.push(error),
    );
    const answer = await broken.handle({
      method: "POST",
      path: `/a2a/${id}`,
      headers: {},
      body: new Uint8Array(),
    });
    expect(answer.status).toBe(500);
    expect(new TextDecoder().decode(answer.body)).toBe("The gateway could not answer.\n");
    expect(failures.splice(0)).toMatchObject([{ message: "the resolver's secret" }]);
    // And where a method fails for a reason that is no fault of the client's.
    const failing = new A2aServer(
      {
        served: () => Promise.resolve({ address: mina }),
        get: () => {
          throw new Error("the disk is full");
        },
      } as unknown as Front,
      "/a2a/",
      (error) => failures.push(error),
    );
    const reply = await failing.handle({
      method: "POST",
      path: `/a2a/${id}`,
      headers: { "content-type": "application/json", "a2a-version": "1.0" },
      body: utf8('{"jsonrpc":"2.0","id":3,"method":"GetTask","params":{"id":"t"}}'),
    });
    expect(JSON.parse(new TextDecoder().decode(reply.body))).toStrictEqual({
      jsonrpc: "2.0",
      id: 3,
      error: { code: -32603, message: "The agent could not do that." },
    });
    expect(failures.splice(0)).toMatchObject([{ message: "the disk is full" }]);
    // A server that is told of nothing answers the same.
    const quiet = new A2aServer(
      { served: () => Promise.reject(new Error("unheard")) } as unknown as Front,
      "/a2a",
    );
    expect(
      (await quiet.handle({ method: "GET", path: "/a2a/x", headers: {}, body: new Uint8Array() }))
        .status,
    ).toBe(500);
  });
});

describe("a listing of a mind's tasks, for a client", () => {
  const CONTEXT = "the listing's context";
  const tasks: string[] = [];

  beforeAll(async () => {
    for (const [index, verb] of ["deliver", "request", "deliver"].entries()) {
      const { reply } = await exchange(
        { message: message(`Task ${String(index)}.`, { contextId: CONTEXT }) },
        () => ({ verb, ...text(`Answer ${String(index)}.`) }),
      );
      tasks.push(taskOf(reply).id);
      await sleep(5);
    }
  });

  const listed = async (params: Record<string, unknown>) => {
    const reply = await ask("ListTasks", { contextId: CONTEXT, ...params });
    const result = reply.result as {
      tasks: Record<string, unknown>[];
      nextPageToken: string;
      pageSize: number;
      totalSize: number;
    };
    return { ...result, ids: result.tasks.map((task) => task["id"]) };
  };

  it("has the tasks of the context a client names, the one whose state is newest first, without their artifacts", async () => {
    const all = await listed({});
    expect(all.ids).toStrictEqual([...tasks].reverse());
    expect(all).toMatchObject({ nextPageToken: "", pageSize: 50, totalSize: 3 });
    for (const task of all.tasks) expect(task).not.toHaveProperty("artifacts");
    const whole = await listed({ includeArtifacts: true });
    expect(whole.tasks.map((task) => "artifacts" in task)).toStrictEqual([true, false, true]);
  });

  it("comes a page at a time, and the last page says so with an empty token", async () => {
    const first = await listed({ pageSize: 2 });
    expect(first.ids).toStrictEqual([tasks[2], tasks[1]]);
    expect(first).toMatchObject({ pageSize: 2, totalSize: 3 });
    expect(first.nextPageToken).not.toBe("");
    const second = await listed({ pageSize: 2, pageToken: first.nextPageToken });
    expect(second.ids).toStrictEqual([tasks[0]]);
    expect(second.nextPageToken).toBe("");
  });

  it("is of one state, or of what changed since a time, with as much history as is asked for", async () => {
    expect((await listed({ status: "TASK_STATE_INPUT_REQUIRED" })).ids).toStrictEqual([tasks[1]]);
    expect((await listed({ status: "TASK_STATE_UNSPECIFIED" })).ids).toHaveLength(3);
    const [newest] = (await listed({})).tasks;
    const since = (newest?.["status"] as { timestamp: string }).timestamp;
    expect((await listed({ statusTimestampAfter: since })).ids).toStrictEqual([tasks[2]]);
    const none = await listed({ historyLength: 0 });
    for (const task of none.tasks) expect(task).not.toHaveProperty("history");
    const one = await listed({ historyLength: 1 });
    expect(one.tasks.map((task) => (task["history"] as unknown[]).length)).toStrictEqual([1, 1, 1]);
    const [waiting] = (await listed({ status: "TASK_STATE_INPUT_REQUIRED" })).tasks;
    expect((waiting?.["history"] as unknown[]).length).toBe(2);
  });

  it("shows a client that names no context nothing: nobody says who a client is", async () => {
    for (const params of [{}, { contextId: "" }]) {
      expect((await ask("ListTasks", params)).result).toStrictEqual({
        tasks: [],
        nextPageToken: "",
        pageSize: 50,
        totalSize: 0,
      });
    }
    expect((await ask("ListTasks", { contextId: "a context nobody made" })).result).toStrictEqual({
      tasks: [],
      nextPageToken: "",
      pageSize: 50,
      totalSize: 0,
    });
  });

  it.each([
    [{ contextId: 7 }, "contextId is a text."],
    [{ status: "TASK_STATE_OF_MIND" }, "status is no state of a task."],
    [{ pageToken: 7 }, "pageToken is a text."],
    [{ pageToken: "not a token!" }, "pageToken is no token this agent gave."],
    [
      { statusTimestampAfter: "yesterday" },
      "statusTimestampAfter is a time, as ISO 8601 writes one.",
    ],
    [{ statusTimestampAfter: 7 }, "statusTimestampAfter is a time, as ISO 8601 writes one."],
    [{ pageSize: 0 }, "pageSize is from 1 to 100."],
    [{ pageSize: 101 }, "pageSize is from 1 to 100."],
    [{ pageSize: "many" }, "pageSize is a whole number, zero or more."],
    [{ historyLength: -1 }, "historyLength is a whole number, zero or more."],
  ])("is refused for parameters that are none of its own: %j", async (params, why) => {
    expect((await ask("ListTasks", { contextId: CONTEXT, ...params })).error).toStrictEqual({
      code: -32602,
      message: why,
    });
  });

  it("gives as much of a task's history as a client asks for, the newest of it", async () => {
    const [, waiting = ""] = tasks;
    const all = (await ask("GetTask", { id: waiting })).result;
    expect(
      (all?.["history"] as { parts: { text: string }[] }[]).map((said) => said.parts[0]?.text),
    ).toStrictEqual(["Task 1.", "Answer 1."]);
    const last = (await ask("GetTask", { id: waiting, historyLength: 1 })).result;
    expect(
      (last?.["history"] as { parts: { text: string }[] }[]).map((said) => said.parts[0]?.text),
    ).toStrictEqual(["Answer 1."]);
    expect((await ask("GetTask", { id: waiting, historyLength: 0 })).result).not.toHaveProperty(
      "history",
    );
    // And of the answer to a message.
    const went = await exchange(
      {
        message: message("Into English.", { taskId: waiting }),
        configuration: { historyLength: 0 },
      },
      () => ({ verb: "deliver", ...text("Done.") }),
    );
    expect(went.reply.result?.["task"]).not.toHaveProperty("history");
    expect(failures).toStrictEqual([]);
  });
});

describe("what a gateway that serves keeps to, whoever asks", () => {
  const cardOf = (mindId: string) =>
    server.handle({
      method: "GET",
      path: `/a2a/${mindId}/.well-known/agent-card.json`,
      headers: {},
      body: new Uint8Array(),
    });

  /** Makes a mind whose profile lists a card at a URL made of the mind's ID. */
  async function listing(name: string, url: (mindId: string) => string): Promise<string> {
    const address = await place.make(name, { kind: "agent" });
    const mindId = address.slice("did:oip:".length);
    const opened = await place.mind(name);
    try {
      await opened.mind.publishProfile({ name, interfaces: { a2a: url(mindId) } });
    } finally {
      opened.mind.close();
    }
    return mindId;
  }

  it(`${clause("L0 3.2")} serves a mind whose profile lists the card this gateway serves for it, and none that lists another: another gateway's, or a URL that begins the same`, async () => {
    const elsewhere = await listing(
      "carol",
      (mindId) => `https://other.example/a2a/${mindId}/.well-known/agent-card.json`,
    );
    const longer = await listing(
      "dana",
      (mindId) => `${BASE}/${mindId}/.well-known/agent-card.json?and=more`,
    );
    const under = await listing("erin", (mindId) => `${BASE}/${mindId}`);
    for (const mindId of [elsewhere, longer, under]) {
      expect((await cardOf(mindId)).status, mindId).toBe(404);
    }
    expect((await cardOf(id)).status).toBe(200);
  });

  it("gives a task to who asks the mind it is of, and to nobody who asks another mind this gateway serves", async () => {
    const other = await listing(
      "frank",
      (mindId) => `${BASE}/${mindId}/.well-known/agent-card.json`,
    );
    expect((await cardOf(other)).status).toBe(200);
    const reply = await ask("SendMessage", {
      message: message("Translate, I shall ask again."),
      configuration: { returnImmediately: true },
    });
    const task = taskOf(reply);
    expect((await ask("GetTask", { id: task.id })).result).toMatchObject({ id: task.id });
    // Asked of the other mind, there is no such task: to see, to cancel, to go on with or to list.
    const elsewhere = `/a2a/${other}`;
    for (const method of ["GetTask", "CancelTask"]) {
      expect((await ask(method, { id: task.id }, undefined, elsewhere)).error?.code, method).toBe(
        -32001,
      );
    }
    const more = { message: message("And more.", { taskId: task.id }) };
    expect((await ask("SendMessage", more, undefined, elsewhere)).error?.code).toBe(-32001);
    expect(
      (await ask("ListTasks", { contextId: task.contextId }, undefined, elsewhere)).result,
    ).toMatchObject({ tasks: [], totalSize: 0 });
    // It is as it was, for who asks the mind it is of.
    expect((await ask("GetTask", { id: task.id })).result).toMatchObject({
      status: { state: "TASK_STATE_SUBMITTED" },
    });
    await minaAnswers(() => ({ verb: "decline", ...text("Not today.") }));
  });

  it("has a task for an answer that the mind gave before the message's sending had returned", async () => {
    // The mind answers at once, and the gateway reads its mailbox, while the packet that asked
    // is still on its way back to the front that sent it.
    let reading: Promise<number> | undefined;
    const racing: Front = frontWith({
      send: async (given: Message) => {
        const sent = await gateway.mind.send(given);
        const opened = await place.mind("mina");
        try {
          const got = await firstTo(opened);
          await opened.mind.send({
            to: [own],
            verb: "deliver",
            ...text("Done before you knew it."),
            replyTo: got.id,
            ...(got.packet.session === undefined ? {} : { session: got.packet.session }),
          });
        } finally {
          opened.mind.close();
        }
        reading = racing.pump();
        // The reading has all the time it needs to be done with the answer, if it does not wait.
        await Promise.race([reading, sleep(1500)]);
        return sent;
      },
    });
    const served = await racing.served(id);
    if (served === undefined) throw new Error("the mind is served");
    const result = await racing.send(
      served,
      { messageId: "m-raced", role: "ROLE_USER", parts: [{ text: "Quickly." }] },
      { returnImmediately: true },
    );
    await reading;
    if (!("task" in result)) throw new Error("a client that does not wait is given a task");
    expect(racing.get(served, result.task.id)).toMatchObject({
      state: "TASK_STATE_COMPLETED",
      artifacts: [{ parts: [{ text: "Done before you knew it." }] }],
    });
  });

  it("signs one Receipt for a cancelling, though the mind could not be told at first", async () => {
    const reply = await ask("SendMessage", {
      message: message("Translate, I may change my mind."),
      configuration: { returnImmediately: true },
    });
    const task = taskOf(reply);
    await minaAnswers(() => undefined);
    const receipts: string[] = [];
    let reachable = false;
    const flaky = frontWith({
      send: (given: Message) => {
        receipts.push(contentId((given.content as { body: JsonObject }).body));
        return reachable
          ? gateway.mind.send(given)
          : Promise.reject(new Error("the network is away"));
      },
    });
    const served = await flaky.served(id);
    if (served === undefined) throw new Error("the mind is served");
    await expect(flaky.cancel(served, task.id)).rejects.toThrow("the network is away");
    // Nothing was told, and the task has not ended: its client asks again.
    expect(flaky.get(served, task.id).state).toBe("TASK_STATE_SUBMITTED");
    reachable = true;
    expect((await flaky.cancel(served, task.id)).state).toBe("TASK_STATE_CANCELED");
    expect(receipts).toHaveLength(2);
    expect(receipts[1]).toBe(receipts[0]);
    // The task as it is kept has nothing of the cancelling left in it.
    expect(flaky.get(served, task.id)).not.toHaveProperty("cancelling");
    const {
      reached: [told],
    } = await minaAnswers(() => undefined);
    expect(contentId((told?.packet.content as { body: JsonObject }).body)).toBe(receipts[0]);
  });

  it("is told so where the mind was not given word of a cancelling, and the task is not said to be cancelled", async () => {
    const reply = await ask("SendMessage", {
      message: message("Translate, I may change my mind again."),
      configuration: { returnImmediately: true },
    });
    const task = taskOf(reply);
    await minaAnswers(() => undefined);
    const deaf = frontWith({
      send: async (given: Message) => {
        const sent = await gateway.mind.send({ ...given, queue: false });
        return { ...sent, deliveries: [{ to: mina, sealed: true, stored: false }] };
      },
    });
    const served = await deaf.served(id);
    if (served === undefined) throw new Error("the mind is served");
    await expect(deaf.cancel(served, task.id)).rejects.toMatchObject({
      code: -32603,
      message: "The mind could not be given the word of it: none of its endpoints took it.",
    });
    expect(deaf.get(served, task.id).state).toBe("TASK_STATE_SUBMITTED");
    await minaAnswers(() => ({ verb: "decline", ...text("Never mind.") }));
  });

  it(`${clause("core 1.1")} takes a client's text that no record holds as text that one does, and bytes in either alphabet of base64`, async () => {
    const noncharacter = String.fromCodePoint(0xfffe);
    const { reply, reached } = await exchange(
      {
        message: {
          messageId: `m-${String(++sent)}`,
          role: "ROLE_USER",
          parts: [
            { text: `caf${noncharacter}e` },
            // "~~~???" in the alphabet of URLs, which A2A's own schema does not have.
            { raw: "fn5-Pz8_", mediaType: "text/plain" },
          ],
        },
      },
      () => ({ verb: "deliver", ...text("Done.") }),
    );
    // No fault of the gateway's, and no refusal: the mind has the message, mended.
    expect(reply.error).toBeUndefined();
    // The packet is the first of its session, and carries the record that names it first.
    const { parts } = reached[0]?.packet.content as { parts: unknown[] };
    expect(parts.slice(-2)).toStrictEqual([
      { mediaType: "text/plain", body: `caf${String.fromCodePoint(0xfffd)}e` },
      { mediaType: "text/plain", body: "~~~???" },
    ]);
    // What the client is given back of its bytes is as A2A writes bytes. `ask` held the whole
    // result against the A2A project's schema.
    const history = (reply.result?.["task"] as { history: { parts: Record<string, unknown>[] }[] })
      .history;
    expect(history[0]?.parts[1]).toStrictEqual({ raw: "fn5+Pz8/", mediaType: "text/plain" });
  });

  it("reads a request that says it is JSON, and no other: a page in a browser cannot post one unasked", async () => {
    const posted = (type: string | undefined) =>
      server.handle({
        method: "POST",
        path: `/a2a/${id}?A2A-Version=1.0`,
        headers: type === undefined ? {} : { "content-type": type },
        body: utf8('{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"t"}}'),
      });
    for (const type of [
      undefined,
      "text/plain",
      "application/x-www-form-urlencoded",
      "multipart/form-data",
      "application/jsonx",
    ]) {
      const answer = await posted(type);
      expect(answer.status, String(type)).toBe(415);
      expect(new TextDecoder().decode(answer.body)).toBe(
        "A request is JSON, and says so: Content-Type: application/json.\n",
      );
    }
    for (const type of ["application/json", "Application/JSON; charset=utf-8"]) {
      expect((await posted(type)).status, type).toBe(200);
    }
  });

  it("keeps so many tasks of a mind, and takes no message that would begin one more", async () => {
    const book = new Book(join(gateway.home.dir, "front"));
    const before = book.count(mina);
    const planted: string[] = [];
    for (let n = before; n < MAX_TASKS; n++) {
      const name = `planted-${String(n)}`;
      planted.push(name);
      book.put({
        id: name,
        mind: mina,
        contextId: "ctx-planted",
        state: "TASK_STATE_WORKING",
        at: new Date().toISOString(),
        artifacts: [],
        history: [],
        session: "bciqsession",
        request: "bciqrequest",
        announced: true,
      });
    }
    try {
      const full = await ask("SendMessage", { message: message("One more.") });
      expect(full.error).toMatchObject({
        code: -32004,
        message: "This agent keeps as many tasks as it can. Ask again later.",
      });
      // Nothing was said to the mind.
      const opened = await place.mind("mina");
      try {
        expect((await opened.mind.receive()).received).toStrictEqual([]);
      } finally {
        opened.mind.close();
      }
    } finally {
      for (const name of planted) book.drop(mina, name);
    }
    expect(book.count(mina)).toBe(before);
    // The tasks of a mind are in a directory of the mind's own.
    expect(join(gateway.home.dir, "front", "tasks", fileNameOf(mina))).toMatch(/[0-9a-f]{40}$/u);
  });
});
