// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The server through MCP itself: the official client on one side, the
 * server on the other, in both eras of the protocol. The older revisions
 * open with a handshake, and the server asks the person by a request of
 * its own. The revision of 2026-07-28 has neither: a call that needs the
 * person comes back saying so, and is made again with their answer.
 *
 * What a host could send that a well-behaved one would not is sent here
 * too: an answer nobody asked for, a state that was altered, an answer
 * given to another question, and the same answer twice.
 */

import type { McpServerFactory } from "@modelcontextprotocol/server";
import type { JsonObject } from "@oip/core";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { INSTRUCTIONS, NOTICE, serverFactory, TOOLS, VERSION, type Work } from "../src/index.ts";
import { PASSPHRASE, Place } from "./harness.ts";
import { type Answer, connect, type Connected, type Era, said } from "./host.ts";

let place: Place;
let ada: string;
let bob: string;
let adas: Work;

beforeAll(async () => {
  place = await new Place().start();
  ada = await place.make("ada", { name: "Ada" }, "person");
  bob = await place.make("bob", {
    name: "Bob",
    capabilities: [{ id: "proofread", summary: "Proofreads a chapter" }],
  });
  adas = place.work("ada");
});
afterAll(async () => {
  await place.close();
});

/** The Commitments the mind of a name holds. */
async function commitments(name: string): Promise<number> {
  const opened = await place.mind(name);
  try {
    return opened.mind.records().filter((record) => record.type === "Commitment").length;
  } finally {
    opened.mind.close();
  }
}

const deal = (amount: string): JsonObject => ({
  debtors: [bob],
  creditors: ["me"],
  promise: "A chapter proofread",
  price: { amount, currency: "USD" },
});

describe.each<Era>(["legacy", "modern"])("an MCP host of the %s era", (era) => {
  it(`${clause("L0 2.2")} is given the nine tools, in order, each with its schema and what it does to the world`, async () => {
    const host = await connect(era, adas);
    try {
      expect(host.client.getServerVersion()).toMatchObject({ name: "oip", version: VERSION });
      expect(host.client.getInstructions()).toBe(INSTRUCTIONS);
      const { tools } = await host.client.listTools();
      expect(tools.map(({ name }) => name)).toEqual(TOOLS.map(({ name }) => name));
      for (const [index, tool] of tools.entries()) {
        const ours = TOOLS[index];
        expect(tool.description).toBe(ours?.description);
        expect(tool.inputSchema).toMatchObject(ours?.input ?? {});
        expect(tool.annotations).toMatchObject({
          readOnlyHint: ours?.reads,
          destructiveHint: ours?.binds === true,
        });
      }
      expect(tools.find(({ name }) => name === "oip_commit")?.annotations).toMatchObject({
        readOnlyHint: false,
        destructiveHint: true,
      });
    } finally {
      await host.close();
    }
  });

  it("is answered with JSON to read, and the same for a program", async () => {
    const host = await connect(era, adas);
    try {
      const result = await host.client.callTool({ name: "oip_whoami", arguments: {} });
      expect(result.isError).not.toBe(true);
      expect(said(result)).toMatchObject({ address: ada, kind: "person" });
      const [block] = result.content as { type: string; text: string }[];
      expect(block?.type).toBe("text");
      expect(JSON.parse(block?.text ?? "")).toEqual(said(result));
    } finally {
      await host.close();
    }
  });

  it(`${clause("L0 2.2")} is given what others wrote as data, under \`untrusted\``, async () => {
    const host = await connect(era, adas);
    try {
      const result = await host.client.callTool({
        name: "oip_find",
        arguments: { want: "proofread" },
      });
      const found = said(result);
      expect(found["notice"]).toBe(NOTICE);
      expect(found["found"]).toMatchObject([{ mind: bob, untrusted: { name: "Bob" } }]);
    } finally {
      await host.close();
    }
  });

  it("is told what was wrong with a call, in words to act on", async () => {
    const host = await connect(era, adas);
    try {
      const missing = await host.client.callTool({
        name: "oip_status",
        arguments: { record: `bciq${"a".repeat(52)}` },
      });
      expect(missing.isError).toBe(true);
      expect(said(missing)["error"]).toMatch(/^the mind holds no record bciq/u);
      // Arguments that are not the tool's never reach it.
      const wrong = await host.client
        .callTool({ name: "oip_find", arguments: { want: "x", limit: "many" } })
        .then(
          (result) => ({ refused: result.isError === true }),
          () => ({ refused: true }),
        );
      expect(wrong).toEqual({ refused: true });
    } finally {
      await host.close();
    }
  });

  it("is told that the keys could not be opened, and nothing of the passphrase", async () => {
    const host = await connect(
      era,
      place.work("ada", {}, { env: { OIP_PASSPHRASE: "not the passphrase" } }),
    );
    try {
      const result = await host.client.callTool({ name: "oip_inbox", arguments: {} });
      expect(result.isError).toBe(true);
      expect(said(result)).toMatchObject({ code: "not-opened" });
      expect(JSON.stringify(result)).not.toContain("not the passphrase");
      expect(JSON.stringify(result)).not.toContain(PASSPHRASE);
    } finally {
      await host.close();
    }
  });

  it(`${clause("L0 2.2")} gets no signature where it cannot ask the person`, async () => {
    const before = await commitments("ada");
    const host = await connect(era, adas);
    try {
      const result = await host.client.callTool({ name: "oip_commit", arguments: deal("10") });
      expect(result.isError).toBe(true);
      expect(said(result)["error"]).toMatch(/^NOT SIGNED\./u);
      expect(await commitments("ada")).toBe(before);
    } finally {
      await host.close();
    }
  });

  it(`${clause("L0 2.2")} gets a signature once the person has confirmed the terms the server showed them`, async () => {
    const before = await commitments("ada");
    const host = await connect(era, adas, {
      answer: () => ({ action: "accept", content: { sign: true } }),
    });
    try {
      const result = await host.client.callTool({ name: "oip_commit", arguments: deal("11") });
      expect(result.isError).not.toBe(true);
      expect(said(result)).toMatchObject({
        signed: true,
        confirmedBy: "the user",
        says: { promise: "A chapter proofread", terms: { price: { amount: "11" } } },
      });
      expect(host.questions).toHaveLength(1);
      expect(host.questions[0]).toContain("WRITE AND SIGN a Commitment in your name");
      expect(host.questions[0]).toContain("A chapter proofread");
      expect(host.questions[0]).toContain("Price: 11 USD");
      expect(await commitments("ada")).toBe(before + 1);
    } finally {
      await host.close();
    }
  });

  it.each<[string, Answer]>([
    ["declines", { action: "decline" }],
    ["closes the question", { action: "cancel" }],
    ["answers no", { action: "accept", content: { sign: false } }],
    ["answers with something else", { action: "accept", content: { sign: "true" } }],
    ["answers with nothing", { action: "accept" }],
  ])(`${clause("L0 2.2")} gets no signature where the person %s`, async (_, answer) => {
    const before = await commitments("ada");
    const host = await connect(era, adas, { answer: () => answer });
    try {
      const result = await host.client.callTool({ name: "oip_commit", arguments: deal("12") });
      expect(said(result)).toMatchObject({ signed: false });
      expect(host.questions).toHaveLength(1);
      expect(await commitments("ada")).toBe(before);
    } finally {
      await host.close();
    }
  });

  it(`${clause("L0 2.2")} gets a signature unasked where the person's policy permits it`, async () => {
    const permitted = place.work("ada", { commit: [["<=", ".terms.price.amount", "5"]] });
    const host = await connect(era, permitted);
    try {
      const result = await host.client.callTool({ name: "oip_commit", arguments: deal("5") });
      expect(said(result)).toMatchObject({ signed: true, confirmedBy: "the user's policy" });
      const over = await host.client.callTool({ name: "oip_commit", arguments: deal("5.01") });
      expect(over.isError).toBe(true);
    } finally {
      await host.close();
    }
  });
});

describe("a host that does not behave", () => {
  /** A call that came back asking for the person. */
  interface Asking {
    readonly resultType: "input_required";
    readonly inputRequests: Record<string, { params: { message: string } }>;
    readonly requestState: string;
  }
  const yes = { confirm: { action: "accept", content: { sign: true } } };

  /** Makes a call by hand: with whatever answers and state the test sends. */
  async function round(
    host: Connected,
    given: JsonObject,
    more: { inputResponses?: unknown; requestState?: string } = {},
  ): Promise<{ asking?: Asking; said?: JsonObject; refused?: string }> {
    try {
      const result = (await host.client.callTool(
        { name: "oip_commit", arguments: given, ...more },
        { allowInputRequired: true },
      )) as unknown as Asking | { structuredContent: JsonObject };
      return "inputRequests" in result ? { asking: result } : { said: result.structuredContent };
    } catch (error) {
      return { refused: error instanceof Error ? error.message : "refused" };
    }
  }

  const manual = (factory?: McpServerFactory): Promise<Connected> =>
    connect("modern", adas, {
      answer: () => ({ action: "decline" }),
      manual: true,
      ...(factory === undefined ? {} : { factory }),
    });

  it(`${clause("L0 2.2")} gets no signature for an answer nobody asked for`, async () => {
    const before = await commitments("ada");
    const host = await manual();
    try {
      const first = await round(host, deal("20"), { inputResponses: yes });
      // The answer is to no question of this server's: the question is put.
      expect(first.asking?.inputRequests["confirm"]?.params.message).toContain("Price: 20 USD");
      expect(await commitments("ada")).toBe(before);
    } finally {
      await host.close();
    }
  });

  it(`${clause("L0 2.2")} gets no signature for a yes that was given to other terms`, async () => {
    const before = await commitments("ada");
    const host = await manual();
    try {
      const cheap = await round(host, deal("21"));
      expect(cheap.asking).toBeDefined();
      // The person said yes to 21. The call that comes back with it asks for 2100.
      const dear = await round(host, deal("2100"), {
        inputResponses: yes,
        requestState: cheap.asking?.requestState ?? "",
      });
      expect(dear.asking?.inputRequests["confirm"]?.params.message).toContain("Price: 2100 USD");
      expect(await commitments("ada")).toBe(before);
    } finally {
      await host.close();
    }
  });

  it(`${clause("L0 2.2")} gets no signature for a state that was altered, or that another server made`, async () => {
    const before = await commitments("ada");
    const host = await manual();
    const other = await manual();
    try {
      const asked = await round(host, deal("22"));
      const state = asked.asking?.requestState ?? "";
      const [version = "", body = "", mac = ""] = state.split(".");
      const forged = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as JsonObject;
      const altered = [
        version,
        Buffer.from(JSON.stringify({ ...forged, exp: 9_999_999_999 })).toString("base64url"),
        mac,
      ].join(".");
      for (const requestState of [altered, `${state}x`, "v1.e30.AAAA", ""]) {
        const result = await round(host, deal("22"), { inputResponses: yes, requestState });
        expect(result.said).toBeUndefined();
      }
      // A server that did not hand the state out does not take it: its key is its own.
      const elsewhere = await round(other, deal("22"), {
        inputResponses: yes,
        requestState: state,
      });
      expect(elsewhere.said).toBeUndefined();
      expect(await commitments("ada")).toBe(before);
    } finally {
      await host.close();
      await other.close();
    }
  });

  it(`${clause("L0 2.2")} gets one signature for one yes, however often it sends it`, async () => {
    const before = await commitments("ada");
    const factory = serverFactory(adas, { log: () => undefined });
    const host = await manual(factory);
    try {
      const asked = await round(host, deal("23"));
      const answered = { inputResponses: yes, requestState: asked.asking?.requestState ?? "" };
      const first = await round(host, deal("23"), answered);
      expect(first.said).toMatchObject({ signed: true, confirmedBy: "the user" });
      const again = await round(host, deal("23"), answered);
      expect(again.said).toBeUndefined();
      expect(again.asking?.requestState).not.toBe(asked.asking?.requestState);
      expect(await commitments("ada")).toBe(before + 1);
    } finally {
      await host.close();
    }
  });

  it("gets no signature for a no that it sends on as a yes later", async () => {
    const before = await commitments("ada");
    const host = await manual();
    try {
      const asked = await round(host, deal("24"));
      const requestState = asked.asking?.requestState ?? "";
      const no = await round(host, deal("24"), {
        inputResponses: { confirm: { action: "decline" } },
        requestState,
      });
      expect(no.said).toMatchObject({ signed: false });
      // The question was answered: its state takes no second answer.
      const then = await round(host, deal("24"), { inputResponses: yes, requestState });
      expect(then.said).toBeUndefined();
      expect(await commitments("ada")).toBe(before);
    } finally {
      await host.close();
    }
  });
});
