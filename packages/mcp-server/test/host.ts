// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * An MCP host, for the tests: the official client, connected to a server
 * for a mind in either era of the protocol, with a person behind it who
 * answers as the test says.
 */

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import {
  createMcpHandler,
  InMemoryTransport,
  type McpServerFactory,
} from "@modelcontextprotocol/server";
import type { JsonObject } from "@oip/core";

import { serverFactory, type Work } from "../src/index.ts";

/** The older revisions, which open with a handshake, or that of 2026-07-28, which has none. */
export type Era = "legacy" | "modern";

/** What the person answers when they are asked. */
export interface Answer {
  // The library's result takes other members too: an answer here has these alone.
  [member: string]: unknown;
  action: "accept" | "decline" | "cancel";
  content?: Record<string, string | number | boolean | string[]>;
}

/** A host connected to a server, as a test drives it. */
export interface Connected {
  readonly client: Client;
  /** The questions the person was put, in order. */
  readonly questions: string[];
  close(): Promise<void>;
}

/**
 * Connects a client to a server for a mind.
 *
 * @param with.answer - What the person answers when asked. Without it the host cannot ask.
 * @param with.manual - The client hands a call that needs the person back to the test.
 * @param with.factory - The servers' factory, where two connections are to share one.
 */
export async function connect(
  era: Era,
  work: Work,
  options: {
    readonly answer?: (question: string) => Answer;
    readonly manual?: boolean;
    readonly factory?: McpServerFactory;
  } = {},
): Promise<Connected> {
  const factory = options.factory ?? serverFactory(work, { log: () => undefined });
  const questions: string[] = [];
  const client = new Client(
    { name: "a-test-host", version: "1.0.0" },
    {
      capabilities: options.answer === undefined ? {} : { elicitation: { form: {} } },
      ...(era === "modern" ? { versionNegotiation: { mode: "auto" as const } } : {}),
      ...(options.manual === true ? { inputRequired: { autoFulfill: false } } : {}),
    },
  );
  const { answer } = options;
  if (answer !== undefined) {
    client.setRequestHandler("elicitation/create", (request) => {
      const { message } = request.params as { message: string };
      questions.push(message);
      return Promise.resolve(answer(message));
    });
  }
  if (era === "legacy") {
    const [ours, theirs] = InMemoryTransport.createLinkedPair();
    const server = await factory({ era });
    await server.connect(theirs);
    await client.connect(ours);
    return {
      client,
      questions,
      close: async () => {
        await client.close();
        await server.close();
      },
    };
  }
  const handler = createMcpHandler(factory);
  await client.connect(
    new StreamableHTTPClientTransport(new URL("http://server.test/mcp"), {
      fetch: (url, init) => handler.fetch(new Request(url, init)),
    }),
  );
  return { client, questions, close: () => client.close() };
}

/** What a tool said, as a program reads it. */
export const said = (result: { structuredContent?: unknown }): JsonObject =>
  result.structuredContent as JsonObject;
