// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * An MCP server for the tests, made with the MCP project's own server: the
 * gateway's connection is tried against the real thing. Run as a program,
 * it serves over the standard streams, as a server that is a command does.
 */

import { fileURLToPath } from "node:url";

import {
  fromJsonSchema,
  inputRequired,
  McpServer,
  type McpServerFactory,
} from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";

/** How many tools the server lists, and in how many pages. */
export const TOOLS = 4;

/** How often `ask` was called, in this process. */
export const asked = { times: 0 };

/**
 * The server: `echo` says what it is told, `environment` says what a
 * variable holds, `boom` throws, and `ask` wants an answer of a person
 * before it does anything.
 */
export const factory: McpServerFactory = () => {
  const server = new McpServer(
    { name: "fixture-server", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.registerTool(
    "echo",
    {
      description: "Says what it is told.",
      inputSchema: fromJsonSchema<{ text: string }>({
        type: "object",
        properties: { text: { type: "string" } },
        required: ["text"],
      }),
    },
    ({ text }) => ({ content: [{ type: "text", text }] }),
  );
  server.registerTool(
    "environment",
    {
      description: "Says what a variable of its environment holds.",
      inputSchema: fromJsonSchema<{ name: string }>({
        type: "object",
        properties: { name: { type: "string" } },
        required: ["name"],
      }),
    },
    ({ name }) => ({ content: [{ type: "text", text: process.env[name] ?? "(not set)" }] }),
  );
  server.registerTool(
    "boom",
    { description: "Fails.", inputSchema: fromJsonSchema<object>({ type: "object" }) },
    () => {
      throw new Error("The disk is full.");
    },
  );
  server.registerTool(
    "ask",
    {
      description: "Asks before it acts.",
      inputSchema: fromJsonSchema<object>({ type: "object" }),
    },
    () => {
      asked.times += 1;
      return inputRequired({
        inputRequests: {
          confirm: inputRequired.elicit({
            message: "Go on?",
            requestedSchema: { type: "object", properties: { confirm: { type: "boolean" } } },
          }),
        },
      });
    },
  );
  return server;
};

if (process.argv[1] === fileURLToPath(import.meta.url)) serveStdio(factory);
