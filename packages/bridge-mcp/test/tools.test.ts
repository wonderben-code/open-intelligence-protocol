// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { canonicalBytes, parseJson } from "@oip/core";
import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  capabilitiesOf,
  jsonText,
  MAX_CAPABILITIES,
  MAX_CAPABILITIES_BYTES,
  MAX_NAME,
  MAX_SCHEMA_BYTES,
  MAX_SCHEMAS_BYTES,
  MAX_SUMMARY,
} from "../src/index.ts";

const NONCHARACTER = String.fromCodePoint(0xfffe);
const LONE = String.fromCodePoint(0xd800);
const REPLACED = String.fromCodePoint(0xfffd);
const ELLIPSIS = String.fromCodePoint(0x2026);

const SCHEMA = { type: "object", properties: { text: { type: "string" } }, required: ["text"] };

describe("the tools of an MCP server, as capabilities", () => {
  it(`${clause("L0 2.1", "L1 16.2")} are a capability each: the name as its id, the description as its summary, the input schema in a block of its own`, () => {
    const mapped = capabilitiesOf([
      { name: "echo", description: "Says what it is told.", inputSchema: SCHEMA },
      {
        name: "translate-legal.sw_en",
        description: "Translates.",
        inputSchema: { type: "object" },
      },
    ]);
    expect(mapped).toStrictEqual({
      capabilities: [
        {
          id: "echo",
          summary: "Says what it is told.",
          inputs: ["application/json"],
          outputs: ["application/json"],
          ext: { "oip.mcp": { inputSchema: SCHEMA } },
        },
        {
          id: "translate-legal.sw_en",
          summary: "Translates.",
          inputs: ["application/json"],
          outputs: ["application/json"],
          ext: { "oip.mcp": { inputSchema: { type: "object" } } },
        },
      ],
      withoutSchema: 0,
      left: [],
    });
  });

  it(`${clause("L0 2.1")} are summarised by a title, or else by the name, where a tool has no description`, () => {
    const { capabilities } = capabilitiesOf([
      { name: "a", title: "A title", description: "" },
      { name: "b", annotations: { title: "An older title" }, description: "   " },
      { name: "c", description: 7 },
      { name: "d", title: "A title", description: "A description wins." },
    ]);
    expect(capabilities.map(({ summary }) => summary)).toStrictEqual([
      "A title",
      "An older title",
      "c",
      "A description wins.",
    ]);
  });

  it(`${clause("L0 2.1")} carry a schema that no record holds as its JSON text`, () => {
    const schema = { type: "object", properties: { by: { type: "number", maximum: 0.5 } } };
    const { capabilities, withoutSchema } = capabilitiesOf([
      { name: "scale", inputSchema: schema },
    ]);
    expect(withoutSchema).toBe(0);
    const carried = capabilities[0]?.ext?.["oip.mcp"].inputSchema;
    expect(carried).toBe(jsonText(schema));
    expect(JSON.parse(carried as string)).toStrictEqual(schema);
  });

  it(`${clause("L0 2.1")} leave out a schema the profile has no room for, and stay capabilities`, () => {
    const wide = { type: "object", description: "x".repeat(MAX_SCHEMA_BYTES) };
    const one = capabilitiesOf([{ name: "wide", inputSchema: wide }]);
    expect(one).toMatchObject({ withoutSchema: 1, left: [] });
    expect(one.capabilities[0]).toStrictEqual({
      id: "wide",
      summary: "wide",
      inputs: ["application/json"],
      outputs: ["application/json"],
    });
    // Each schema fits, and all of them together do not: the first ones are carried.
    const each = { type: "object", description: "x".repeat(MAX_SCHEMA_BYTES - 100) };
    const many = capabilitiesOf(
      Array.from({ length: 12 }, (_, at) => ({ name: `tool-${String(at)}`, inputSchema: each })),
    );
    const carried = many.capabilities.filter(({ ext }) => ext !== undefined);
    expect(carried.length).toBe(Math.floor(MAX_SCHEMAS_BYTES / JSON.stringify(each).length));
    expect(many.withoutSchema).toBe(12 - carried.length);
    expect(carried.length).toBeGreaterThan(0);
    expect(many.withoutSchema).toBeGreaterThan(0);
    // What is no schema at all is none.
    expect(capabilitiesOf([{ name: "odd", inputSchema: "a schema" }]).withoutSchema).toBe(1);
    expect(capabilitiesOf([{ name: "odd", inputSchema: [SCHEMA] }]).withoutSchema).toBe(1);
  });

  it(`${clause("L1 16.2")} are no capability where the name is none a profile takes`, () => {
    const long = "n".repeat(MAX_NAME + 1);
    const mapped = capabilitiesOf([
      { name: "echo" },
      "a string",
      null,
      { description: "No name." },
      { name: "" },
      { name: 7 },
      { name: long },
      { name: `bad${NONCHARACTER}` },
      { name: `worse${LONE}` },
      { name: "echo", description: "The second of its name." },
      { name: "n".repeat(MAX_NAME) },
    ]);
    expect(mapped.capabilities.map(({ id }) => id)).toStrictEqual(["echo", "n".repeat(MAX_NAME)]);
    expect(mapped.left.map(({ name }) => name)).toStrictEqual([
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      long,
      `bad${NONCHARACTER}`,
      `worse${LONE}`,
      "echo",
    ]);
    expect(mapped.left.at(-1)?.why).toBe("another tool has its name");
    expect(mapped.left[0]?.why).toBe("it has no name");
    // A name is counted in characters, not in the units a string is made of.
    const emoji = String.fromCodePoint(0x1f600).repeat(MAX_NAME);
    expect(capabilitiesOf([{ name: emoji }]).capabilities).toHaveLength(1);
  });

  it(`${clause("L1 16.1")} are 256 at most: the rest are left out, and said to be`, () => {
    const listed = Array.from({ length: MAX_CAPABILITIES + 2 }, (_, at) => ({
      name: `tool-${String(at)}`,
    }));
    const mapped = capabilitiesOf(listed);
    expect(mapped.capabilities).toHaveLength(MAX_CAPABILITIES);
    expect(mapped.left).toStrictEqual([
      { name: "tool-256", why: "a profile has 256 capabilities at most" },
      { name: "tool-257", why: "a profile has 256 capabilities at most" },
    ]);
  });

  it(`${clause("core 1.6")} fit a profile that every implementation accepts: schemas go first, then summaries are cut, then tools are left out`, () => {
    const sizeOf = (capabilities: unknown): number => canonicalBytes(capabilities).length;
    const description = "d".repeat(MAX_SUMMARY);
    const name = (at: number): string => `tool-${String(at).padStart(3, "0")}-${"n".repeat(110)}`;
    // As many tools as a profile has, each with a summary as long as one may be: more than the
    // profile has room for, with the schemas that fit beside them.
    const full = capabilitiesOf(
      Array.from({ length: MAX_CAPABILITIES }, (_, at) => ({
        name: name(at),
        description,
        inputSchema: { type: "object", description: "s".repeat(400) },
      })),
    );
    expect(sizeOf(full.capabilities)).toBeLessThanOrEqual(MAX_CAPABILITIES_BYTES);
    // Every tool is a capability still: the schemas went, and the summaries were cut.
    expect(full.capabilities).toHaveLength(MAX_CAPABILITIES);
    expect(full.left).toStrictEqual([]);
    expect(full.withoutSchema).toBe(MAX_CAPABILITIES);
    expect(Array.from(full.capabilities[0]?.summary ?? "")).toHaveLength(256);
    expect(full.capabilities[0]?.summary.endsWith(ELLIPSIS)).toBe(true);

    // Where the schemas alone are too many, the last tools lose theirs and the first keep them.
    const some = capabilitiesOf(
      Array.from({ length: MAX_CAPABILITIES }, (_, at) => ({
        name: name(at),
        description: "d".repeat(380),
        inputSchema: { type: "object", description: "s".repeat(400) },
      })),
    );
    expect(sizeOf(some.capabilities)).toBeLessThanOrEqual(MAX_CAPABILITIES_BYTES);
    expect(some.left).toStrictEqual([]);
    expect(some.capabilities[0]?.ext).toBeDefined();
    expect(some.capabilities.at(-1)?.ext).toBeUndefined();
    expect(some.capabilities[0]?.summary).toBe("d".repeat(380));
    expect(some.withoutSchema).toBe(
      some.capabilities.filter(({ ext }) => ext === undefined).length,
    );
    expect(some.withoutSchema).toBeGreaterThan(0);
    expect(some.withoutSchema).toBeLessThan(MAX_CAPABILITIES);

    // Names and summaries of characters that take four bytes each: cut, the summaries are
    // still more than a profile has room for, and the last tools are left out, each said to be.
    const wide = String.fromCodePoint(0x1f600);
    const most = capabilitiesOf(
      Array.from({ length: MAX_CAPABILITIES }, (_, at) => ({
        name: `${String(at).padStart(3, "0")}${wide.repeat(MAX_NAME - 3)}`,
        description: wide.repeat(MAX_SUMMARY),
      })),
    );
    expect(sizeOf(most.capabilities)).toBeLessThanOrEqual(MAX_CAPABILITIES_BYTES);
    expect(most.capabilities.length).toBeGreaterThan(0);
    expect(most.capabilities.length).toBeLessThan(MAX_CAPABILITIES);
    expect(most.capabilities.length + most.left.length).toBe(MAX_CAPABILITIES);
    expect(most.left.every(({ why }) => why === "the profile has no room for it")).toBe(true);
    // Left out from the end: the first tools are the ones that stay.
    expect(most.capabilities[0]?.id.startsWith("000")).toBe(true);
    expect(most.left[0]?.name?.startsWith("255")).toBe(true);
    expect(most.withoutSchema).toBe(most.capabilities.length);
  });

  it("leave out a schema that JSON cannot say, and carry what a record holds as the parser read it", () => {
    const { capabilities, withoutSchema } = capabilitiesOf([
      { name: "endless", inputSchema: { type: "object", maximum: Number.POSITIVE_INFINITY } },
      { name: "plain", inputSchema: SCHEMA },
    ]);
    expect(withoutSchema).toBe(1);
    expect(capabilities[0]?.ext).toBeUndefined();
    expect(capabilities[1]?.ext).toStrictEqual({ "oip.mcp": { inputSchema: SCHEMA } });
  });

  it(`${clause("core 1.1")} have a summary that a record holds, of a bounded length`, () => {
    const { capabilities } = capabilitiesOf([
      { name: "odd", description: `A text with ${NONCHARACTER} and ${LONE} in it.` },
      { name: "long", description: "d".repeat(MAX_SUMMARY + 50) },
      { name: "just", description: "d".repeat(MAX_SUMMARY) },
    ]);
    expect(capabilities[0]?.summary).toBe(`A text with ${REPLACED} and ${REPLACED} in it.`);
    expect(capabilities[1]?.summary).toBe(`${"d".repeat(MAX_SUMMARY - 1)}${ELLIPSIS}`);
    expect(capabilities[2]?.summary).toBe("d".repeat(MAX_SUMMARY));
    // Everything the mapping made is JSON of a record.
    expect(parseJson(JSON.stringify({ capabilities })).ok).toBe(true);
  });
});
