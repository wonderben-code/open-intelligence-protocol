// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The tools of an MCP server as the capabilities of a mind (Layer 0, 2.1).
 *
 * A tool becomes a capability with the tool's name as its `id`, its
 * description as its `summary`, and its input schema under
 * `ext["oip.mcp"].inputSchema` of the capability.
 *
 * What a server lists is a stranger's JSON. It is read member by member,
 * and nothing of it reaches a profile that a profile cannot hold: a name
 * that is too long or is there twice names no capability, and a schema the
 * profile has no room for is left out.
 */

import { canonicalBytes, type JsonValue } from "@oip/core";

import { carriedJson, holds, sizeOf } from "./json.ts";

/** The namespace of what a capability says of the tool it stands for. */
export const MCP_NAMESPACE = "oip.mcp";
/** The most capabilities a profile has (Layer 1, 16.1). */
export const MAX_CAPABILITIES = 256;
/** The longest `id` of a capability, in characters (Layer 1, 16.2). */
export const MAX_NAME = 128;
/** The longest summary the gateway writes for a tool, in characters. */
export const MAX_SUMMARY = 1024;
/** The largest input schema a capability carries, in bytes. */
export const MAX_SCHEMA_BYTES = 16_384;
/** The most all the input schemas of one profile take, in bytes. */
export const MAX_SCHEMAS_BYTES = 131_072;
/**
 * The most that everything a server wrote takes in a profile, in bytes of
 * the profile's canonical form: names, summaries and schemas together. A
 * profile stays a record that every implementation accepts (core 1.6: 256
 * KiB at least), with room for what is the gateway's own in it.
 */
export const MAX_CAPABILITIES_BYTES = 229_376;
/** The length summaries are cut to where a profile has no room for them whole, in characters. */
export const SHORT_SUMMARY = 256;

/** A capability the gateway writes for a tool. */
export interface ToolCapability {
  readonly id: string;
  readonly summary: string;
  readonly inputs: string[];
  readonly outputs: string[];
  readonly ext?: { readonly [MCP_NAMESPACE]: { readonly inputSchema: JsonValue } };
}

/** What a server lists, as far as a profile takes it. */
export interface Mapped {
  /** A capability for each tool that can be one, in the server's order. */
  readonly capabilities: readonly ToolCapability[];
  /** How many of them carry no input schema: the tool has none that fits. */
  readonly withoutSchema: number;
  /** What the server listed that is no capability, each with why. A name is any text, or is missing. */
  readonly left: readonly { readonly name?: string; readonly why: string }[];
}

const isObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const REPLACEMENT = String.fromCodePoint(0xfffd);

/** Text that a record's string can hold, cut to a length in characters. */
function textOf(text: string, most: number): string {
  // What no string of a record may hold (core 1.1) is replaced, as a decoder replaces what it cannot read.
  const clean = text.replace(/\p{Surrogate}|\p{Noncharacter_Code_Point}/gu, REPLACEMENT);
  const characters = Array.from(clean);
  return characters.length > most ? `${characters.slice(0, most - 1).join("")}…` : clean;
}

const words = (value: unknown): string | undefined =>
  typeof value === "string" && value.trim() !== "" ? value : undefined;

/**
 * Makes capabilities of the tools a server lists.
 *
 * @param listed - The `tools` of the server's answers to `tools/list`, as they came.
 */
export function capabilitiesOf(listed: readonly unknown[]): Mapped {
  const capabilities: ToolCapability[] = [];
  const left: { name?: string; why: string }[] = [];
  const seen = new Set<string>();
  let room = MAX_SCHEMAS_BYTES;
  let withoutSchema = 0;
  for (const tool of listed) {
    const name = isObject(tool) ? tool["name"] : undefined;
    if (!isObject(tool) || typeof name !== "string" || name === "") {
      left.push({ why: "it has no name" });
      continue;
    }
    if (Array.from(name).length > MAX_NAME || !holds(name)) {
      left.push({
        name,
        why: `its name is no \`id\` of a capability: ${String(MAX_NAME)} characters at most, of text a record holds`,
      });
      continue;
    }
    if (seen.has(name)) {
      left.push({ name, why: "another tool has its name" });
      continue;
    }
    if (capabilities.length >= MAX_CAPABILITIES) {
      left.push({ name, why: `a profile has ${String(MAX_CAPABILITIES)} capabilities at most` });
      continue;
    }
    seen.add(name);
    // Layer 0, 2.1: the description, or the tool's title, or else its name.
    const annotations = isObject(tool["annotations"]) ? tool["annotations"] : {};
    const summary =
      words(tool["description"]) ?? words(tool["title"]) ?? words(annotations["title"]) ?? name;
    const schema = tool["inputSchema"];
    let ext: ToolCapability["ext"];
    if (isObject(schema)) {
      let carried: JsonValue | undefined;
      try {
        carried = carriedJson(schema);
      } catch {
        // A schema that JSON cannot say, with a number that is not finite in it, is left out.
        carried = undefined;
      }
      const size = carried === undefined ? 0 : sizeOf(carried);
      if (carried !== undefined && size <= MAX_SCHEMA_BYTES && size <= room) {
        room -= size;
        ext = { [MCP_NAMESPACE]: { inputSchema: carried } };
      }
    }
    if (ext === undefined) withoutSchema += 1;
    capabilities.push({
      id: name,
      summary: textOf(summary, MAX_SUMMARY),
      inputs: ["application/json"],
      outputs: ["application/json"],
      ...(ext === undefined ? {} : { ext }),
    });
  }
  // The whole of it is measured as it will be signed: the canonical form of a list is its
  // members' canonical forms with a comma between each two, in brackets (core, Section 2). Each
  // capability is measured once, and again only where it changes. Where a profile has no room
  // for all of it, the schemas go first, from the last tool backwards, then the summaries are
  // cut, and then tools are left out from the end, each said to be.
  const sizes = capabilities.map((capability) => canonicalBytes(capability).length);
  const over = (): boolean =>
    sizes.reduce((sum, size) => sum + size, 0) + Math.max(0, sizes.length - 1) + 2 >
    MAX_CAPABILITIES_BYTES;
  const put = (place: number, capability: ToolCapability): void => {
    capabilities[place] = capability;
    sizes[place] = canonicalBytes(capability).length;
  };
  for (let last = capabilities.length - 1; last >= 0 && over(); last -= 1) {
    const capability = capabilities[last];
    if (capability?.ext === undefined) continue;
    const { ext: _, ...bare } = capability;
    put(last, bare);
    withoutSchema += 1;
  }
  if (over()) {
    for (const [place, capability] of capabilities.entries()) {
      put(place, { ...capability, summary: textOf(capability.summary, SHORT_SUMMARY) });
    }
  }
  while (over()) {
    const dropped = capabilities.pop();
    sizes.pop();
    if (dropped === undefined) break;
    // It was counted among those without a schema: every schema went before any tool did.
    if (dropped.ext === undefined) withoutSchema -= 1;
    left.push({ name: dropped.id, why: "the profile has no room for it" });
  }
  return { capabilities, withoutSchema, left };
}
