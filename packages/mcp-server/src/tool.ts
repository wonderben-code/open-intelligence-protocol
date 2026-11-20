// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What a tool is, apart from the protocol that carries its calls. A tool
 * is written, and tested, without MCP: `./server.ts` gives each to a host.
 */

import type { JsonObject, JsonValue } from "@oip/core";

import type { Given } from "./given.ts";
import type { Work } from "./work.ts";

/** A question for the person, with what it is a question about. */
export interface Question {
  /**
   * The digest of what would be signed: the same for the same thing, and
   * for nothing else. An answer counts for the question it was given to.
   */
  readonly digest: string;
  /** The question, in words written by this server from what would be signed. */
  readonly text: string;
  /** What saying yes does, in a few words: the name of the box the person ticks. */
  readonly action: string;
}

/** How a tool learns what the person said, where it has to ask them. */
export interface Confirming {
  /** Whether the host can put a question to the person. */
  readonly canAsk: boolean;
  /**
   * What the person answered to the question with this digest: `yes` or
   * `no`, or `undefined` if that question was not put to them. An answer
   * is given once: asked of again, it is `undefined`.
   */
  answer(digest: string): "yes" | "no" | undefined;
}

/** What a tool comes back with: what it found or did, or a question that must be answered first. */
export type Said = { readonly result: JsonObject } | { readonly ask: Question };

/** A tool. */
export interface Tool {
  /** Its name, as Layer 0, 2.2 gives it. */
  readonly name: string;
  /** Its name for a person. */
  readonly title: string;
  /** What it does and when to use it, written for the model that will call it. */
  readonly description: string;
  /** The JSON Schema of its arguments. */
  readonly input: JsonObject;
  /** Whether it changes nothing: it sends nothing, signs nothing, and takes nothing from a mailbox. */
  readonly reads: boolean;
  /** Whether what it does cannot be taken back. A host may ask the person before such a call. */
  readonly binds?: true;
  /**
   * Does it.
   *
   * @throws UsageError for a call that cannot be done as it was made, in
   *   words the assistant can act on.
   */
  run(work: Work, given: Given, confirming: Confirming): Promise<Said>;
}

/** A JSON Schema for an object with these properties, and no others. */
export function objectOf(
  properties: Readonly<Record<string, JsonValue>>,
  required: readonly string[] = [],
): JsonObject {
  return {
    type: "object",
    properties: { ...properties },
    ...(required.length === 0 ? {} : { required: [...required] }),
    additionalProperties: false,
  };
}

/** The schema of a text argument. */
export const textOf = (description: string, maxLength = 8192): JsonObject => ({
  type: "string",
  description,
  maxLength,
});

/** The schema of a list of texts. */
export const listOf = (description: string, maxItems = 64): JsonObject => ({
  type: "array",
  description,
  items: { type: "string" },
  maxItems,
});

/** The schema of a yes-or-no argument. */
export const flagOf = (description: string): JsonObject => ({ type: "boolean", description });

/** The schema of a whole number within bounds. */
export const countOf = (description: string, minimum: number, maximum: number): JsonObject => ({
  type: "integer",
  description,
  minimum,
  maximum,
});

/** What the description of an address argument says of its form. */
export const ADDRESS = "a mind's address (did:oip:…)";
/** What the description of a record argument says of its form. */
export const RECORD = "the content ID (bciq…) of a record this mind holds";
/** What the description of a time argument says of its form. */
export const TIME = "a UTC time written as 2026-01-31T12:00:00Z";
