// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The records a mind holds, as a program names them and asks about them. */

import type { Mind } from "@oip/client";
import { contentId, formatRecordRef, type JsonObject, OipError } from "@oip/core";

import { UsageError } from "./errors.ts";
import { readObject } from "./files.ts";
import type { Opened } from "./mind.ts";

const CONTENT_ID = /^bciq[a-z2-7]{52}$/u;

/**
 * A record a program is told of: by the content ID of one the mind holds,
 * or by a file that holds it as JSON.
 *
 * @param what - What the record is to the program, for the message: "the offer".
 * @throws UsageError if the mind holds no such record, or there is no such file.
 */
export function recordOf(opened: Opened, named: string, what: string): JsonObject {
  if (!CONTENT_ID.test(named)) return readObject(named, what);
  const held = opened.mind.records().find((record) => contentId(record) === named);
  if (held === undefined) {
    throw new UsageError(
      `the mind holds no record ${named}: \`oip inbox\` reads what was sent to it, and a file names any other`,
    );
  }
  return held as unknown as JsonObject;
}

/** How a record is referred to by another: its author's address, and its content ID. */
export function refOf(record: JsonObject): string {
  const { author } = record;
  try {
    return formatRecordRef(typeof author === "string" ? author : "", contentId(record));
  } catch {
    throw new UsageError("that is no record another can refer to: it names no author");
  }
}

/** The status of a record, or `undefined` for a record of a type that has none. */
export async function statusOf(mind: Mind, record: object): Promise<string | undefined> {
  try {
    return await mind.statusOf(record);
  } catch (error) {
    if (error instanceof OipError && error.code === "invalid-record") return undefined;
    throw error;
  }
}
