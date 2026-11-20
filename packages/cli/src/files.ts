// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The files a command is given to read: JSON, under the profile of core
 * Section 1. What a file holds is as little trusted as what a service sent.
 */

import { readFileSync, statSync } from "node:fs";

import { type JsonObject, type JsonValue, MAX_RECORD_BYTES, parseJsonBytes } from "@oip/core";

import { UsageError } from "./command.ts";

/**
 * The most bytes of a file that are read. A record is at most 1 MiB in
 * canonical form (Layer 1, Section 19). A file may be indented, and may
 * hold several records: sixteen times that is room enough.
 */
export const MAX_FILE_BYTES = 16 * MAX_RECORD_BYTES;

/**
 * Reads a file of JSON.
 *
 * @param what - What the file is to the command, for the message: "the record".
 * @throws UsageError if there is no such file, it is too large, or it is not JSON of the profile.
 */
export function readJson(path: string, what: string): JsonValue {
  let bytes: Uint8Array;
  try {
    if (statSync(path).size > MAX_FILE_BYTES) {
      throw new UsageError(
        `${path} is more than ${String(MAX_FILE_BYTES)} bytes: ${what} is not that large`,
      );
    }
    bytes = readFileSync(path);
  } catch (error) {
    if (error instanceof UsageError) throw error;
    throw new UsageError(`${what} could not be read from ${path}: there is no such file to read`);
  }
  const parsed = parseJsonBytes(bytes, { maxLength: MAX_FILE_BYTES });
  if (!parsed.ok) {
    const [{ message, clause }] = parsed.issues;
    throw new UsageError(`${path} is not JSON a record may be in: ${message} (${clause})`);
  }
  return parsed.value;
}

/** Reads a file of JSON that holds one object. */
export function readObject(path: string, what: string): JsonObject {
  const value = readJson(path, what);
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new UsageError(`${path} holds no JSON object: ${what} is one`);
  }
  // `Array.isArray` does not tell a read-only array from an object, for the compiler.
  return value as JsonObject;
}
