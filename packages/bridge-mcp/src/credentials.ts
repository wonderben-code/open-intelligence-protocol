// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What an MCP server asks of whoever calls it: the gateway "holds whatever
 * credentials the MCP server requires" (Layer 0, 2.1).
 *
 * They are the operator's, in a file of the bridged mind's directory that
 * nobody else on the machine can read, `credentials.json`:
 *
 *     { "headers": { "Authorization": "Bearer …" } }      a server over HTTP
 *     { "env": { "API_KEY": "…" } }                       a server that is a command
 *
 * The gateway reads the file when it connects, sends the headers with
 * each request to the server and to nobody else, and says nothing of
 * their values: not in a log, not in an error, not in a packet.
 */

import { existsSync, statSync } from "node:fs";
import { join } from "node:path";

import { readObject, UsageError } from "@oip/local";

/** The name of the file, in a bridged mind's directory. */
export const CREDENTIALS_FILE = "credentials.json";

/** What the gateway sends a server, or starts it with. */
export interface Credentials {
  /** Headers of each request to a server over HTTP. */
  readonly headers: Readonly<Record<string, string>>;
  /** Variables of the environment of a server that is a command. */
  readonly env: Readonly<Record<string, string>>;
}

/** No credentials: what a server that asks for none is given. */
export const NONE: Credentials = { headers: {}, env: {} };

/** Headers that say how a request is framed, where it goes, or what MCP itself says in it. */
const NOT_THE_OPERATORS =
  /^(?:host|content-length|content-type|transfer-encoding|connection|accept|upgrade|te|trailer|mcp-.*)$/iu;
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/u;
/** A header's value: visible ASCII and spaces, with no line end in it. */
const HEADER_VALUE = /^[\x20-\x7e]{1,8192}$/u;
const VARIABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/u;

const isObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Reads the credentials of a bridged mind.
 *
 * @param dir - The bridged mind's directory.
 * @returns The credentials. `NONE` where there is no file.
 * @throws UsageError as `credentialsIn` does.
 */
export function readCredentials(dir: string): Credentials {
  return credentialsIn(join(dir, CREDENTIALS_FILE));
}

/**
 * Reads a file of credentials.
 *
 * @returns The credentials. `NONE` where there is no file.
 * @throws UsageError if the file can be read by others on the machine, or
 *   is no such file. The message names the member that is wrong, and never
 *   a value.
 */
export function credentialsIn(file: string): Credentials {
  if (!existsSync(file)) return NONE;
  // Where the system has such a thing as a mode, the file is its owner's alone.
  if (process.platform !== "win32" && (statSync(file).mode & 0o077) !== 0) {
    throw new UsageError(
      `${file} can be read by others on this machine: \`chmod 600\` it, and take the credentials in it for known`,
    );
  }
  let read: Readonly<Record<string, unknown>>;
  try {
    read = readObject(file, "the credentials");
  } catch {
    // What a parser says of a text may quote the text. Of this file, nothing is quoted.
    throw new UsageError(
      `${file} is no credentials: it is not JSON that holds one object. The gateway does not say what it read there`,
    );
  }
  const { headers = {}, env = {}, ...more } = read;
  if (!isObject(headers) || !isObject(env) || Object.keys(more).length > 0) {
    throw new UsageError(
      `${file} is no credentials: it has \`headers\`, \`env\`, or both, each an object of names and values`,
    );
  }
  for (const [name, value] of Object.entries(headers)) {
    if (!HEADER_NAME.test(name) || NOT_THE_OPERATORS.test(name)) {
      throw new UsageError(
        `${file}: ${JSON.stringify(name)} is no header the gateway sends for the operator`,
      );
    }
    if (typeof value !== "string" || !HEADER_VALUE.test(value)) {
      throw new UsageError(
        `${file}: the value of the header ${name} is not one line of visible characters`,
      );
    }
  }
  for (const [name, value] of Object.entries(env)) {
    if (!VARIABLE_NAME.test(name)) {
      throw new UsageError(`${file}: ${JSON.stringify(name)} is no name of a variable`);
    }
    if (typeof value !== "string" || value.includes("\0")) {
      throw new UsageError(`${file}: the value of the variable ${name} is no text`);
    }
  }
  return {
    headers: headers as Record<string, string>,
    env: env as Record<string, string>,
  };
}
