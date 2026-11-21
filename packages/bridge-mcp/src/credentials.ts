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
 *     { "query": { "api_key": "…" } }                     a server that wants its key in the URL
 *     { "env": { "API_KEY": "…" } }                       a server that is a command
 *
 * The gateway reads the file when it connects, sends the headers and the
 * query with each request to the server and to nobody else, and says
 * nothing of their values: not in a log, not in an error, not in a packet.
 * A server may say them back: what a server said is searched for them
 * before any of it is passed on (`withoutSecrets`, `holdsSecret`).
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
  /**
   * Parameters added to the query of each request to a server over HTTP.
   * The URL a server is named by has no query: it is published, in the
   * bridged mind's genesis, for good.
   */
  readonly query: Readonly<Record<string, string>>;
  /** Variables of the environment of a server that is a command. */
  readonly env: Readonly<Record<string, string>>;
}

/** No credentials: what a server that asks for none is given. */
export const NONE: Credentials = { headers: {}, query: {}, env: {} };

/** Headers that say how a request is framed, where it goes, or what MCP itself says in it. */
const NOT_THE_OPERATORS =
  /^(?:host|content-length|content-type|transfer-encoding|connection|accept|upgrade|te|trailer|mcp-.*)$/iu;
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/u;
/** A header's value: visible ASCII and spaces, with no line end in it. */
const HEADER_VALUE = /^[\x20-\x7e]{1,8192}$/u;
const VARIABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/u;
const PARAMETER_NAME = /^[A-Za-z0-9._~-]{1,64}$/u;

/** What stands where a credential stood, in words of a server's that are passed on. */
export const WITHHELD = "[a credential of the gateway's operator]";
/** The shortest text that is searched for: a word as short as `Bearer` is no secret. */
const MIN_SECRET = 8;

/**
 * Every text of the credentials that is never to be said: each value, each
 * word of a value (the token after `Bearer`), what `Basic` hides, and each
 * of these as base64 writes it.
 */
export function secretsOf(credentials: Credentials): string[] {
  const secrets = new Set<string>();
  const take = (text: string): void => {
    if (text.length >= MIN_SECRET) secrets.add(text);
  };
  const values = [
    ...Object.values(credentials.headers),
    ...Object.values(credentials.query),
    ...Object.values(credentials.env),
  ];
  for (const value of values) {
    take(value);
    for (const word of value.split(/\s+/u)) {
      take(word);
      // `Basic` is followed by a name and a password in base64: a server may say either back.
      if (/^[A-Za-z0-9+/_-]{8,}={0,2}$/u.test(word)) {
        const hidden = Buffer.from(word, "base64").toString("utf8");
        if (/^[\x20-\x7e]+$/u.test(hidden)) {
          take(hidden);
          for (const part of hidden.split(":")) take(part);
        }
      }
    }
  }
  for (const secret of [...secrets]) {
    const bytes = Buffer.from(secret, "utf8");
    take(bytes.toString("base64"));
    take(bytes.toString("base64").replace(/=+$/u, ""));
    take(bytes.toString("base64url"));
    take(encodeURIComponent(secret));
  }
  // The longest first: a value is replaced whole before a word of it is.
  return [...secrets].sort((one, other) => other.length - one.length);
}

/** Whether a text holds a credential, or a word of one. */
export function holdsSecret(text: string, secrets: readonly string[]): boolean {
  return secrets.some((secret) => text.includes(secret));
}

/**
 * Whether a value a server returned repeats a credential: in a string of
 * it, in a member's name, or in its JSON text, where a key that is all
 * digits may stand as a number.
 */
export function repeatsSecret(value: unknown, secrets: readonly string[]): boolean {
  if (secrets.length === 0) return false;
  const inside = (one: unknown, depth: number): boolean => {
    if (typeof one === "string") return holdsSecret(one, secrets);
    // What nests deeper than any value a packet carries is looked at as text, below.
    if (typeof one !== "object" || one === null || depth > 256) return false;
    return Object.entries(one).some(
      ([name, member]) => holdsSecret(name, secrets) || inside(member, depth + 1),
    );
  };
  if (inside(value, 0)) return true;
  let text: unknown;
  try {
    text = JSON.stringify(value);
  } catch {
    // What has no text is not carried at all.
    return false;
  }
  return typeof text === "string" && holdsSecret(text, secrets);
}

/** A server's words with every credential they repeat taken out. */
export function withoutSecrets(text: string, secrets: readonly string[]): string {
  let clean = text;
  for (const secret of secrets) clean = clean.split(secret).join(WITHHELD);
  return clean;
}

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
 *   is no such file. The message says what kind of thing is wrong, and
 *   quotes nothing of the file: not a value, and not a name, since a file
 *   with a name and its value the wrong way round has a secret for a name.
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
  const { headers = {}, query = {}, env = {}, ...more } = read;
  if (!isObject(headers) || !isObject(query) || !isObject(env) || Object.keys(more).length > 0) {
    throw new UsageError(
      `${file} is no credentials: it has \`headers\`, \`query\` or \`env\`, each an object of names and values`,
    );
  }
  // Which member is wrong is said by its place, and nothing of it is quoted.
  const wrong = (kind: string, place: number, why: string): UsageError =>
    new UsageError(`${file}: the ${kind} at place ${String(place + 1)} ${why}`);
  for (const [place, [name, value]] of Object.entries(headers).entries()) {
    if (!HEADER_NAME.test(name) || NOT_THE_OPERATORS.test(name)) {
      throw wrong(
        "header",
        place,
        "has a name that is no header the gateway sends for the operator",
      );
    }
    if (typeof value !== "string" || !HEADER_VALUE.test(value)) {
      throw wrong("header", place, "has a value that is not one line of visible characters");
    }
  }
  for (const [place, [name, value]] of Object.entries(query).entries()) {
    if (!PARAMETER_NAME.test(name)) {
      throw wrong("parameter of the query", place, "has a name that is none of a parameter");
    }
    if (typeof value !== "string" || !HEADER_VALUE.test(value)) {
      throw wrong(
        "parameter of the query",
        place,
        "has a value that is not one line of visible characters",
      );
    }
  }
  for (const [place, [name, value]] of Object.entries(env).entries()) {
    if (!VARIABLE_NAME.test(name)) {
      throw wrong("variable", place, "has a name that is no name of a variable");
    }
    if (typeof value !== "string" || value.includes("\0")) {
      throw wrong("variable", place, "has a value that is no text");
    }
  }
  return {
    headers: headers as Record<string, string>,
    query: query as Record<string, string>,
    env: env as Record<string, string>,
  };
}
