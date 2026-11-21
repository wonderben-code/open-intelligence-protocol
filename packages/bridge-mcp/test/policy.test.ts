// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { UsageError } from "@oip/local";
import { clause } from "@oip/testkit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  allows,
  ANYONE,
  CREDENTIALS_FILE,
  credentialsIn,
  NOBODY,
  NONE,
  type Policy,
  POLICY_FILE,
  readCredentials,
  readPolicy,
} from "../src/index.ts";
import {
  holdsSecret,
  repeatsSecret,
  secretsOf,
  WITHHELD,
  withoutSecrets,
} from "../src/credentials.ts";

const AMINA = `did:oip:bciq${"a".repeat(52)}`;
const BORIS = `did:oip:bciq${"b".repeat(51)}a`;
const FIRM = `did:oip:bciq${"c".repeat(51)}a`;

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "oip-bridge-mcp-policy-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const write = (name: string, value: unknown, mode = 0o600): string => {
  const file = join(dir, name);
  writeFileSync(file, typeof value === "string" ? value : JSON.stringify(value), { mode });
  chmodSync(file, mode);
  return file;
};

describe("the operator's checks", () => {
  it(`${clause("L0 2.1")} cover nobody where the operator has written none`, () => {
    expect(readPolicy(dir)).toBe(NOBODY);
    expect(allows(NOBODY, "echo", [AMINA])).toBe(false);
    write(POLICY_FILE, { allow: {} });
    expect(allows(readPolicy(dir), "echo", [AMINA])).toBe(false);
  });

  it(`${clause("L0 2.1")} cover a requester whose authority, its own or one it was given, a tool's entry names`, () => {
    write(POLICY_FILE, { allow: { echo: "anyone", send: [AMINA, FIRM], "*": [FIRM], none: [] } });
    const policy = readPolicy(dir);
    expect(allows(policy, "echo", [BORIS])).toBe(true);
    expect(allows(policy, "send", [AMINA])).toBe(true);
    expect(allows(policy, "send", [BORIS])).toBe(false);
    // A sender that was sent for a mind the entry names has that mind's authority.
    expect(allows(policy, "send", [BORIS, FIRM])).toBe(true);
    // A tool with an entry of its own is not opened by the entry for the rest.
    expect(allows(policy, "none", [FIRM])).toBe(false);
    expect(allows(policy, "any_other", [FIRM])).toBe(true);
    expect(allows(policy, "any_other", [AMINA])).toBe(false);
    expect(allows(policy, "any_other", [])).toBe(false);
  });

  it("find no entry that the operator did not write, whatever a tool is called", () => {
    write(POLICY_FILE, { allow: { echo: [AMINA] } });
    const policy = readPolicy(dir);
    for (const tool of ["constructor", "__proto__", "toString", "hasOwnProperty", "*"]) {
      expect(allows(policy, tool, [AMINA]), tool).toBe(false);
    }
    // A tool may be called by such a name, and is then opened by its own entry.
    const named = { allow: { constructor: ANYONE } } as unknown as Policy;
    expect(allows(named, "constructor", [BORIS])).toBe(true);
  });

  it("are refused where they are none: a gateway does not guess what its operator meant", () => {
    const wrong: unknown[] = [
      "{",
      "[]",
      {},
      { allow: [] },
      { allow: { echo: "everybody" } },
      { allow: { echo: AMINA } },
      { allow: { echo: ["amina"] } },
      { allow: { echo: [AMINA, 7] } },
      { allow: { echo: true } },
      { allow: {}, deny: {} },
      { allows: {} },
    ];
    for (const value of wrong) {
      write(POLICY_FILE, value);
      expect(() => readPolicy(dir), JSON.stringify(value)).toThrow(UsageError);
    }
    write(POLICY_FILE, { allow: { echo: "everybody" } });
    expect(() => readPolicy(dir)).toThrow('who may call "echo" is "anyone", or a list');
  });
});

describe("the credentials of a server", () => {
  it(`${clause("L0 2.1")} are none where the operator gave none, and what the file says where there is one`, () => {
    expect(readCredentials(dir)).toBe(NONE);
    write(CREDENTIALS_FILE, { headers: { Authorization: "Bearer abc", "X-Api-Key": "k 1" } });
    expect(readCredentials(dir)).toStrictEqual({
      headers: { Authorization: "Bearer abc", "X-Api-Key": "k 1" },
      query: {},
      env: {},
    });
    const file = write("other.json", { env: { API_KEY: "abc", _HOME: "" } });
    expect(credentialsIn(file)).toStrictEqual({
      headers: {},
      query: {},
      env: { API_KEY: "abc", _HOME: "" },
    });
    // What a server wants in its query: the URL the mind names the server by has none.
    write(CREDENTIALS_FILE, { query: { api_key: "k-1", "tenant.id": "7" } });
    expect(readCredentials(dir)).toStrictEqual({
      headers: {},
      query: { api_key: "k-1", "tenant.id": "7" },
      env: {},
    });
    expect(credentialsIn(join(dir, "absent.json"))).toBe(NONE);
  });

  it(`${clause("L0 2.1")} are taken only from a file that nobody else on the machine can read`, () => {
    for (const mode of [0o640, 0o604, 0o660, 0o644, 0o666]) {
      write(CREDENTIALS_FILE, { headers: { Authorization: "Bearer abc" } }, mode);
      expect(() => readCredentials(dir), mode.toString(8)).toThrow("can be read by others");
    }
    write(CREDENTIALS_FILE, { headers: { Authorization: "Bearer abc" } }, 0o400);
    expect(readCredentials(dir).headers).toStrictEqual({ Authorization: "Bearer abc" });
  });

  it("are refused where they are none, in words that hold no value of theirs", () => {
    const SECRET = "s3cret-value";
    const wrong: unknown[] = [
      // Text that is no JSON, or no JSON of one object: what a parser says of it could quote it.
      `{"headers": {"Authorization": "${SECRET}"`,
      `{"${SECRET}": 1, "${SECRET}": 2}`,
      `["${SECRET}"]`,
      `{"headers": {"Authorization": "${SECRET}"}, "rate": 0.5}`,
      { headers: [SECRET] },
      { env: SECRET },
      { headers: {}, token: SECRET },
      { headers: { "A Name": SECRET } },
      { headers: { "": SECRET } },
      // A header that frames the request, says where it goes, or is MCP's own.
      { headers: { Host: SECRET } },
      { headers: { "content-length": SECRET } },
      { headers: { "Mcp-Session-Id": SECRET } },
      { headers: { Accept: SECRET } },
      // A value that would end the header, and begin another.
      { headers: { Authorization: `${SECRET}\r\nX-Other: 1` } },
      { headers: { Authorization: `${SECRET}\n` } },
      { headers: { Authorization: "" } },
      { headers: { Authorization: 7 } },
      { headers: { Authorization: `${SECRET}é` } },
      { env: { "A-NAME": SECRET } },
      { env: { "1NAME": SECRET } },
      { env: { NAME: 7 } },
      { env: { NAME: `${SECRET}\0` } },
      { query: [SECRET] },
      { query: { "a name": SECRET } },
      { query: { key: 7 } },
      { query: { key: `${SECRET}\n` } },
      { query: { key: "" } },
      // A name and its value the wrong way round: the name is the secret, and is not quoted.
      { headers: { [`Bearer ${SECRET}`]: "Authorization" } },
      { env: { [SECRET]: "API_KEY" } },
      { query: { [`${SECRET} `]: "key" } },
    ];
    for (const value of wrong) {
      write(CREDENTIALS_FILE, value);
      let said = "";
      try {
        readCredentials(dir);
      } catch (error) {
        expect(error).toBeInstanceOf(UsageError);
        said = (error as Error).message;
      }
      expect(said, JSON.stringify(value)).not.toBe("");
      expect(said).not.toContain(SECRET);
    }
    // Which member is wrong is said by its place.
    write(CREDENTIALS_FILE, { headers: { "X-First": "one", [`Bearer ${SECRET}`]: "two" } });
    expect(() => readCredentials(dir)).toThrow(
      "the header at place 2 has a name that is no header",
    );
    write(CREDENTIALS_FILE, { env: { FIRST: "one", SECOND: "two", THIRD: 3 } });
    expect(() => readCredentials(dir)).toThrow(
      "the variable at place 3 has a value that is no text",
    );
    write(CREDENTIALS_FILE, { query: { key: 7 } });
    expect(() => readCredentials(dir)).toThrow("the parameter of the query at place 1");
  });
});

describe("what a server says back of the credentials", () => {
  const credentials = {
    headers: { Authorization: "Bearer sk-live-0123456789abcdef", "X-Short": "abc" },
    query: { api_key: "q-key/with+signs=" },
    env: { BASIC: "Basic dXNlci1uYW1lOnBhc3N3b3JkLTEyMw==", TOKEN: "t0ken-of-the-env" },
  };
  const secrets = secretsOf(credentials);

  it("is searched for each value, each word of a value, and what `Basic` hides", () => {
    for (const secret of [
      "Bearer sk-live-0123456789abcdef",
      "sk-live-0123456789abcdef",
      "q-key/with+signs=",
      "t0ken-of-the-env",
      "dXNlci1uYW1lOnBhc3N3b3JkLTEyMw==",
      // The name and the password that `Basic` writes in base64.
      "user-name:password-123",
      "user-name",
      "password-123",
      // And each as base64 and as a URL write it.
      Buffer.from("sk-live-0123456789abcdef").toString("base64"),
      Buffer.from("sk-live-0123456789abcdef").toString("base64url"),
      encodeURIComponent("q-key/with+signs="),
    ]) {
      expect(secrets, secret).toContain(secret);
      expect(holdsSecret(`The server said ${secret}.`, secrets), secret).toBe(true);
    }
    // A word as short as `Bearer`, or a value of three letters, is no secret: it would be
    // found in every other sentence.
    expect(secrets).not.toContain("Bearer");
    expect(secrets).not.toContain("Basic");
    expect(secrets).not.toContain("abc");
    expect(holdsSecret("The bearer of this is basic, abc.", secrets)).toBe(false);
    expect(secretsOf(NONE)).toStrictEqual([]);
  });

  it("is passed on with each credential taken out, the whole value before a word of it", () => {
    expect(
      withoutSecrets(
        "401: the header Authorization: Bearer sk-live-0123456789abcdef is not valid, nor is sk-live-0123456789abcdef alone",
        secrets,
      ),
    ).toBe(`401: the header Authorization: ${WITHHELD} is not valid, nor is ${WITHHELD} alone`);
    expect(withoutSecrets("Nothing of them here.", secrets)).toBe("Nothing of them here.");
    expect(withoutSecrets("Anything at all.", [])).toBe("Anything at all.");
  });

  it("is found in a result wherever it stands: in a string, in a member's name, as a number", () => {
    const key = "sk-live-0123456789abcdef";
    for (const value of [
      key,
      { content: [{ type: "text", text: `Your key is ${key}.` }] },
      { [key]: true },
      [[[{ deep: [key] }]]],
      // A string with a quotation mark in it is another text once it is written as JSON.
      { text: `"${credentials.query.api_key}"` },
    ]) {
      expect(repeatsSecret(value, secrets), JSON.stringify(value)).toBe(true);
    }
    // A key that is all digits may come back as a number.
    expect(
      repeatsSecret(
        { account: 1234567890123 },
        secretsOf({ ...NONE, env: { PIN: "1234567890123" } }),
      ),
    ).toBe(true);
    for (const value of [null, 7, "Habari.", { content: [{ type: "text", text: "Habari." }] }]) {
      expect(repeatsSecret(value, secrets), JSON.stringify(value)).toBe(false);
    }
    // With no credentials there is nothing to find, and what has no text is not carried.
    expect(repeatsSecret({ text: key }, [])).toBe(false);
    const circle: Record<string, unknown> = {};
    circle["self"] = circle;
    expect(repeatsSecret(circle, secrets)).toBe(false);
  });
});
