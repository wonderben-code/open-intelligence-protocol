// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { clause, repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  errorFrom,
  MEDIA_TYPE,
  OipError,
  PROBLEM_CODES,
  PROBLEM_MEDIA_TYPE,
  problemCode,
  problemDetails,
  PROBLEMS,
  problemType,
  parseRecord,
} from "../src/index.ts";

/** The table of core 10.2, read from the specification itself. */
function specificationTable(): { code: string; status: number; meaning: string }[] {
  const text = readFileSync(join(repoRoot, "spec", "core.md"), "utf8");
  const section = text.slice(text.indexOf("\n10.2. "), text.indexOf("\n## 11. "));
  return [...section.matchAll(/^\| `([a-z-]+)` \| ([0-9]{3}) \| (.+) \|$/gm)].map((row) => ({
    code: row[1] ?? "",
    status: Number(row[2]),
    meaning: row[3] ?? "",
  }));
}

describe(`${clause("core 10.1")} the media type`, () => {
  it("is application/oip+json", () => {
    expect(MEDIA_TYPE).toBe("application/oip+json");
    expect(PROBLEM_MEDIA_TYPE).toBe("application/problem+json");
  });
});

describe(`${clause("core 10.2")} problem types`, () => {
  it("has every code of the specification's table, with its status and meaning, in its order", () => {
    const table = specificationTable();
    expect(table).toHaveLength(11);
    expect(PROBLEM_CODES).toEqual(table.map((row) => row.code));
    for (const row of table) {
      const problem = PROBLEMS[row.code as keyof typeof PROBLEMS];
      expect(problem, row.code).toEqual({ status: row.status, title: row.meaning });
    }
  });

  it("names a problem urn:oip:error:<code>, and reads the code back", () => {
    expect(problemType("invalid-record")).toBe("urn:oip:error:invalid-record");
    for (const code of PROBLEM_CODES) {
      expect(problemType(code)).toBe(`urn:oip:error:${code}`);
      expect(problemCode(problemType(code))).toBe(code);
    }
    for (const bad of [
      "invalid-record",
      "urn:oip:error:",
      "urn:oip:error:unknown",
      "urn:oip:error:Invalid-Record",
      "urn:oip:error:invalid-record ",
      " urn:oip:error:invalid-record",
      "URN:OIP:ERROR:invalid-record",
      "urn:oip:errors:invalid-record",
      "urn:oip:error:toString",
      "urn:oip:error:constructor",
      "urn:oip:error:__proto__",
      "about:blank",
      "",
      null,
      undefined,
      400,
      ["urn:oip:error:expired"],
    ]) {
      expect(problemCode(bad), String(bad)).toBeUndefined();
    }
  });

  it("builds RFC 9457 problem details", () => {
    expect(problemDetails("not-found")).toEqual({
      type: "urn:oip:error:not-found",
      title: "Unknown mind or record",
      status: 404,
    });
    expect(problemDetails("too-large", "the canonical form is 2000000 bytes")).toEqual({
      type: "urn:oip:error:too-large",
      title: "The record exceeds a size limit",
      status: 413,
      detail: "the canonical form is 2000000 bytes",
    });
    const issues = [{ path: "/created", message: "not a timestamp", clause: "core 1.4" }];
    expect(problemDetails("invalid-record", "detail", issues)).toEqual({
      type: "urn:oip:error:invalid-record",
      title: "Not a well-formed record of the expected type",
      status: 400,
      detail: "detail",
      issues,
    });
    expect(Object.hasOwn(problemDetails("expired", undefined, []), "issues")).toBe(false);
    expect(Object.hasOwn(problemDetails("expired", undefined, []), "detail")).toBe(false);
    expect(problemDetails("expired", "")).toMatchObject({ detail: "" });
    expect(JSON.parse(JSON.stringify(problemDetails("rate-limited")))).toEqual({
      type: "urn:oip:error:rate-limited",
      title: "Too many requests",
      status: 429,
    });
  });
});

describe("OipError", () => {
  it("carries a code, a detail for a person, and the clause it enforces", () => {
    const error = new OipError("forbidden", "the delegation does not cover /oip/send", {
      clause: "L1 11.2",
    });
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(OipError);
    expect(error.name).toBe("OipError");
    expect(error.message).toBe("the delegation does not cover /oip/send");
    expect(error.detail).toBe(error.message);
    expect(error.code).toBe("forbidden");
    expect(error.clause).toBe("L1 11.2");
    expect(error.issues).toEqual([]);
    expect(error.cause).toBeUndefined();
    expect(Object.hasOwn(error, "cause")).toBe(false);
    expect(String(error)).toBe("OipError: the delegation does not cover /oip/send");
    expect(error.stack).toContain("errors.test.ts");
  });

  it("has no clause and no issues unless given them", () => {
    const error = new OipError("not-found", "no such mind");
    expect(error.clause).toBeUndefined();
    expect(error.issues).toEqual([]);
    expect(error.toProblem()).toEqual({
      type: "urn:oip:error:not-found",
      title: "Unknown mind or record",
      status: 404,
      detail: "no such mind",
    });
  });

  it("keeps its cause without repeating it", () => {
    const cause = new Error("the secret detail of a lower layer");
    const error = new OipError("stale-version", "the resolver could not be reached", { cause });
    expect(error.cause).toBe(cause);
    expect(error.detail).toBe("the resolver could not be reached");
    expect(JSON.stringify(error.toProblem())).not.toContain("secret");
    const falsy = new OipError("expired", "x", { cause: 0 });
    expect(falsy.cause).toBe(0);
  });

  it("is made from a rejection, with its first issue as the detail and all of them kept", () => {
    const rejection = parseRecord('{"oip":"1","type":"Intent","created":"yesterday"}');
    expect(rejection.ok).toBe(false);
    if (rejection.ok) return;
    const error = errorFrom(rejection);
    expect(error.code).toBe("invalid-record");
    expect(error.issues).toBe(rejection.issues);
    expect(error.clause).toBe(rejection.issues[0].clause);
    expect(error.detail).toContain(rejection.issues[0].message);

    const located = errorFrom({
      issues: [
        { path: "/terms/price/amount", message: "not an amount", clause: "core 1.3" },
        { path: "/created", message: "not a timestamp", clause: "core 1.4" },
      ],
    });
    expect(located.detail).toBe("/terms/price/amount: not an amount");
    expect(located.clause).toBe("core 1.3");
    expect(located.issues).toHaveLength(2);
    expect(error.toProblem().issues).toBe(rejection.issues);
    expect(error.toProblem().status).toBe(400);

    const whole = errorFrom(
      { issues: [{ path: "", message: "a record is a JSON object", clause: "core 1.1" }] },
      "invalid-proof",
    );
    expect(whole.detail).toBe("a record is a JSON object");
    expect(whole.code).toBe("invalid-proof");
    expect(whole.clause).toBe("core 1.1");
  });
});
