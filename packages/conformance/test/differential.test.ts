// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Differential testing against the independent Python checker. It needs
 * Python 3 with the `cryptography` package. Without them the suite is
 * skipped, unless OIP_REQUIRE_PYTHON is set (as it is in CI), in which case
 * it fails.
 *
 * It covers `record` cases and `json` cases.
 *
 * - `record`: the Python checker's structural checks are a subset of the
 *   schemas, by design, so the rule is "no laxer": whatever the schemas
 *   accept, the checker accepts.
 * - `json` (M1): whether a text is JSON within the profile of core Section 1.
 *   Both implementations decide that completely, so the rule is "same". The
 *   reference implementation also has a limit of its own on the length of a
 *   text, which the checker has not; the texts compared here are far below it.
 *
 * M2 extends it to identity logs, with the rule "same".
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { canonicalBytes } from "@oip/core";
import { sampleRecords } from "@oip/testkit";
import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  compareVerdicts,
  type JsonCase,
  type JsonObject,
  loadVectors,
  positiveRecords,
  PythonJudge,
  pythonJudgeUnavailable,
  type RecordCase,
  referenceAdapter,
  SECTIONS,
  VECTORS_DIRECTORY,
} from "../src/index.ts";

const unavailable = pythonJudgeUnavailable();
const required = process.env["OIP_REQUIRE_PYTHON"] !== undefined;
// Each PR runs a short campaign; the nightly job sets OIP_DIFFERENTIAL_RUNS higher.
const RUNS = Number(process.env["OIP_DIFFERENTIAL_RUNS"] ?? 2000);
// About 1.5 ms a case on a laptop; ten times that, so a slow runner does not fail the campaign.
const TIMEOUT = Math.max(120_000, RUNS * 15);

const vectors = loadVectors();
// Every record of the positive vectors, and a sample of each of the 29
// record types, so that the types the vectors lack are compared too.
const records = [
  ...positiveRecords(vectors).map((entry) => entry.record),
  ...Object.values(sampleRecords),
  // The well-formed records among the cases: a type an extension defines, the
  // containers at their deepest, a duration at its longest. Mutating these reaches
  // rules that no other record here has anything to break.
  ...[...vectors.valid, ...vectors.controls].flatMap((entry) =>
    entry.kind === "record" ? [entry.record as JsonObject] : [],
  ),
  {
    oip: "1",
    type: "com.example.Minimal",
    created: "2026-11-17T09:00:00Z",
    ext: { "com.example": {} },
    critical: ["com.example"],
  },
];

/** Values that tend to break a structural check. */
const junk = fc.oneof(
  fc.constantFrom<unknown>(null, true, 0, -1, 1.5, "", "short", [], {}, "1,000", "-5", "1e2"),
  fc.constantFrom(
    "2026-02-30T00:00:00Z",
    "2026-10-30T09:00:00Z",
    "2026-13-01T00:00:00Z",
    // Year 0000 is a year of RFC 3339, and a leap year (core 1.4).
    "0000-02-29T00:00:00Z",
    "0000-01-01T00:00:00.5Z",
  ),
  // Durations, at and beyond their longest (core 1.5), and what is not one.
  fc.constantFrom("P30D", "PT0S", "none", "P1Y", "P", `P${"9".repeat(62)}D`, `P${"9".repeat(63)}D`),
  fc.string({ maxLength: 80 }),
  fc.integer(),
);

/** Every path to a value inside a record, as lists of keys. */
function paths(value: unknown, prefix: (string | number)[] = [], out: (string | number)[][] = []) {
  if (prefix.length > 0) out.push(prefix);
  if (prefix.length >= 6 || typeof value !== "object" || value === null) return out;
  for (const [key, inner] of Object.entries(value)) {
    paths(inner, [...prefix, Array.isArray(value) ? Number(key) : key], out);
  }
  return out;
}

interface Mutation {
  path: (string | number)[];
  action: "delete" | "replace" | "copy";
  value: unknown;
  from: (string | number)[];
}

function apply(record: JsonObject, mutation: Mutation): JsonObject {
  const copy = structuredClone(record) as Record<string, unknown>;
  // Own members only. After an earlier mutation a path may run through an
  // array or a string, where a key such as "keys" would otherwise find a
  // method of the prototype.
  const read = (path: (string | number)[]): unknown =>
    path.reduce<unknown>(
      (at, key) =>
        typeof at === "object" && at !== null && Object.hasOwn(at, key)
          ? (at as Record<string | number, unknown>)[key]
          : undefined,
      copy,
    );
  const parent = read(mutation.path.slice(0, -1)) as Record<string | number, unknown> | undefined;
  const key = mutation.path.at(-1);
  // An earlier mutation may have replaced the parent with something that has no members.
  if (typeof parent !== "object" || parent === null || key === undefined) return copy;
  if (mutation.action === "delete") {
    if (Array.isArray(parent)) parent.splice(Number(key), 1);
    else delete parent[key];
  } else {
    // "copy" sets one member to the value of another, which is how a
    // delegation to oneself or a payer that is also the payee arises.
    parent[key] =
      mutation.action === "copy" ? structuredClone(read(mutation.from)) : mutation.value;
  }
  return copy;
}

const mutatedRecord = fc.constantFrom(...records).chain((record) => {
  const all = paths(record);
  const path = fc.constantFrom(...all);
  const mutation = fc.record({
    path,
    action: fc.constantFrom("delete", "replace", "replace", "copy"),
    value: junk,
    from: path,
  }) as fc.Arbitrary<Mutation>;
  return fc
    .array(mutation, { minLength: 1, maxLength: 3 })
    .map((mutations) => mutations.reduce(apply, record));
});

/** Pieces of JSON text, well formed and not, that the two parsers must judge alike. */
const fragment = fc.oneof(
  { weight: 6, arbitrary: fc.json({ maxDepth: 4 }) },
  {
    weight: 3,
    arbitrary: fc.constantFrom(
      "1.0",
      "1e2",
      "100e-2",
      "-0",
      "0.0e-7",
      "9007199254740991",
      "9007199254740991.0",
      "9007199254740992",
      "-9007199254740992",
      "1.5",
      "1e-1",
      "1e16",
      "1e400",
      "0e99999999999999999999",
      "1e-99999999999999999999",
      "1e99999999999999999999",
      // Numbers written at length: more digits than a platform will turn into a number.
      `1${"0".repeat(5000)}e-5000`,
      `1${"0".repeat(5000)}e-4999`,
      `1${"0".repeat(5000)}e-5001`,
      `0.${"0".repeat(5000)}`,
      `0.${"0".repeat(5000)}1e5001`,
      `0.${"0".repeat(5000)}1e5000`,
      "9".repeat(5000),
      `-${"0.".padEnd(4400, "0")}`,
      `9007199254740991${"0".repeat(4400)}e-4400`,
      `9007199254740992${"0".repeat(4400)}e-4400`,
      "01",
      "+1",
      ".5",
      "1.",
      "NaN",
      "Infinity",
      "-Infinity",
      '"\\ud800"',
      '"\\ud83d\\ude00"',
      '"\\udc00\\ud800"',
      // Noncharacters, escaped and as themselves, and their neighbours.
      '"\\ufffe"',
      '"\\uFFFF"',
      '"\\ufdd0"',
      '"\\ufdef"',
      '"\\ufdcf\\ufdf0\\ufffd"',
      '"\\ud83f\\udffe"',
      '"\\udbff\\udfff"',
      '"\\udbff\\udffd"',
      '"\ufffe"',
      '"\u{1ffff}"',
      '{"\ufdd0":1}',
      '"\ufffd"',
      // Half a surrogate pair as itself, beside an escape that would complete it.
      '"\ud83d\\ude00"',
      '"\\ud83d\ude00"',
      '"\ud800"',
      '"\\x41"',
      '"tab\tinside"',
      '{"a":1,"a":1}',
      '{"a":1,"\\u0061":2}',
      '{"a":{"a":1},"b":{"a":1}}',
      '{"__proto__":1}',
      "[1,]",
      "{,}",
      "\ufeff1",
      "// comment",
      "'single'",
      "",
      " ",
    ),
  },
  { weight: 1, arbitrary: fc.string({ unit: "binary", maxLength: 20 }) },
  {
    weight: 1,
    arbitrary: fc
      .string({
        unit: fc.constantFrom(...'[]{}:,"\\ 0123456789.eE-+truefalsn'.split("")),
        maxLength: 30,
      })
      .map((text) => text),
  },
);

/** A JSON-like text: a fragment, sometimes wrapped, nested or joined to another. */
const jsonText = fc
  .tuple(
    fragment,
    fragment,
    fc.constantFrom("plain", "array", "member", "deep63", "deep64", "pair"),
  )
  .map(([one, other, shape]) => {
    switch (shape) {
      case "array":
        return `[${one}, ${other}]`;
      case "member":
        return `{"a": ${one}, "b": ${other}}`;
      case "deep63":
        return `${"[".repeat(63)}${one}${"]".repeat(63)}`;
      case "deep64":
        return `${"[".repeat(64)}${one}${"]".repeat(64)}`;
      case "pair":
        return `${one}${other}`;
      default:
        return one;
    }
  });

describe.skipIf(unavailable !== undefined && !required)("differential: the JSON profile", () => {
  let judge: PythonJudge;

  beforeAll(() => {
    if (unavailable !== undefined) throw new Error(`OIP_REQUIRE_PYTHON is set, but ${unavailable}`);
    judge = new PythonJudge();
  });

  afterAll(async () => {
    await judge.close();
  });

  const jsonCase = (text: string): JsonCase => ({ name: "generated", kind: "json", text });

  it("agrees with the Python checker on every json case of the vectors", async () => {
    let compared = 0;
    for (const section of SECTIONS) {
      for (const vectorCase of vectors[section]) {
        if (vectorCase.kind !== "json") continue;
        const theirs = await judge.judge(vectorCase);
        expect(theirs.holds, vectorCase.name).toBe(section !== "negative");
        expect(referenceAdapter.jsonIsWithinProfile?.(vectorCase.text), vectorCase.name).toBe(
          theirs.holds,
        );
        compared++;
      }
    }
    expect(compared).toBe(21);
  });

  it("agrees with it on what neither is required to reject: duplicate member names", async () => {
    // core 1.1 says receivers SHOULD reject these. Both implementations do.
    for (const text of ['{"a":1,"a":1}', '{"a":1,"\\u0061":2}', '[{"x":null,"x":null}]']) {
      expect((await judge.judge(jsonCase(text))).holds, text).toBe(false);
      expect(referenceAdapter.jsonIsWithinProfile?.(text), text).toBe(false);
    }
  });

  it(
    `gives the same verdict as the Python checker on ${RUNS} generated texts`,
    async () => {
      let accepted = 0;
      let rejected = 0;
      await fc.assert(
        fc.asyncProperty(jsonText, async (text) => {
          const disagreement = await compareVerdicts(
            referenceAdapter,
            judge,
            vectors,
            jsonCase(text),
            "same",
          );
          expect(disagreement, JSON.stringify(text)).toBeUndefined();
          if (referenceAdapter.jsonIsWithinProfile?.(text) === true) accepted++;
          else rejected++;
        }),
        { numRuns: RUNS },
      );
      // Both answers must be exercised for the comparison to mean anything.
      expect(accepted).toBeGreaterThan(RUNS / 10);
      expect(rejected).toBeGreaterThan(RUNS / 10);
    },
    TIMEOUT,
  );
});

describe.skipIf(unavailable !== undefined && !required)("differential: record cases", () => {
  let judge: PythonJudge;

  beforeAll(() => {
    if (unavailable !== undefined) throw new Error(`OIP_REQUIRE_PYTHON is set, but ${unavailable}`);
    judge = new PythonJudge();
  });

  afterAll(async () => {
    await judge.close();
  });

  const recordCase = (record: unknown, name = "generated"): RecordCase => ({
    name,
    kind: "record",
    record,
  });

  it("covers every record type, and types that extensions define", () => {
    const types = new Set(records.map((record) => record["type"]));
    // The 29 of this revision, and two that extensions define.
    expect(types.size).toBe(31);
    expect(records.filter((record) => Array.isArray(record["critical"])).length).toBe(4);
  });

  it("agree on the size limit, to the byte, for a record, a carried record and a container's own part", async () => {
    // core 1.6: 1 MiB of canonical form for each record a container carries, and
    // for the container without the members that hold them.
    const LIMIT = 1024 * 1024;
    const sizeOf = (value: unknown) => canonicalBytes(value).length;
    const padded = (base: JsonObject, measured: (record: JsonObject) => number, size: number) => {
      const withPadding = (blob: string): JsonObject => ({
        ...base,
        ext: { "com.example.padding": { blob } },
      });
      const record = withPadding("a".repeat(size - measured(withPadding(""))));
      expect(measured(record)).toBe(size);
      return record;
    };
    const intent = sampleRecords["Intent"] as JsonObject;
    const page = sampleRecords["LogPage"] as JsonObject;
    const event = (page["events"] as JsonObject[])[0]!;
    const withoutEvents = (record: JsonObject) => {
      const { events: _events, ...rest } = record;
      return sizeOf(rest);
    };
    const cases: [what: string, record: JsonObject, wellFormed: boolean][] = [];
    for (const [size, wellFormed] of [
      [LIMIT, true],
      [LIMIT + 1, false],
    ] as const) {
      cases.push(
        ["a record", padded(intent, sizeOf, size), wellFormed],
        ["a carried record", { ...page, events: [padded(event, sizeOf, size)] }, wellFormed],
        ["a container's own part", padded(page, withoutEvents, size), wellFormed],
      );
    }
    for (const [what, record, wellFormed] of cases) {
      const ours = referenceAdapter.recordIsWellFormed?.(record);
      const theirs = (await judge.judge(recordCase(record))).holds;
      expect([ours, theirs], `${what}, ${wellFormed ? "at" : "over"} the limit`).toEqual([
        wellFormed,
        wellFormed,
      ]);
    }
    // The two limits are separate: a page that is 2 MiB as a whole is well formed.
    const both = { ...padded(page, withoutEvents, LIMIT), events: [padded(event, sizeOf, LIMIT)] };
    expect(sizeOf(both)).toBeGreaterThan(2 * LIMIT);
    expect(referenceAdapter.recordIsWellFormed?.(both)).toBe(true);
    expect((await judge.judge(recordCase(both))).holds).toBe(true);
  });

  it("both accept every record of the positive vectors and every sample", async () => {
    for (const record of records) {
      expect(referenceAdapter.recordIsWellFormed?.(record)).toBe(true);
      expect((await judge.judge(recordCase(record))).holds).toBe(true);
    }
  });

  it("agree on every case in the vectors that the implementation can judge", async () => {
    let compared = 0;
    for (const section of SECTIONS) {
      for (const vectorCase of vectors[section]) {
        if (vectorCase.kind !== "record" && vectorCase.kind !== "json") continue;
        expect(await compareVerdicts(referenceAdapter, judge, vectors, vectorCase)).toBeUndefined();
        compared++;
      }
    }
    // 31 record cases and 21 json cases, over the three sections.
    expect(compared).toBe(31 + 21);
  });

  it(
    `the schemas accept nothing the Python checker rejects (${RUNS} mutated records)`,
    async () => {
      let accepted = 0;
      await fc.assert(
        fc.asyncProperty(mutatedRecord, async (record) => {
          const disagreement = await compareVerdicts(
            referenceAdapter,
            judge,
            vectors,
            recordCase(record),
            "no-laxer",
          );
          if (referenceAdapter.recordIsWellFormed?.(record) === true) accepted++;
          expect(disagreement).toBeUndefined();
        }),
        { numRuns: RUNS },
      );
      // The mutations must not be so harsh that nothing survives to be compared.
      expect(accepted).toBeGreaterThan(0);
    },
    TIMEOUT,
  );

  it("reports a disagreement when the verdicts differ", async () => {
    const lax = { name: "lax", recordIsWellFormed: () => true };
    const bad = vectors.negative.find((entry) => entry.kind === "record");
    if (bad === undefined) throw new Error("no record case");
    expect(await compareVerdicts(lax, judge, vectors, bad)).toMatchObject({
      implementation: true,
      judge: false,
    });
    expect(await compareVerdicts(lax, judge, vectors, bad, "no-laxer")).toBeDefined();
    const strict = { name: "strict", recordIsWellFormed: () => false };
    expect(await compareVerdicts(strict, judge, vectors, bad, "no-laxer")).toBeUndefined();
    expect(await compareVerdicts({ name: "none" }, judge, vectors, bad)).toBeUndefined();
  });

  it("gets an error verdict, not a crash, for input the checker cannot process", async () => {
    const verdict = await judge.judge({ kind: "telepathy", name: "odd" });
    expect(verdict).toMatchObject({ holds: false, name: "odd" });
    expect(verdict.error).toMatch(/unknown case kind/);
    expect((await judge.judge("not a case")).holds).toBe(false);
  });

  it("keeps answers matched to questions when a name holds a line separator", async () => {
    // U+2028 and U+2029 are line breaks to many line readers, and JSON does not escape them.
    const names = ["has\u2028sep", "g1", "has\u2029sep", "b1", "caf\u00e9 \ud83d\ude00"];
    const cases = names.map((name, i) =>
      i % 2 === 1 ? recordCase(records[0], name) : recordCase({ oip: "2" }, name),
    );
    const verdicts = await Promise.all(cases.map((entry) => judge.judge(entry)));
    expect(verdicts.map((verdict) => verdict.name)).toEqual(names);
    expect(verdicts.map((verdict) => verdict.holds)).toEqual([false, true, false, true, false]);
  });

  it("rejects a deeply nested record and carries on", async () => {
    let deep: unknown = "leaf";
    for (let i = 0; i < 1500; i++) deep = [deep];
    const verdict = await judge.judge({ name: "deep", kind: "record", record: deep });
    expect(verdict.holds).toBe(false);
    expect((await judge.judge(recordCase(records[0], "after"))).holds).toBe(true);
  });

  it("gets an error verdict, not a dead checker, for a line nested too deeply to parse", () => {
    // Written as text: JSON.stringify cannot produce nesting this deep.
    const deepLine = `${"[".repeat(200_000)}${"]".repeat(200_000)}`;
    const goodLine = JSON.stringify(recordCase(records[0], "after"));
    const run = spawnSync(
      "python3",
      [join(VECTORS_DIRECTORY, "oip_vectors.py"), "--judge", "--lines"],
      { input: `${deepLine}\n${goodLine}\n`, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
    );
    expect(run.status).toBe(0);
    const verdicts = run.stdout
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as { holds: boolean; error?: string; name: unknown });
    expect(verdicts).toHaveLength(2);
    expect(verdicts[0]).toMatchObject({ holds: false });
    expect(verdicts[0]?.error).toMatch(/not JSON/);
    expect(verdicts[1]).toMatchObject({ holds: true, name: "after" });
  });

  it("stays in step after a case too deep for one side or the other", async () => {
    // Whether JSON.stringify can write nesting this deep depends on the
    // runtime. If it cannot, nothing is sent and the promise rejects. If it
    // can, the checker cannot parse the line and says so. Either way the
    // next answer belongs to the next question.
    let deep: unknown = "leaf";
    for (let i = 0; i < 200_000; i++) deep = [deep];
    const outcome = await judge.judge({ name: "deep", kind: "record", record: deep }).then(
      (verdict) => verdict,
      (error: unknown) => error,
    );
    if (outcome instanceof Error) {
      expect(outcome.message).toMatch(/cannot be written as JSON/);
    } else {
      expect(outcome).toMatchObject({ holds: false, name: null });
      expect((outcome as { error?: string }).error).toMatch(/not JSON/);
    }
    expect((await judge.judge(recordCase(records[0], "still in step"))).name).toBe("still in step");
  });

  it("rejects, without sending anything, a case that JSON cannot represent", async () => {
    await expect(judge.judge({ name: "big", kind: "record", record: 10n })).rejects.toThrow(
      /cannot be written as JSON/,
    );
    await expect(judge.judge(undefined)).rejects.toThrow(/cannot be written as JSON/);
    expect((await judge.judge(recordCase(records[0], "still in step"))).name).toBe("still in step");
  });

  it("propagates an exception from the implementation instead of reading it as a verdict", async () => {
    const crashing = {
      name: "crashes",
      recordIsWellFormed: () => {
        throw new Error("crash");
      },
    };
    await expect(compareVerdicts(crashing, judge, vectors, recordCase(records[0]))).rejects.toThrow(
      "crash",
    );
  });

  it("answers in the order asked", async () => {
    const good = recordCase(records[0], "good");
    const bad = recordCase({ oip: "2" }, "bad");
    const verdicts = await Promise.all(
      [good, bad, good, bad, bad].map((entry) => judge.judge(entry)),
    );
    expect(verdicts.map((verdict) => verdict.name)).toEqual(["good", "bad", "good", "bad", "bad"]);
    expect(verdicts.map((verdict) => verdict.holds)).toEqual([true, false, true, false, false]);
  });
});

describe.skipIf(unavailable !== undefined && !required)("the Python judge process", () => {
  it("rejects pending and later questions when the checker cannot start", async () => {
    const broken = new PythonJudge({ script: "/nonexistent/oip_vectors.py" });
    await expect(broken.judge({ kind: "record", record: {} })).rejects.toThrow(/exited with code/);
    await expect(broken.judge({ kind: "record", record: {} })).rejects.toThrow(/exited with code/);
    await broken.close();
  });

  it("reports a missing interpreter", async () => {
    expect(pythonJudgeUnavailable({ python: "/nonexistent/python3" })).toMatch(/not installed/);
    const broken = new PythonJudge({ python: "/nonexistent/python3" });
    await expect(broken.judge({})).rejects.toThrow(/could not start|exited/);
    await broken.close();
  });

  it("stops trusting a checker whose answers do not match the questions", async () => {
    // A stand-in for the checker that answers every case with the wrong name.
    const directory = mkdtempSync(join(tmpdir(), "oip-judge-"));
    const script = join(directory, "wrong.mjs");
    writeFileSync(
      script,
      'process.stdin.on("data", (chunk) => { for (const line of String(chunk).split("\\n")) ' +
        'if (line) console.log(JSON.stringify({ name: "someone else", kind: "record", holds: true })); });',
    );
    const judge = new PythonJudge({ python: process.execPath, script });
    try {
      await expect(judge.judge({ name: "mine", kind: "record", record: {} })).rejects.toThrow(
        /answered "someone else" when asked about "mine"/,
      );
      await expect(judge.judge({ name: "next", kind: "record", record: {} })).rejects.toThrow(
        /answered "someone else"/,
      );
    } finally {
      await judge.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("closes cleanly, and close can be called twice", async () => {
    const judge = new PythonJudge();
    expect((await judge.judge({ kind: "record", record: { oip: "1" } })).holds).toBe(false);
    await judge.close();
    await judge.close();
    await expect(judge.judge({})).rejects.toThrow(/exited with code 0/);
  });
});
