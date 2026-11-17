// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Differential testing against the independent Python checker. It needs
 * Python 3 with the `cryptography` package. Without them the suite is
 * skipped, unless OIP_REQUIRE_PYTHON is set (as it is in CI), in which case
 * it fails.
 *
 * At M0 it covers `record` cases. The Python checker's structural checks are
 * a subset of the schemas, so the rule is "no laxer": whatever the schemas
 * accept, the checker accepts. M2 extends it to logs with the rule "same".
 */

import fc from "fast-check";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  compareVerdicts,
  type JsonObject,
  loadVectors,
  positiveRecords,
  PythonJudge,
  pythonJudgeUnavailable,
  type RecordCase,
  referenceAdapter,
  SECTIONS,
} from "../src/index.ts";

const unavailable = pythonJudgeUnavailable();
const required = process.env["OIP_REQUIRE_PYTHON"] !== undefined;
// Each PR runs a short campaign; the nightly job sets OIP_DIFFERENTIAL_RUNS higher.
const RUNS = Number(process.env["OIP_DIFFERENTIAL_RUNS"] ?? 2000);

const vectors = loadVectors();
const records = positiveRecords(vectors).map((entry) => entry.record);

/** Values that tend to break a structural check. */
const junk = fc.oneof(
  fc.constantFrom<unknown>(null, true, 0, -1, 1.5, "", "short", [], {}, "1,000", "-5", "1e2"),
  // Year 0000 is left out: the Python checker rejects it, the specification
  // does not, and the question is queued for M1 (PROGRESS.md, spec feedback).
  fc.constantFrom("2026-02-30T00:00:00Z", "2026-10-30T09:00:00Z", "2026-13-01T00:00:00Z"),
  fc.string({ maxLength: 80 }),
  fc.integer(),
);

/** Every path to a value inside a record, as lists of keys. */
function paths(value: unknown, prefix: (string | number)[] = [], out: (string | number)[][] = []) {
  if (prefix.length > 0) out.push(prefix);
  if (prefix.length >= 4 || typeof value !== "object" || value === null) return out;
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

  it("both accept every record of the positive vectors", async () => {
    for (const record of records) {
      expect(referenceAdapter.recordIsWellFormed?.(record)).toBe(true);
      expect((await judge.judge(recordCase(record))).holds).toBe(true);
    }
  });

  it("agree on every case in the vectors that the implementation can judge", async () => {
    let compared = 0;
    for (const section of SECTIONS) {
      for (const vectorCase of vectors[section]) {
        if (vectorCase.kind !== "record") continue;
        expect(await compareVerdicts(referenceAdapter, judge, vectors, vectorCase)).toBeUndefined();
        compared++;
      }
    }
    expect(compared).toBe(2);
  });

  it(`the schemas accept nothing the Python checker rejects (${RUNS} mutated records)`, async () => {
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
  }, 120_000);

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

  it("closes cleanly, and close can be called twice", async () => {
    const judge = new PythonJudge();
    expect((await judge.judge({ kind: "record", record: { oip: "1" } })).holds).toBe(false);
    await judge.close();
    await judge.close();
    await expect(judge.judge({})).rejects.toThrow(/exited with code 0/);
  });
});
