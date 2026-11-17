// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import {
  type CaseKind,
  claimMustHold,
  type ConformanceAdapter,
  loadVectors,
  namedLog,
  namedRecord,
  parseVectors,
  positiveRecords,
  referenceAdapter,
  runCase,
  runVectors,
  tally,
  type VectorCase,
  viewFor,
} from "../src/index.ts";

const vectors = loadVectors();
const first = (kind: CaseKind, section: "valid" | "negative" | "controls" = "negative") => {
  const found = vectors[section].find((entry) => entry.kind === kind);
  if (found === undefined) throw new Error(`no ${kind} case in ${section}`);
  return found;
};

/** An adapter that answers every question the same way. */
const always = (answer: boolean, status = "open"): ConformanceAdapter => ({
  name: `always ${String(answer)}`,
  recordIsWellFormed: () => answer,
  logVerifies: () => answer,
  countsFor: () => answer,
  sentFor: () => answer,
  status: () => status,
  assurance: () => status,
  canonicalize: () => "",
});

describe("what a case requires", () => {
  it("requires must-accept cases and controls to hold, and negative cases not to", () => {
    for (const kind of ["log", "countsFor", "sentFor", "record"] as const) {
      expect(claimMustHold("valid", kind)).toBe(true);
      expect(claimMustHold("controls", kind)).toBe(true);
      expect(claimMustHold("negative", kind)).toBe(false);
    }
  });

  it("requires a negative status or assurance case to give the value it expects", () => {
    expect(claimMustHold("negative", "status")).toBe(true);
    expect(claimMustHold("negative", "assurance")).toBe(true);
  });
});

describe("running a case", () => {
  it("reports pending, never pass, when the adapter lacks the method", () => {
    const none: ConformanceAdapter = { name: "nothing yet" };
    for (const section of ["valid", "negative", "controls"] as const) {
      for (const vectorCase of vectors[section]) {
        expect(runCase(none, vectors, section, vectorCase).outcome).toBe("pending");
      }
    }
    expect(tally(runVectors(none, vectors))).toMatchObject({ pass: 0, fail: 0 });
  });

  it("fails an implementation that accepts everything on every negative case", () => {
    const accepting = always(true, "not a real status");
    for (const vectorCase of vectors.negative) {
      const result = runCase(accepting, vectors, "negative", vectorCase);
      expect(result.outcome, vectorCase.name).toBe("fail");
      expect(result.detail).toContain(vectorCase.reason);
    }
    for (const section of ["valid", "controls"] as const) {
      for (const vectorCase of vectors[section]) {
        expect(runCase(accepting, vectors, section, vectorCase).outcome).toBe("pass");
      }
    }
  });

  it("fails an implementation that rejects everything on every must-accept case and control", () => {
    const rejecting = always(false, "not a real status");
    for (const section of ["valid", "controls"] as const) {
      for (const vectorCase of vectors[section]) {
        const result = runCase(rejecting, vectors, section, vectorCase);
        expect(result.outcome, vectorCase.name).toBe("fail");
        expect(result.detail).toMatch(/must be accepted/);
      }
    }
  });

  it("counts an adapter that throws as the claim not holding", () => {
    const throwing: ConformanceAdapter = {
      name: "throws",
      logVerifies: () => {
        throw new Error("crash");
      },
    };
    expect(runCase(throwing, vectors, "valid", first("log", "valid")).outcome).toBe("fail");
    expect(runCase(throwing, vectors, "negative", first("log")).outcome).toBe("pass");
  });

  it("compares status and assurance with the expected value", () => {
    const status = first("status") as Extract<VectorCase, { kind: "status" }>;
    expect(runCase(always(true, status.expect), vectors, "negative", status).outcome).toBe("pass");
    expect(runCase(always(true, "open-ish"), vectors, "negative", status).outcome).toBe("fail");
    const assurance = first("assurance") as Extract<VectorCase, { kind: "assurance" }>;
    expect(runCase(always(true, assurance.expect), vectors, "negative", assurance).outcome).toBe(
      "pass",
    );
    expect(runCase(always(true, "bridged"), vectors, "negative", assurance).outcome).toBe("fail");
  });

  it("gives the adapter the baseline and what the case adds", () => {
    const withExtras = vectors.negative.find(
      (entry) => entry.extraLogs !== undefined && entry.seen !== undefined,
    );
    if (withExtras === undefined) throw new Error("no case with extraLogs and seen");
    const view = viewFor(vectors, withExtras);
    expect(view.logs).toHaveLength(vectors.baseline.logs.length);
    expect(view.records).toHaveLength(vectors.baseline.records.length);
    expect(view.logs[0]).toBe(namedLog(vectors, vectors.baseline.logs[0] ?? ""));
    expect(view.extraLogs).toBe(withExtras.extraLogs);
    expect(view.seen).toBe(withExtras.seen);
    const plain = viewFor(vectors, first("record"));
    expect(plain).toMatchObject({ extraLogs: [], branches: [], extraRecords: [] });
    expect(plain.seen).toBeUndefined();
  });
});

describe("the positive checks", () => {
  it("pass the reference implementation where it is built and are pending elsewhere", () => {
    const results = runVectors(referenceAdapter, vectors).filter(
      (result) => result.section === "positive",
    );
    expect(results.filter((result) => result.outcome === "fail")).toEqual([]);
    expect(results.find((result) => result.name.includes("well formed"))?.outcome).toBe("pass");
    expect(results.find((result) => result.name === "JCS example")?.outcome).toBe("pending");
  });

  it("fail an implementation that rejects a positive record or canonicalises wrongly", () => {
    const results = runVectors(always(false), vectors).filter(
      (result) => result.section === "positive" && result.outcome === "fail",
    );
    expect(results.map((result) => result.name)).toEqual([
      "every record in the positive vectors is well formed",
      "JCS example",
    ]);
    expect(results[0]?.detail).toContain("amina_log[0] was rejected");
  });

  it("report a check that throws as a failure", () => {
    const throwing: ConformanceAdapter = {
      name: "throws",
      canonicalize: () => {
        throw new Error("no JCS here");
      },
    };
    const result = runVectors(throwing, vectors).find((entry) => entry.name === "JCS example");
    expect(result).toMatchObject({ outcome: "fail", detail: "threw no JCS here" });
  });
});

describe("reading the vectors", () => {
  const raw = () => structuredClone(vectors) as unknown as Record<string, unknown>;

  it("finds named records and logs, and every positive record", () => {
    expect(namedRecord(vectors, "intent")["type"]).toBe("Intent");
    expect(namedLog(vectors, "amina_log")).toHaveLength(2);
    expect(() => namedRecord(vectors, "amina_log")).toThrow(/not a record/);
    expect(() => namedLog(vectors, "intent")).toThrow(/not a log/);
    expect(() => namedRecord(vectors, "missing")).toThrow(/not a record/);
    expect(positiveRecords(vectors).length).toBeGreaterThan(40);
  });

  it("rejects a file that is not the shape the suite relies on", () => {
    expect(() => parseVectors(null)).toThrow(/not an object/);
    for (const member of [
      "spec_revision",
      "cases",
      "keys",
      "baseline",
      "valid",
      "negative",
      "controls",
    ]) {
      const broken = raw();
      delete broken[member];
      expect(() => parseVectors(broken), member).toThrow(/vectors\.json/);
    }
  });

  it("rejects a baseline that names something the file does not contain", () => {
    const broken = raw();
    broken["baseline"] = { logs: ["amina_log", "nobody_log"], records: [] };
    expect(() => parseVectors(broken)).toThrow(/nobody_log/);
  });

  it("rejects a case with no name, an unknown kind, a missing member or a repeated name", () => {
    const withCase = (
      change: (first: Record<string, unknown>, list: Record<string, unknown>[]) => void,
    ) => {
      const broken = raw();
      const list = broken["negative"] as Record<string, unknown>[];
      const [first] = list;
      if (first === undefined) throw new Error("the vectors have no negative cases");
      change(first, list);
      return () => parseVectors(broken);
    };
    expect(withCase((first) => delete first["name"])).toThrow(/no name/);
    expect(withCase((first) => (first["kind"] = "vibes"))).toThrow(/unknown kind/);
    expect(withCase((first) => delete first["log"])).toThrow(/has no log/);
    expect(withCase((first, list) => list.push({ ...first }))).toThrow(/appears twice/);
    expect(
      withCase((_first, list) => list.push("a string" as unknown as Record<string, unknown>)),
    ).toThrow(/not an object/);
  });
});
