// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause, sampleRecords } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  isNamespace,
  parseRecord,
  understandsCritical,
  unsupportedCritical,
} from "../src/index.ts";
import { named, show } from "./vectors.ts";

const intent = named("intent");

describe(`${clause("core 8.1")} namespaces`, () => {
  it("accepts the three forms", () => {
    for (const namespace of [
      "com.example.escrow",
      "example.com",
      "a.b",
      "org.w3-c.vc",
      "9.9",
      "x402",
      "ap2",
      "acp",
      "l402",
      "vc",
      "as2",
      "oip.sealed-v2",
      "oip.",
      "oip.anything at all",
    ]) {
      expect(isNamespace(namespace), namespace).toBe(true);
    }
  });

  it("rejects everything else", () => {
    for (const bad of [
      "",
      "escrow",
      "com",
      "Com.Example",
      "com.example.Escrow",
      "com..example",
      ".com.example",
      "com.example.",
      "com_example.escrow",
      "com.example/escrow",
      "com.example escrow",
      "x403",
      "X402",
      "vc2",
      "oip",
      "OIP.x",
      "oipx",
      " x402",
      null,
      undefined,
      1,
      ["x402"],
      // Values that read as a namespace when turned into a string.
      ["com.example"],
      ["oip.profile"],
      { toString: () => "com.example.escrow" },
      new String("x402"),
    ]) {
      expect(isNamespace(bad), show(bad)).toBe(false);
    }
  });
});

describe(`${clause("core 8.3")} critical extensions`, () => {
  const record = (critical?: unknown, ext?: unknown) => ({
    ...intent,
    ...(ext === undefined ? {} : { ext }),
    ...(critical === undefined ? {} : { critical }),
  });

  it("lets a reader act on a record with no critical extension", () => {
    expect(unsupportedCritical(intent)).toEqual([]);
    expect(understandsCritical(intent)).toBe(true);
    expect(unsupportedCritical(record([]))).toEqual([]);
    expect(understandsCritical(record([]), ["x402"])).toBe(true);
    // An extension that is not critical never stops a reader (core 8.4).
    expect(understandsCritical(record(undefined, { "com.example.escrow": { v: 1 } }))).toBe(true);
  });

  it("names the critical namespaces the reader does not understand", () => {
    const critical = record(["com.example.escrow", "x402", "oip.future"]);
    expect(unsupportedCritical(critical)).toEqual(["com.example.escrow", "x402", "oip.future"]);
    expect(unsupportedCritical(critical, ["x402"])).toEqual(["com.example.escrow", "oip.future"]);
    expect(unsupportedCritical(critical, new Set(["oip.future", "com.example.escrow"]))).toEqual([
      "x402",
    ]);
    expect(
      unsupportedCritical(critical, ["com.example.escrow", "x402", "oip.future", "other"]),
    ).toEqual([]);
    expect(understandsCritical(critical)).toBe(false);
    expect(understandsCritical(critical, ["x402", "com.example.escrow"])).toBe(false);
    expect(understandsCritical(critical, ["x402", "com.example.escrow", "oip.future"])).toBe(true);
  });

  it("names a repeated namespace once", () => {
    expect(unsupportedCritical(record(["x402", "x402", "ap2", "x402"]))).toEqual(["x402", "ap2"]);
  });

  it("matches namespaces exactly", () => {
    expect(understandsCritical(record(["com.example.escrow"]), ["com.example"])).toBe(false);
    expect(understandsCritical(record(["com.example"]), ["com.example.escrow"])).toBe(false);
    expect(understandsCritical(record(["X402"]), ["x402"])).toBe(false);
  });

  it("does not let a malformed critical pass as understood", () => {
    for (const bad of ["x402", { x402: true }, null, 1, true]) {
      expect(unsupportedCritical(record(bad), ["x402"]), show(bad)).toEqual(["critical"]);
      expect(understandsCritical(record(bad), ["x402"]), show(bad)).toBe(false);
    }
    expect(unsupportedCritical(record(["x402", 1, null, "ap2"]), ["x402"])).toEqual([
      "critical",
      "ap2",
    ]);
    expect(understandsCritical(record([["x402"]]), ["x402"])).toBe(false);
  });

  it("reads a record it cannot read as naming something nobody understands", () => {
    const hostile = new Proxy(
      {},
      {
        get: () => {
          throw new Error("no");
        },
      },
    );
    expect(unsupportedCritical(hostile)).toEqual(["critical"]);
    expect(unsupportedCritical(hostile, ["critical"])).toEqual(["critical"]);
    expect(understandsCritical(hostile)).toBe(false);
    // The same when it is the list that cannot be read.
    const list = new Proxy(["com.example"], {
      get: () => {
        throw new Error("no");
      },
    });
    expect(unsupportedCritical({ critical: list })).toEqual(["critical"]);
    expect(understandsCritical({ critical: list }, ["com.example"])).toBe(false);
    const revoked = Proxy.revocable([], {});
    revoked.revoke();
    expect(unsupportedCritical({ critical: revoked.proxy })).toEqual(["critical"]);
  });

  it("requires every critical namespace to have an extension block", () => {
    const sample = sampleRecords["Intent"] ?? {};
    const text = (critical: unknown, ext: unknown) => JSON.stringify({ ...sample, critical, ext });
    expect(parseRecord(text(["x402"], { x402: { v: 1 } })).ok).toBe(true);
    const missing = parseRecord(text(["x402", "ap2"], { x402: {} }));
    expect(!missing.ok && missing.issues[0]).toMatchObject({
      path: "/critical/1",
      clause: "core 8.3",
    });
    const none = parseRecord(JSON.stringify({ ...sample, critical: ["x402"] }));
    expect(!none.ok && none.issues[0].clause).toBe("core 8.3");
  });
});

describe(`${clause("core 8.4")} extensions that are not critical`, () => {
  it("do not change whether a record is well formed or whether a reader may act on it", () => {
    const sample = sampleRecords["Intent"] ?? {};
    const extended = {
      ...sample,
      ext: { "com.example.unknown": { anything: [1, { deep: null }] }, vc: {} },
    };
    expect(parseRecord(JSON.stringify(extended)).ok).toBe(true);
    expect(understandsCritical(extended)).toBe(true);
    expect(unsupportedCritical(extended, [])).toEqual([]);
  });
});
