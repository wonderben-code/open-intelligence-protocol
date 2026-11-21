// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { OipError } from "@oip/core";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  ConfigError,
  FetchRefused,
  HttpFailure,
  Log,
  StorageError,
  Unavailable,
} from "../src/index.ts";

/** 18 November 2026, 12:00:00 UTC. */
const NOON = 1_795_003_200_000_000_000n;
const SECRET = "5f1d3b7a9c2e4f60";

function logging(level?: "debug" | "info" | "warn" | "error") {
  const lines: string[] = [];
  const log = new Log({
    service: "resolver",
    clock: { now: () => NOON },
    sink: (line) => lines.push(line),
    ...(level === undefined ? {} : { level }),
  });
  const read = (): Record<string, unknown>[] =>
    lines.map((line) => JSON.parse(line) as Record<string, unknown>);
  return { log, lines, read };
}

describe("a line of a service's log", () => {
  it("is one line of JSON: the time, the level, the service, the event and its fields", () => {
    const { log, lines } = logging();
    log.event("info", "request", { method: "GET", status: 200, ms: 1.5, cached: false, at: NOON });
    expect(lines).toStrictEqual([
      '{"time":"2026-11-18T12:00:00Z","level":"info","service":"resolver","event":"request","method":"GET","status":200,"ms":1.5,"cached":false,"at":"1795003200000000000"}',
    ]);
  });

  it("stays one line whatever a field holds, and cuts a text that is long", () => {
    const { log, lines, read } = logging();
    log.event("warn", "odd\nname", {
      text: 'a "quoted"\nline\u2028break\u2029and\u0085more',
      long: "x".repeat(300),
    });
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toMatch(/[\n\r\u0085\u2028\u2029]/u);
    const [line] = read();
    expect(line?.["event"]).toBe("odd\nname");
    expect(line?.["text"]).toBe('a "quoted"\nline\u2028break\u2029and\u0085more');
    expect(line?.["long"]).toBe(`${"x".repeat(256)}… (300 characters)`);
  });

  it("has no field that is not a plain value, and none that takes a name of its own", () => {
    const { log, read } = logging();
    log.event("info", "request", {
      record: { seed: SECRET } as never,
      list: [SECRET] as never,
      missing: undefined,
      nothing: null as never,
      fn: (() => SECRET) as never,
      ratio: Number.NaN,
      time: "then",
      level: "debug",
      service: "other",
      event: "other",
      "bad name": "x",
      Upper: "x",
      __proto__: "x",
      ok: true,
    });
    expect(read()).toStrictEqual([
      {
        time: "2026-11-18T12:00:00Z",
        level: "info",
        service: "resolver",
        event: "request",
        record: "(not a plain value)",
        list: "(not a plain value)",
        nothing: "(not a plain value)",
        fn: "(not a plain value)",
        ratio: "NaN",
        ok: true,
      },
    ]);
  });

  it("is written from its level up", () => {
    const { log, read } = logging("warn");
    for (const level of ["debug", "info", "warn", "error"] as const) log.event(level, level);
    expect(read().map((line) => line["event"])).toStrictEqual(["warn", "error"]);
    const all = logging("debug");
    for (const level of ["debug", "info"] as const) all.log.event(level, level);
    expect(all.read()).toHaveLength(2);
    // `info` where nothing is said.
    const usual = logging();
    for (const level of ["debug", "info"] as const) usual.log.event(level, level);
    expect(usual.read().map((line) => line["event"])).toStrictEqual(["info"]);
  });

  it("is never anything but one line of JSON, whatever text its fields hold", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary" }), fc.string({ unit: "binary" }), (name, value) => {
        const { log, lines } = logging();
        log.event("info", name, { value });
        expect(lines).toHaveLength(1);
        expect(lines[0]).not.toMatch(/[\n\r\u0085\u2028\u2029]/u);
        expect((JSON.parse(lines[0] ?? "") as { event: string }).event).toBe(name);
      }),
    );
  });
});

describe("a failure in a service's log", () => {
  it("says the message of an error of ours, its code, and where it was thrown", () => {
    const { log, read } = logging();
    log.failure("request failed", new OipError("invalid-proof", "no proof verifies"), {
      route: "/inbox",
    });
    const [line] = read();
    expect(line).toMatchObject({
      level: "error",
      event: "request failed",
      route: "/inbox",
      error: "OipError",
      code: "invalid-proof",
      message: "no proof verifies",
    });
    expect(String(line?.["at"])).toMatch(/log\.test\.ts:\d+:\d+/u);
    expect(String(line?.["at"])).not.toContain("no proof verifies");
    for (const ours of [
      new StorageError("the database is older than its data"),
      new HttpFailure(415, "Unsupported Media Type"),
      new Unavailable("cut short"),
      new FetchRefused("address", "the host is at an address that is not fetched from"),
      new ConfigError(["OIP_X is not set"]),
    ]) {
      const next = logging();
      next.log.failure("failed", ours);
      expect(next.read()[0]?.["message"]).toBe(ours.message);
    }
  });

  it("withholds the message of any other error: what a library says is not known", () => {
    const { log, lines, read } = logging();
    // As a library that puts the value it choked on into its message.
    const foreign = new TypeError(`invalid private key: ${SECRET}`);
    log.failure("signing failed", foreign);
    const sqlite = Object.assign(new Error(`constraint failed: ${SECRET}`), {
      code: "ERR_SQLITE_ERROR",
      errcode: 1811,
    });
    log.failure("store failed", sqlite);
    expect(read()).toMatchObject([
      { error: "TypeError", message: "(withheld: not an error of ours)" },
      {
        error: "Error",
        code: "ERR_SQLITE_ERROR",
        errcode: 1811,
        message: "(withheld: not an error of ours)",
      },
    ]);
    expect(lines.join("\n")).not.toContain(SECRET);
    // Where it was thrown is still said.
    expect(String(read()[0]?.["at"])).toMatch(/log\.test\.ts/u);
  });

  it("says nothing of a cause, of a field of the error, or of a stack that is no text", () => {
    const { log, lines, read } = logging();
    const error = new OipError("forbidden", "not permitted", { cause: new Error(SECRET) });
    Object.assign(error, { seed: SECRET, code: { secret: SECRET } });
    Object.defineProperty(error, "stack", { value: { secret: SECRET } });
    log.failure("failed", error);
    expect(lines.join("\n")).not.toContain(SECRET);
    expect(read()[0]).not.toHaveProperty("at");
    expect(read()[0]).not.toHaveProperty("code");
    // Nor does a stack that fails to be read stop the line from being written.
    const sly = new StorageError("sly");
    Object.defineProperty(sly, "stack", {
      get: () => {
        throw new Error(SECRET);
      },
    });
    log.failure("failed", sly);
    expect(read()[1]).toMatchObject({ error: "StorageError", message: "sly" });
    expect(read()[1]).not.toHaveProperty("at");
    expect(lines.join("\n")).not.toContain(SECRET);
  });

  it("says what kind of thing was thrown, where it was no error", () => {
    for (const [thrown, kind] of [
      [SECRET, "(string thrown)"],
      [{ seed: SECRET }, "(object thrown)"],
      [null, "(null thrown)"],
      [undefined, "(undefined thrown)"],
      [7, "(number thrown)"],
    ] as const) {
      const { log, lines, read } = logging();
      log.failure("failed", thrown);
      expect(read()[0]?.["error"]).toBe(kind);
      expect(lines.join("\n")).not.toContain(SECRET);
    }
  });

  it("logs no more places of a stack than a line can bear", () => {
    const { log, read } = logging();
    const deep = new StorageError("deep");
    deep.stack = [
      "StorageError: deep",
      ...Array.from({ length: 20 }, (_, n) => `    at f${n} (file.ts:${n}:1)`),
    ].join("\n");
    log.failure("failed", deep);
    expect(String(read()[0]?.["at"]).split(" < ")).toStrictEqual(
      Array.from({ length: 8 }, (_, n) => `f${n} (file.ts:${n}:1)`),
    );
  });
});
