// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { EventEmitter } from "node:events";

import { describe, expect, it, vi } from "vitest";

import { every, healthResponse, Log, readyResponse, Shutdown } from "../src/index.ts";

function logging() {
  const lines: Record<string, unknown>[] = [];
  const log = new Log({
    service: "test",
    clock: { now: () => 0n },
    sink: (line) => lines.push(JSON.parse(line) as Record<string, unknown>),
    level: "debug",
  });
  const events = (): unknown[] => lines.map((line) => line["event"]);
  return { log, lines, events };
}

const later = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

describe("a service that is told to stop", () => {
  it("stops what it started, the last first, and waits for each", async () => {
    const { log, events, lines } = logging();
    const shutdown = new Shutdown({ log });
    const order: string[] = [];
    shutdown.add("database", () => {
      order.push("database");
    });
    shutdown.add("listener", async () => {
      await later(20);
      order.push("listener");
    });
    expect(shutdown.stopping).toBe(false);
    const done = shutdown.run("SIGTERM");
    expect(shutdown.stopping).toBe(true);
    expect(await done).toBe(true);
    expect(order).toStrictEqual(["listener", "database"]);
    expect(events()).toStrictEqual(["stopping", "stopped"]);
    expect(lines[0]).toMatchObject({ reason: "SIGTERM", steps: 2 });
    expect(lines[1]).toMatchObject({ clean: true });
  });

  it("stops once: told again, it is the same stopping", async () => {
    const { log } = logging();
    const shutdown = new Shutdown({ log });
    let stops = 0;
    shutdown.add("x", () => {
      stops++;
    });
    const first = shutdown.run("SIGTERM");
    expect(shutdown.run("SIGINT")).toBe(first);
    await first;
    await shutdown.run("again");
    expect(stops).toBe(1);
    expect(() => {
      shutdown.add("late", () => undefined);
    }).toThrow(TypeError);
  });

  it("goes on when a step fails, and says which", async () => {
    const { log, lines } = logging();
    const shutdown = new Shutdown({ log });
    const order: string[] = [];
    shutdown.add("database", () => {
      order.push("database");
    });
    shutdown.add("sync", () => {
      throw new TypeError("thrown at once");
    });
    shutdown.add("async", () => Promise.reject(new Error("rejected")));
    await shutdown.run("SIGTERM");
    expect(order).toStrictEqual(["database"]);
    expect(lines.filter((line) => line["event"] === "stop failed")).toMatchObject([
      { step: "async", error: "Error" },
      { step: "sync", error: "TypeError" },
    ]);
    expect(lines.at(-1)).toMatchObject({ event: "stopped", clean: true });
  });

  it("gives all the steps together a grace period, and still starts each when it has run out", async () => {
    const { log, lines } = logging();
    const shutdown = new Shutdown({ log, graceMs: 50 });
    const order: string[] = [];
    shutdown.add("database", () => {
      order.push("database");
    });
    shutdown.add("listener", () => new Promise(() => undefined));
    const before = Date.now();
    expect(await shutdown.run("SIGTERM")).toBe(false);
    expect(Date.now() - before).toBeLessThan(2000);
    // The database was closed, late, and not left open.
    expect(order).toStrictEqual(["database"]);
    expect(
      lines.filter((line) => line["event"] === "stopped late").map((line) => line["step"]),
    ).toStrictEqual(["listener", "database"]);
    expect(lines.at(-1)).toMatchObject({ event: "stopped", clean: false });
  });

  it("stops on the signal a process is stopped with, and ends the process", async () => {
    for (const signal of ["SIGTERM", "SIGINT"] as const) {
      const { log, lines } = logging();
      const shutdown = new Shutdown({ log });
      let stopped = false;
      shutdown.add("x", () => {
        stopped = true;
      });
      const signals = new EventEmitter();
      const exited = new Promise<number>((resolve) => {
        shutdown.listen(signals, resolve);
      });
      expect(stopped).toBe(false);
      signals.emit(signal);
      expect(await exited).toBe(0);
      expect(stopped).toBe(true);
      expect(lines[0]).toMatchObject({ event: "stopping", reason: signal });
    }
  });

  it("ends the process with 1 where the grace period ran out", async () => {
    const { log } = logging();
    const shutdown = new Shutdown({ log, graceMs: 30 });
    shutdown.add("stuck", () => new Promise(() => undefined));
    const signals = new EventEmitter();
    const exited = new Promise<number>((resolve) => {
      shutdown.listen(signals, resolve);
    });
    signals.emit("SIGTERM");
    expect(await exited).toBe(1);
  });

  it("takes a grace period that is a whole number of milliseconds", () => {
    const { log } = logging();
    for (const wrong of [-1, 1.5, Number.NaN]) {
      expect(() => new Shutdown({ log, graceMs: wrong })).toThrow(TypeError);
    }
  });
});

describe("whether a service is alive and ready", () => {
  it("is alive when it answers", async () => {
    const response = healthResponse();
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toStrictEqual({ status: "ok" });
  });

  it("is ready when every check holds and it is not stopping", async () => {
    const response = readyResponse({ database: () => true, keys: () => true }, false);
    expect(response.status).toBe(200);
    expect(await response.json()).toStrictEqual({ status: "ready" });
    expect(await readyResponse({}, false).json()).toStrictEqual({ status: "ready" });
  });

  it("is not ready, and says why, when a check fails or throws or it has begun to stop", async () => {
    const response = readyResponse(
      {
        database: () => false,
        keys: () => true,
        disk: () => {
          throw new Error("no");
        },
      },
      true,
    );
    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toStrictEqual({
      status: "not ready",
      failing: ["stopping", "database", "disk"],
    });
    expect(readyResponse({ database: () => true }, true).status).toBe(503);
  });
});

describe("something done again and again", () => {
  it("is done on a timer, and no more once it is stopped", () => {
    vi.useFakeTimers();
    try {
      let done = 0;
      const stop = every(() => done++, 1000);
      vi.advanceTimersByTime(999);
      expect(done).toBe(0);
      vi.advanceTimersByTime(2001);
      expect(done).toBe(3);
      stop();
      vi.advanceTimersByTime(10_000);
      expect(done).toBe(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not keep a process alive that has nothing else to do", () => {
    const unref = vi.fn();
    const set = vi
      .spyOn(globalThis, "setInterval")
      .mockReturnValue({ unref } as unknown as ReturnType<typeof setInterval>);
    every(() => undefined, 1000);
    set.mockRestore();
    expect(unref).toHaveBeenCalledOnce();
  });
});
