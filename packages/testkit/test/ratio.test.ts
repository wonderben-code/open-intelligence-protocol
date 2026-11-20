// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

import { describeMeasured, middle, ratiosOver } from "../src/ratio.ts";

/**
 * A machine whose clock is moved by the work it does, at a speed that the
 * weather sets: `slowness` says how many times longer work takes at a time.
 */
function machine(slowness: (time: number) => number = () => 1) {
  let time = 0;
  const calls = new Map<string, number>();
  return {
    now: () => time,
    calls,
    /** Work that costs `cost` milliseconds on a machine that does nothing else. */
    work: (name: string, cost: number) => () => {
      calls.set(name, (calls.get(name) ?? 0) + 1);
      time += cost * slowness(time);
    },
  };
}

describe("a ratio measured turn about", () => {
  it("is the cost of each piece of work over the cost of the reference", async () => {
    const { now, work } = machine();
    const measured = await ratiosOver(
      work("reference", 2),
      { heavy: work("heavy", 5), light: work("light", 0.5) },
      { now },
    );
    expect(measured.ratios.heavy).toBeCloseTo(2.5, 9);
    expect(measured.ratios.light).toBeCloseTo(0.25, 9);
    expect(measured.reference).toBeCloseTo(2, 9);
    expect(measured.latencies).toMatchObject({ heavy: 5, light: 0.5 });
    expect(measured.fastest).toMatchObject({ heavy: 5, light: 0.5 });
    // Two seconds of turns of 7.5 ms each.
    expect(measured.turns).toBe(Math.ceil(2000 / 7.5));
  });

  it("does not move with the weather: a machine that slows for a while slows both sides of a turn", async () => {
    // Every other 40 ms the machine takes 1.7 times as long, as a shared one does.
    const { now, work } = machine((time) => (Math.floor(time / 40) % 2 === 0 ? 1 : 1.7));
    const measured = await ratiosOver(
      work("reference", 2),
      { heavy: work("heavy", 5), light: work("light", 0.5) },
      { now },
    );
    expect(measured.ratios.heavy).toBeCloseTo(2.5, 9);
    expect(measured.ratios.light).toBeCloseTo(0.25, 9);
    // The fastest sample is of the machine at its best, which is what a ceiling is held to.
    expect(measured.fastest.heavy).toBeCloseTo(5, 9);
    // The times themselves did move: that is what a ratio of two of them, taken apart, inherits.
    const slow = machine((time) => (time < 1000 ? 1 : 1.7));
    const apart = await ratiosOver(slow.work("reference", 2), {}, { now: slow.now, budgetMs: 900 });
    const later = await ratiosOver(slow.work("heavy", 5), {}, { now: slow.now, budgetMs: 900 });
    expect(later.reference / apart.reference).toBeCloseTo(2.5 * 1.7, 9);
  });

  it("runs fast work several times for one sample, and still gives the cost of one run", async () => {
    const { now, work, calls } = machine();
    const measured = await ratiosOver(
      work("reference", 2),
      { fast: work("fast", 0.001) },
      { now, maxTurns: 20, warmupMs: 1 },
    );
    expect(measured.ratios.fast).toBeCloseTo(0.0005, 9);
    expect(measured.latencies.fast).toBeCloseTo(0.001, 9);
    expect(measured.turns).toBe(20);
    // 250 runs make a sample of a quarter of a millisecond.
    expect(calls.get("fast")).toBeGreaterThanOrEqual(20 * 250);
    expect(calls.get("reference")).toBeLessThan(20 + 10);
  });

  it("awaits work that returns a promise, and times the wait", async () => {
    const { now, work } = machine();
    const slow = work("awaited", 4);
    const measured = await ratiosOver(
      work("reference", 2),
      { awaited: () => Promise.resolve().then(slow) },
      { now, maxTurns: 10 },
    );
    expect(measured.ratios.awaited).toBeCloseTo(2, 9);
  });

  it("takes its least turns however long one is, and its most however short", async () => {
    const long = machine();
    const few = await ratiosOver(
      long.work("reference", 300),
      { work: long.work("work", 600) },
      { now: long.now, budgetMs: 100, minTurns: 5 },
    );
    expect(few.turns).toBe(5);
    expect(few.ratios.work).toBeCloseTo(2, 9);
    const short = machine();
    const many = await ratiosOver(
      short.work("reference", 0.5),
      { work: short.work("work", 0.5) },
      { now: short.now, budgetMs: 1_000_000, maxTurns: 7, minTurns: 0 },
    );
    expect(many.turns).toBe(7);
  });

  it("ends when the clock does not move", async () => {
    let runs = 0;
    const measured = await ratiosOver(
      () => {
        runs++;
      },
      {},
      { now: () => 0, maxTurns: 3, minTurns: 1 },
    );
    expect(measured.turns).toBe(3);
    expect(runs).toBeGreaterThan(3);
    expect(measured.reference).toBe(0);
  });

  it("the middle of an odd number of values is one of them, and of an even number half-way between two", () => {
    expect(middle([5, 1, 3])).toBe(3);
    expect(middle([4, 1, 3, 2])).toBe(2.5);
    expect(middle([7])).toBe(7);
    expect(middle([])).toBeNaN();
  });

  it("is told in lines for a log", async () => {
    const { now, work } = machine();
    const measured = await ratiosOver(
      work("reference", 2),
      { heavy: work("heavy", 5) },
      { now, maxTurns: 4, minTurns: 4 },
    );
    expect(describeMeasured("core", "one signature", measured)).toBe(
      [
        "core (4 turns, turn about)",
        "  one signature: 2.0000 ms",
        "  heavy: 5.0000 ms, 2.500 of the reference",
      ].join("\n"),
    );
  });
});
