// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The results this package answers with, and the one judge here that waits (ADR-0010). */

import { cutShort, cutShortCount, noteCutShort } from "@oip/schema";
import { describe, expect, it } from "vitest";

import { judgingLater, no, ok, under } from "../src/result.ts";

/** A failure for want of room, as the engine throws it. */
const spent = (): RangeError => new RangeError("Maximum call stack size exceeded");

describe("a result", () => {
  it("is a value, or the reasons there is none, each with its place and its clause", () => {
    expect(ok(7)).toStrictEqual({ ok: true, value: 7 });
    expect(no("it is wrong", "L1 12.4")).toStrictEqual({
      ok: false,
      issues: [{ path: "", message: "it is wrong", clause: "L1 12.4" }],
    });
    expect(no("it is wrong", "L1 12.4", "/to").issues[0].path).toBe("/to");
  });

  it("keeps every reason of a rejection it is put under, each at its place there", () => {
    const inner = {
      ok: false as const,
      issues: [
        { path: "/to", message: "one", clause: "L1 12.4" },
        { path: "", message: "two", clause: "L1 12.1" },
        { path: "/proof/0", message: "three", clause: "core 5.5" },
      ] as [
        { path: string; message: string; clause: string },
        ...{ path: string; message: string; clause: string }[],
      ],
    };
    expect(under("/packet", inner).issues).toStrictEqual([
      { path: "/packet/to", message: "one", clause: "L1 12.4" },
      { path: "/packet", message: "two", clause: "L1 12.1" },
      { path: "/packet/proof/0", message: "three", clause: "core 5.5" },
    ]);
    // The rejection it was given is as it was.
    expect(inner.issues[0].path).toBe("/to");
  });
});

describe("a judgement that waits (ADR-0010)", () => {
  it("is the answer the work settles on, where no check was cut short meanwhile", async () => {
    expect(await judgingLater(() => Promise.resolve(ok("sealed")))).toStrictEqual(ok("sealed"));
    const refusal = no("no such key", "L1 12.6");
    expect(await judgingLater(() => Promise.resolve(refusal))).toBe(refusal);
  });

  it("is refused where a check was cut short while it waited, whatever it settled on", async () => {
    const before = cutShortCount();
    const answer = await judgingLater(async () => {
      await Promise.resolve();
      // Other work of the process, cut short in between.
      noteCutShort(spent());
      return ok("sealed");
    });
    expect(answer).toBe(cutShort());
    expect(cutShortCount()).toBe(before + 1);
    // Once: the next judgement is its own.
    expect(await judgingLater(() => Promise.resolve(ok("again")))).toStrictEqual(ok("again"));
  });

  it("is refused where the work itself ran out of room, and that is counted", async () => {
    const before = cutShortCount();
    expect(await judgingLater(() => Promise.reject(spent()))).toBe(cutShort());
    expect(
      await judgingLater(() => {
        throw spent();
      }),
    ).toBe(cutShort());
    expect(cutShortCount()).toBe(before + 2);
  });

  it("lets a failure that is no want of room through: it is the caller's to see", async () => {
    const before = cutShortCount();
    await expect(
      judgingLater(() => Promise.reject(new TypeError("a wrong argument"))),
    ).rejects.toThrow(TypeError);
    expect(cutShortCount()).toBe(before);
  });
});
