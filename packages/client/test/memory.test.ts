// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { utf8 } from "@oip/core";
import { KeystoreError, memoryStorage } from "@oip/keystore";
import { describe, expect, it } from "vitest";

import { Memory } from "../src/memory.ts";

const ADA = "did:oip:bciqada";
const BOB = "did:oip:bciqbob";

/** The number a document holds, or `undefined` if it holds none. */
const count = (stored: Readonly<Record<string, unknown>>): number | undefined =>
  typeof stored["count"] === "number" ? stored["count"] : undefined;

/** The code a call is refused with. */
async function refusal(work: () => Promise<unknown>): Promise<string> {
  try {
    await work();
  } catch (error) {
    if (error instanceof KeystoreError) return error.code;
    throw error;
  }
  throw new Error("nothing was refused");
}

describe("what a client remembers", () => {
  it("is nothing at first, and then what was written, with the version a write of it names", async () => {
    const memory = new Memory(memoryStorage(), ADA);
    expect(await memory.get("client-test", count)).toStrictEqual({
      value: undefined,
      version: undefined,
    });
    const first = await memory.put("client-test", { count: 1 }, undefined);
    expect(await memory.get("client-test", count)).toStrictEqual({ value: 1, version: first });
    const second = await memory.put("client-test", { count: 2 }, first);
    expect(second).not.toBe(first);
    expect((await memory.get("client-test", count)).value).toBe(2);
  });

  it("is written in the place of the version that was read, or not at all", async () => {
    const storage = memoryStorage();
    const [one, other] = [new Memory(storage, ADA), new Memory(storage, ADA)];
    const first = await one.put("client-test", { count: 1 }, undefined);
    await other.put("client-test", { count: 2 }, first);
    // The first has not read what the other wrote.
    expect(await refusal(() => one.put("client-test", { count: 3 }, first))).toBe("changed");
    expect(await refusal(() => one.put("client-test", { count: 3 }, undefined))).toBe("changed");
    expect((await one.get("client-test", count)).value).toBe(2);
  });

  it("is forgotten if it is still the version that was read, and nothing is forgotten of nothing", async () => {
    const storage = memoryStorage();
    const memory = new Memory(storage, ADA);
    await memory.forget("client-test", undefined);
    const first = await memory.put("client-test", { count: 1 }, undefined);
    const second = await memory.put("client-test", { count: 2 }, first);
    expect(await refusal(() => memory.forget("client-test", first))).toBe("changed");
    await memory.forget("client-test", second);
    expect(await storage.list()).toStrictEqual([]);
  });

  it("is one mind's: another mind's memory is not read as this one's", async () => {
    const storage = memoryStorage();
    await new Memory(storage, ADA).put("client-test", { count: 1 }, undefined);
    expect(await refusal(() => new Memory(storage, BOB).get("client-test", count))).toBe("damaged");
    // What says it is another's is not written so: the memory names its own mind.
    const version = await new Memory(storage, BOB).put(
      "client-other",
      { count: 5, mind: ADA },
      undefined,
    );
    expect(await new Memory(storage, BOB).get("client-other", count)).toStrictEqual({
      value: 5,
      version,
    });
  });

  it("is damaged where what is stored is not a document of it", async () => {
    for (const stored of ["{", "[1]", '"text"', "7", "null", `{"mind":"${ADA}","count":"one"}`]) {
      const storage = memoryStorage();
      await storage.put("client-test", utf8(stored), undefined);
      expect(await refusal(() => new Memory(storage, ADA).get("client-test", count)), stored).toBe(
        "damaged",
      );
    }
  });
});
