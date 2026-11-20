// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The first two budgets of BUILD.md 3.8 as a service meets them: with
 * OpenSSL doing the arithmetic of each signature (ADR-0016). The portable
 * library's own budgets for the same work are in `@oip/core` and
 * `@oip/identity` (ADR-0006).
 *
 * Each sample forgets the signatures that verified before it, so that it
 * times the checking of a signature and not the memory of one.
 */

import {
  decodeEd25519Multikey,
  forgetVerifiedSignatures,
  parseRecord,
  verifyEd25519,
  verifyProofs,
} from "@oip/core";
import { verifyLog } from "@oip/identity";
import { positiveVectorRecords } from "@oip/testkit";
import { KeyMind, LATER, witness } from "@oip/testkit/minds";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

import { usePortableEd25519 } from "../../core/src/ed25519.ts";
import { useNativeEd25519 } from "../src/index.ts";

export const BUDGETS = {
  /** Verify a record with two proofs, read from text: the median, in milliseconds. */
  recordWithTwoProofs: 2,
  /** Verify an identity log of 1,000 events, in milliseconds. */
  logOfAThousandEvents: 1000,
  /**
   * One signature by OpenSSL against the same by the portable library, as
   * a ratio: it measures at about 0.05. The order check of the key is
   * remembered for both.
   */
  overPortable: 0.2,
} as const;

const EVENTS = 1000;
const ROUNDS = 3;

const commitment = positiveVectorRecords().find(({ name }) => name === "commitment_accepted");
const commitmentText = JSON.stringify(commitment?.record);

/** The middle of an odd number of values. */
function middle(values: readonly number[]): number {
  const sorted = values.toSorted((a, b) => a - b);
  return sorted[(sorted.length - 1) / 2] ?? Number.NaN;
}

/** Verifies every proof of a record, read from text as a receiver reads it, as if for the first time. */
function receive(text: string): number {
  forgetVerifiedSignatures();
  const parsed = parseRecord(text);
  if (!parsed.ok) throw new Error("the record did not parse");
  const verdicts = verifyProofs(parsed.value);
  if (verdicts.issues.length > 0 || verdicts.rejected.length > 0) {
    throw new Error("a proof did not verify");
  }
  return verdicts.verified.length;
}

describe("the first two budgets of BUILD.md 3.8, in a service", () => {
  beforeAll(() => {
    usePortableEd25519();
    if (!useNativeEd25519()) throw new Error("OpenSSL is not in use");
  });
  afterAll(() => {
    usePortableEd25519();
    forgetVerifiedSignatures();
  });

  test("verify a record with two proofs, from text", async ({ bench }) => {
    expect(receive(commitmentText)).toBe(2);
    const result = await bench("parseRecord + verifyProofs: a Commitment with two proofs", () =>
      receive(commitmentText),
    ).run();
    expect(result.latency.p50).toBeLessThan(BUDGETS.recordWithTwoProofs);
  });

  test("verify an identity log of 1,000 events", async ({ bench }) => {
    const mind = new KeyMind("long-lived");
    for (let n = 1; n < EVENTS; n++) mind.update(n, { homes: [`https://home${n}.example`] });
    const evidence = witness([mind.events]);
    const check = verifyLog(mind.events, { evidence, asOf: LATER });
    expect(check.ok && check.value.entries).toHaveLength(EVENTS);
    const whole = await bench("verifyLog: 1,000 events", () => {
      forgetVerifiedSignatures();
      return verifyLog(mind.events, { evidence, asOf: LATER });
    })
      // A few runs say enough.
      .run({ iterations: 5, time: 0, warmupIterations: 1, warmupTime: 0 });
    expect(whole.latency.p50).toBeLessThan(BUDGETS.logOfAThousandEvents);
  });

  test("check a signature in a fraction of the portable library's time", async ({ bench }) => {
    // One signature, its message and its key.
    const key = new KeyMind("measured").operational();
    const message = new TextEncoder().encode(
      "a message of ordinary length, to be signed and verified",
    );
    const signature = key.sign(message);
    const publicKey = decodeEd25519Multikey(key.publicKey);
    if (!publicKey.ok) throw new Error("the key did not decode");
    const once = (): boolean => {
      forgetVerifiedSignatures();
      return verifyEd25519(signature, message, publicKey.value);
    };
    const ratios: number[] = [];
    for (let round = 1; round <= ROUNDS; round++) {
      usePortableEd25519();
      expect(once()).toBe(true);
      const portable = (
        await bench(`verifyEd25519: the portable library (round ${round})`, once).run()
      ).latency.p50;
      expect(useNativeEd25519()).toBe(true);
      expect(once()).toBe(true);
      const native = (await bench(`verifyEd25519: OpenSSL (round ${round})`, once).run()).latency
        .p50;
      ratios.push(native / portable);
    }
    expect(middle(ratios), "OpenSSL over the portable library").toBeLessThan(BUDGETS.overPortable);
  });
});
