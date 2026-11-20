// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The first two performance budgets of BUILD.md 3.8, measured (ADR-0006):
 * verifying a record with two proofs, and the signatures of an identity log
 * of 1,000 events.
 *
 * Two kinds of limit are asserted. The ceilings in milliseconds depend on
 * the machine, so they are set with room. The ratios to the bare library do
 * not, so they are set close: a regression in this package's own code moves
 * a ratio whatever machine the run is on.
 *
 * The other cases show where the time goes.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { positiveVectorRecords } from "@oip/testkit";
import { describe, expect, test } from "vitest";

import {
  canonicalize,
  contentId,
  createProofSync,
  ed25519PublicKey,
  forgetVerifiedSignatures,
  hexToBytes,
  isEd25519PublicKey,
  parseJson,
  parseRecord,
  signerFromPrivateKey,
  verifyEd25519,
  verifyProofs,
} from "../src/index.ts";

/**
 * The budgets, in milliseconds, for this implementation on one core of the
 * reference machine. ADR-0006 says how they were set.
 *
 * A limit in milliseconds is compared with the fastest sample of a run, not
 * the median. On a shared machine other work only ever adds time, so the
 * fastest sample is the steadiest measure of what the code costs, and a
 * regression moves it as surely as it moves the median.
 *
 * A ratio is of two medians measured one after the other, taken in several
 * rounds, and the middle ratio is compared. Other work on the machine while
 * one side is measured moves that round's ratio, up or down. Where it touches
 * one round of the three, the middle ratio stays where it was. Where it
 * touches two the same way, the middle moves with them: the check can then
 * fail a good build or pass a bad one, and a second run tells.
 */
export const BUDGETS = {
  /** Verify a record with two proofs, read from text. */
  recordWithTwoProofs: 6,
  /** Verify the signatures of an identity log of 1,000 events. */
  logOfAThousandEvents: 3000,
  /**
   * `verifyEd25519` against the library's bare verification of the same
   * signature, as a ratio. core 4.4 adds one scalar multiplication to the
   * library's two, which measures at about 1.8. A second one would pass 2.5.
   */
  overLibrary: 2.0,
  /**
   * A record with two proofs, from text, against one bare verification:
   * two signatures at 1.8 each and the parsing, validation and hashing,
   * which measures at about 4.0.
   */
  recordOverLibrary: 4.6,
  /** One identity event with one proof, from text, likewise: about 2.0. */
  eventOverLibrary: 2.3,
  /** A signature that verified before, verified again: one hash, and no arithmetic on the curve. */
  verifiedBefore: 0.05,
} as const;

// A benchmark that reads an import on every call measures the module loader as well.
const checkKey = isEd25519PublicKey;
const verify = verifyEd25519;
const libraryVerify = ed25519.verify.bind(ed25519);

const records = positiveVectorRecords();
const pick = (name: string) => {
  const found = records.find((entry) => entry.name === name);
  if (found === undefined) throw new Error(`the vectors have no record called ${name}`);
  return found.record;
};

const commitment = pick("commitment_accepted");
const commitmentText = JSON.stringify(commitment);
const genesis = pick("amina_log[0]");
const genesisText = JSON.stringify(genesis);
const intent = pick("intent");

/**
 * Runs `run` with no signature remembered as verified. What is timed here is
 * the checking of a signature, and a signature that verified is remembered:
 * a benchmark that verifies the same one again and again would time the memory.
 */
function afresh<T>(run: () => T): () => T {
  return () => {
    forgetVerifiedSignatures();
    return run();
  };
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

const method = (intent["proof"] as { verificationMethod: string; created: string }[])[0];
const seed = hexToBytes("fa8f3711d5a2f523d3507b4857f3dfad2a037080b12ad1e93a2454a35b143aa8");
const publicKey = ed25519PublicKey(seed);
const message = new TextEncoder().encode("a message of ordinary length, to be signed and verified");
const signer = signerFromPrivateKey(seed);
const signature = signer.sign(message);
const selfMethod = `did:key:${signer.publicKey}#${signer.publicKey}`;
let fresh = 0;

/** How many times each ratio is measured. Odd, so that one of them is the middle. */
const ROUNDS = 3;

/** The middle of an odd number of values. */
function middle(values: readonly number[]): number {
  const sorted = values.toSorted((a, b) => a - b);
  return sorted[(sorted.length - 1) / 2] ?? Number.NaN;
}

describe("the budgets of BUILD.md 3.8", () => {
  test("verify a record with two proofs, from text", async ({ bench }) => {
    expect((commitment["proof"] as unknown[]).length).toBe(2);
    const result = await bench("parseRecord + verifyProofs: a Commitment with two proofs", () =>
      receive(commitmentText),
    ).run();
    expect(result.latency.min).toBeLessThan(BUDGETS.recordWithTwoProofs);
  });

  test("verify the signatures of an identity log of 1,000 events", async ({ bench }) => {
    // The cryptographic part of the second budget, which is linear in the number of
    // events: a thousand times one event. Replaying a log is measured with @oip/identity.
    const result = await bench("parseRecord + verifyProofs: one identity event", () =>
      receive(genesisText),
    ).run();
    expect(1000 * result.latency.min).toBeLessThan(BUDGETS.logOfAThousandEvents);
  });

  test("remember the order check of a public key", async ({ bench }) => {
    const result = await bench("isEd25519PublicKey: a key seen before", () =>
      checkKey(publicKey),
    ).run();
    // A scalar multiplication takes about a millisecond; a remembered answer takes microseconds.
    expect(result.latency.p50).toBeLessThan(0.05);
  });

  test("remember a signature that verified", async ({ bench }) => {
    expect(verify(signature, message, publicKey)).toBe(true);
    const result = await bench("verifyEd25519: a signature verified before", () =>
      verify(signature, message, publicKey),
    ).run();
    // Three scalar multiplications take about two milliseconds; a remembered answer is one hash.
    expect(result.latency.p50).toBeLessThan(BUDGETS.verifiedBefore);
  });

  test("stay close to the bare library: the regression check that does not depend on the machine", async ({
    bench,
  }) => {
    // core 4.4 adds one scalar multiplication, the order check of R, to the library's two.
    // The other two ratios are the two budgets: what this package adds to the signatures.
    const ratios = { overLibrary: [] as number[], record: [] as number[], event: [] as number[] };
    for (let round = 1; round <= ROUNDS; round++) {
      const measure = async (name: string, run: () => unknown): Promise<number> =>
        (await bench(`${name} (round ${round})`, run).run()).latency.p50;
      const bare = await measure("the library alone: one signature, strict mode", () =>
        libraryVerify(signature, message, publicKey, { zip215: false }),
      );
      ratios.overLibrary.push(
        (await measure(
          "verifyEd25519: one signature, public key seen before",
          afresh(() => verify(signature, message, publicKey)),
        )) / bare,
      );
      ratios.record.push(
        (await measure("parseRecord + verifyProofs: two proofs, for the ratio", () =>
          receive(commitmentText),
        )) / bare,
      );
      ratios.event.push(
        (await measure("parseRecord + verifyProofs: one event, for the ratio", () =>
          receive(genesisText),
        )) / bare,
      );
    }
    expect(middle(ratios.overLibrary)).toBeLessThan(BUDGETS.overLibrary);
    expect(middle(ratios.record)).toBeLessThan(BUDGETS.recordOverLibrary);
    expect(middle(ratios.event)).toBeLessThan(BUDGETS.eventOverLibrary);
  });
});

const parts: [name: string, run: () => unknown][] = [
  [
    "verifyProofs: a Commitment with two proofs, already parsed",
    afresh(() => verifyProofs(commitment)),
  ],
  [
    "verifyEd25519: one signature, public key seen before",
    afresh(() => verifyEd25519(signature, message, publicKey)),
  ],
  [
    "verifyEd25519: the same signature, verified before",
    () => verifyEd25519(signature, message, publicKey),
  ],
  [
    "isEd25519PublicKey: a key not seen before (the order check)",
    () =>
      isEd25519PublicKey(
        ed25519PublicKey(
          Uint8Array.from({ length: 32 }, (_, i) => (fresh++ >> (8 * (i % 4))) & 0xff),
        ),
      ),
  ],
  ["parseRecord: a Commitment with two proofs", () => parseRecord(commitmentText)],
  ["parseJson: a Commitment with two proofs", () => parseJson(commitmentText)],
  ["canonicalize: a Commitment with two proofs", () => canonicalize(commitment)],
  ["contentId: a Commitment with two proofs", () => contentId(commitment)],
  [
    "createProofSync: sign an Intent and verify the result",
    afresh(() =>
      createProofSync(
        intent,
        { verificationMethod: selfMethod, created: method?.created ?? "" },
        signer,
      ),
    ),
  ],
];

describe("where the time goes", () => {
  test.for(parts)("%s", async ([name, run], { bench }) => {
    await bench(name, run).run();
  });
});
