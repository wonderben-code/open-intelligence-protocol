// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What the functions of this package that never throw answer with the call
 * stack all but spent. `spent-stack.test.ts` runs it in a process of its own
 * (`inNode` says why) and reads what it prints.
 */

import { tally, withStackSpent } from "@oip/testkit";

import {
  contentId,
  ed25519PublicKey,
  isEd25519PublicKey,
  parseExtensionRecord,
  parseRecord,
  recordRefMatches,
  signEd25519,
  unsupportedCritical,
  verifyEd25519,
  verifyProof,
  verifyProofs,
} from "../src/index.ts";
import { named } from "./vectors.ts";

const kindOf = (answer: unknown): string => (Array.isArray(answer) ? "array" : typeof answer);

/** core 4.4: a check cut short is not remembered as a no. */
function keys(): unknown[] {
  const text = new TextEncoder().encode("signed before the key was ever checked");
  return [77, 78, 79, 80].map((fill) => {
    const seed = new Uint8Array(32).fill(fill);
    const key = ed25519PublicKey(seed);
    const made = signEd25519(text, seed);
    // A key never checked before, by each of the two ways in.
    const spent =
      fill % 2 === 1
        ? withStackSpent(() => verifyEd25519(made, text, key))
        : withStackSpent(() => isEd25519PublicKey(key));
    return {
      answers: tally(spent, kindOf),
      // Whatever it could answer then, it answers rightly now.
      verifiesAfter: verifyEd25519(made, text, key),
      isKeyAfter: isEd25519PublicKey(key),
    };
  });
}

function proofs(): unknown {
  const intent = named("intent");
  const [proof] = intent["proof"] as [{ verificationMethod: string }];
  const signer = proof.verificationMethod.split("#")[1];
  const reference = `${intent["author"] as string}/${contentId(intent)}`;
  return {
    one: tally(
      withStackSpent(() => verifyProof(intent, proof as never)),
      (verdict) => {
        if (verdict.ok)
          return verdict.value.key === signer ? "accepted" : "accepted for another key";
        return verdict.issues[0].message.length > 0 ? "refused with a reason" : "refused";
      },
    ),
    all: tally(
      withStackSpent(() => verifyProofs(intent)),
      (verdicts) =>
        `${verdicts.verified.length} verified, ${verdicts.rejected.length} rejected, ${verdicts.issues.length} issues`,
    ),
    matches: tally(
      withStackSpent(() => recordRefMatches(reference, intent)),
      kindOf,
    ),
    after: [
      verifyProof(intent, proof).ok,
      verifyProofs(intent).verified.length,
      recordRefMatches(reference, intent),
    ],
  };
}

function records(): unknown {
  const record = named("intent");
  const text = JSON.stringify(record);
  const bytes = new TextEncoder().encode(text);
  // A record of a type that an extension defines, which the other reader is for.
  const note = JSON.stringify({
    oip: "1",
    type: "com.example.Note",
    created: "2026-11-17T09:00:00Z",
    ext: { "com.example": { text: "A note." } },
    critical: ["com.example"],
  });
  const read = (answer: { ok: boolean; issues?: readonly { message: string }[] }): string => {
    if (answer.ok) return "read";
    return (answer.issues?.[0]?.message.length ?? 0) > 0 ? "refused with a reason" : "refused";
  };
  return {
    text: tally(
      withStackSpent(() => parseRecord(text)),
      read,
    ),
    bytes: tally(
      withStackSpent(() => parseRecord(bytes)),
      read,
    ),
    extension: tally(
      withStackSpent(() => parseExtensionRecord(note)),
      read,
    ),
    critical: tally(
      withStackSpent(() => unsupportedCritical(record)),
      kindOf,
    ),
    after: parseRecord(text).ok && parseExtensionRecord(note).ok,
  };
}

process.stdout.write(JSON.stringify({ keys: keys(), proofs: proofs(), records: records() }));
