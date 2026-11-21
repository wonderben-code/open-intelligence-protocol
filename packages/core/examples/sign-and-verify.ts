// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  contentId,
  createProof,
  formatControlKeyRef,
  keyHash,
  mindAddress,
  parseRecord,
  signerFromPrivateKey,
  verifyProofs,
  withProofs,
} from "@oip/core";

/**
 * Writes the first event of a mind's identity log, signs it, and reads it
 * back as a receiver does: from text, trusting nothing.
 */
export async function example(controlKey: Uint8Array, nextKey: Uint8Array): Promise<string[]> {
  const control = signerFromPrivateKey(controlKey);
  const next = signerFromPrivateKey(nextKey);
  const created = "2026-11-17T09:00:00Z";
  const genesis = {
    oip: "1",
    type: "Genesis",
    kind: "agent",
    created,
    // The next control key is committed to by its hash, and stays secret until it is used.
    controller: { keys: [control.publicKey], next: [keyHash(next.publicKey)], nextThreshold: 1 },
  };
  const proof = await createProof(
    genesis,
    { verificationMethod: formatControlKeyRef(control.publicKey), created },
    control,
  );
  const sent = JSON.stringify(withProofs(genesis, [proof]));

  // The receiver. Validate: is this text a well-formed record?
  const received = parseRecord(sent);
  if (!received.ok) {
    return received.issues.map((issue) => `${issue.clause} ${issue.path}: ${issue.message}`);
  }
  // Verify: which of its proofs are well formed, with a valid signature?
  const { verified, rejected } = verifyProofs(received.value);
  return [
    `a well-formed ${received.value.type}`,
    // A mind's address is the content ID of its first event.
    `address: ${mindAddress(contentId(received.value))}`,
    ...verified.map((proof) => `proof ${proof.index}: a valid signature by ${proof.key}`),
    ...rejected.map(
      (entry) => `proof ${entry.index}: ${entry.issues[0].clause} ${entry.issues[0].message}`,
    ),
  ];
}
