// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The adapter for this repository's implementation. It grows with each milestone. */

import {
  canonicalize,
  contentId,
  createProofSync,
  keyHash,
  type ProofOptions,
  signerFromPrivateKey,
  verifyProof,
} from "@oip/core";
import { validateRecord } from "@oip/schema";

import type { ConformanceAdapter } from "./adapter.ts";

/**
 * The reference implementation, as far as it is built. Kinds of case it does
 * not answer yet are reported as pending.
 */
export const referenceAdapter: ConformanceAdapter = {
  name: "OIP reference implementation (TypeScript)",
  recordIsWellFormed: (record) => validateRecord(record).ok,
  canonicalize,
  contentId,
  keyHash,
  createProof: (record, request, privateKey) =>
    createProofSync(record, request as ProofOptions, signerFromPrivateKey(privateKey)),
  proofVerifies: (record, proof) => verifyProof(record, proof).ok,
};
