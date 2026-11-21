// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** A Data Integrity proof with the `eddsa-jcs-2022` cryptosuite (core Section 5). */

import { type Static, Type } from "typebox";

import { meta } from "./naming.ts";
import { patterns, Timestamp } from "./primitives.ts";

/** core 5.6. */
export const PROOF_PURPOSES = [
  "capabilityInvocation",
  "capabilityDelegation",
  "authentication",
  "assertionMethod",
] as const;
export type ProofPurpose = (typeof PROOF_PURPOSES)[number];

/**
 * One entry of a proof's `authority`: a `record-ref`, or an inline
 * `Delegation` or `Collective` record (core 5.2). The proof schema checks only
 * that an entry is a string or an object. What an entry refers to or contains
 * is judged when the chain or the charter is evaluated (Layer 1, 11.4;
 * Layer 2, 7.1): a proof whose `authority` does not hold up still counts for
 * its signer's own mind, so it must not stop being a proof.
 */
export type AuthorityItem = string | Readonly<Record<string, unknown>>;

/**
 * core 5.2: a proof has exactly these members. The schema is closed, unlike a
 * record's, because a proof with any other member never counts.
 */
export const Proof = Type.Object(
  {
    type: Type.Literal("DataIntegrityProof"),
    cryptosuite: Type.Literal("eddsa-jcs-2022"),
    verificationMethod: Type.Union([
      Type.String({ pattern: patterns.keyRef }),
      Type.String({ pattern: patterns.controlKeyRef }),
    ]),
    proofPurpose: Type.Unsafe<ProofPurpose>({ enum: [...PROOF_PURPOSES] }),
    created: Timestamp,
    proofValue: Type.String({ pattern: patterns.proofValue }),
    challenge: Type.Optional(Type.String()),
    domain: Type.Optional(Type.String()),
    authority: Type.Optional(
      Type.Unsafe<AuthorityItem[]>({
        description:
          "Exactly one delegation chain, root first (Layer 1, 11.6), or exactly one charter (Layer 2, 7.1). Entries are record-refs or inline records; their content is judged when the chain or charter is evaluated.",
        type: "array",
        minItems: 1,
        maxItems: 8,
        items: { type: ["string", "object"] },
      }),
    ),
    "@context": Type.Optional(Type.Unknown()),
  },
  {
    ...meta("Proof", "One proof of a record's proof set (core 5.2)."),
    additionalProperties: false,
    // 5.2: `challenge` and `domain` appear only in authentication proofs.
    dependentSchemas: {
      challenge: { properties: { proofPurpose: { const: "authentication" } } },
      domain: { properties: { proofPurpose: { const: "authentication" } } },
    },
  },
);
export type Proof = Static<typeof Proof>;
