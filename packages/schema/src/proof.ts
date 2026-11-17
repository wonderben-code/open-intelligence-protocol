// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** A Data Integrity proof with the `eddsa-jcs-2022` cryptosuite (core Section 5). */

import { type Static, Type } from "typebox";

import { meta, schemaId } from "./naming.ts";
import { patterns, Timestamp } from "./primitives.ts";
import type { Delegation } from "./records/delegation.ts";
import type { Collective } from "./records/web.ts";

/** core 5.6. */
export const PROOF_PURPOSES = [
  "capabilityInvocation",
  "capabilityDelegation",
  "authentication",
  "assertionMethod",
] as const;
export type ProofPurpose = (typeof PROOF_PURPOSES)[number];

/** A `record-ref` or an inline record: one link of a chain, or a charter (core 5.2). */
export type AuthorityItem = string | Delegation | Collective;

const recordRef = { type: "string", pattern: patterns.recordRef };

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
    challenge: Type.Optional(Type.String({ minLength: 1 })),
    domain: Type.Optional(Type.String({ minLength: 1 })),
    authority: Type.Optional(
      Type.Unsafe<AuthorityItem[]>({
        description:
          "Exactly one delegation chain, root first (Layer 1, 11.6), or exactly one charter (Layer 2, 7.1).",
        anyOf: [
          {
            type: "array",
            minItems: 1,
            maxItems: 8,
            items: { anyOf: [recordRef, { $ref: schemaId("Delegation") }] },
          },
          {
            type: "array",
            minItems: 1,
            maxItems: 1,
            items: { anyOf: [recordRef, { $ref: schemaId("Collective") }] },
          },
        ],
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
