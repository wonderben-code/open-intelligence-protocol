// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The Layer 2 records: Intent, Offer, Commitment, Receipt and Collective. */

import { type Static, Type } from "typebox";

import { signedRecord } from "../common.ts";
import { define, meta, ref } from "../naming.ts";
import {
  Amount,
  Count,
  Ext,
  JsonObject,
  MindAddress,
  Namespaced,
  RecordRef,
  Sha256Digest,
  Strings,
  Timestamp,
  UnitDecimal,
} from "../primitives.ts";
import { Command, Policy } from "./delegation.ts";

/** Layer 1, 18.2. Every member is optional. */
export const CapabilityQuery = define(
  "capabilityQuery",
  Type.Object({
  want: Type.Optional(Type.String({ maxLength: 1024 })),
  tags: Type.Optional(Strings),
  kinds: Type.Optional(
    Type.Array(Type.Union([Type.Literal("Participant"), Type.Literal("Offer"), Type.Literal("Intent")])),
  ),
  constraints: Type.Optional(JsonObject),
  evidence: Type.Optional(JsonObject),
  limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })),
  }),
);
export type CapabilityQuery = Static<typeof CapabilityQuery>;

/** Layer 2, 9: an evidence item. `uri` and `hash` items carry the digest of the exact bytes. */
export const Evidence = define(
  "evidence",
  Type.Object(
  {
    kind: Type.Union([
      Type.Literal("oip"),
      Type.Literal("uri"),
      Type.Literal("hash"),
      Type.Literal("vc"),
      Type.Literal("payment"),
      Type.Literal("log"),
      Namespaced,
    ]),
    ref: Type.String({ minLength: 1 }),
    digest: Type.Optional(Sha256Digest),
    mediaType: Type.Optional(Type.String()),
    note: Type.Optional(Type.String()),
    ext: Type.Optional(Ext),
  },
  {
    if: { properties: { kind: { enum: ["uri", "hash"] } }, required: ["kind"] },
    then: { required: ["digest"] },
  },
  ),
);
export type Evidence = Static<typeof Evidence>;

/** Layer 2, Section 2: members any Layer 2 record may have. */
const layer2 = {
  ...signedRecord,
  author: MindAddress,
  supersedes: Type.Optional(RecordRef),
  status: Type.Optional(Type.String({ minLength: 1 })),
  links: Type.Optional(Type.Array(Type.Object({ rel: Type.String(), ref: Type.String() }))),
};

// Section 2: `status` appears only in a superseding record.
const statusNeedsSupersedes = { dependentRequired: { status: ["supersedes"] } };

/** Layer 2, 4.1: who a record is meant for. */
export const Audience = Type.Union([
  Type.Literal("public"),
  MindAddress,
  Type.Array(MindAddress),
  Type.Object({ query: CapabilityQuery }),
]);
export type Audience = Static<typeof Audience>;

const Price = Type.Object({ amount: Amount, currency: Type.String({ minLength: 1 }) });

export const Intent = Type.Object(
  {
    ...layer2,
    type: Type.Literal("Intent"),
    want: Type.String({ maxLength: 4096 }),
    subject: Type.Optional(Type.Unknown()),
    constraints: Type.Optional(
      Type.Object({
        deadline: Type.Optional(Timestamp),
        budget: Type.Optional(Type.Object({ max: Amount, currency: Type.String({ minLength: 1 }) })),
        requires: Type.Optional(Strings),
      }),
    ),
    audience: Type.Optional(Audience),
  },
  { ...meta("Intent", "A statement of an outcome a mind seeks (Layer 2, 4.1)."), ...statusNeedsSupersedes },
);
export type Intent = Static<typeof Intent>;

/** Layer 2, 4.2: the terms of an Offer or of a capability. */
export const OfferTerms = define(
  "offerTerms",
  Type.Object({
  summary: Type.String(),
  price: Type.Optional(Price),
  deliveryBy: Type.Optional(Timestamp),
  quantity: Type.Optional(Count),
  conditions: Type.Optional(Strings),
  }),
);
export type OfferTerms = Static<typeof OfferTerms>;

export const Offer = Type.Object(
  {
    ...layer2,
    type: Type.Literal("Offer"),
    provides: Type.String({ maxLength: 4096 }),
    terms: OfferTerms,
    answers: Type.Optional(RecordRef),
    capability: Type.Optional(Type.String({ maxLength: 128 })),
    subject: Type.Optional(Type.Unknown()),
    audience: Type.Optional(Audience),
  },
  { ...meta("Offer", "A statement of what a mind provides, and on what terms (Layer 2, 4.2)."), ...statusNeedsSupersedes },
);
export type Offer = Static<typeof Offer>;

const Role = Type.Union([
  Type.Literal("debtor"),
  Type.Literal("creditor"),
  Type.Literal("witness"),
  Namespaced,
]);

/** Layer 2, 5.1: a party to a Commitment. */
export const Party = Type.Object(
  {
    mind: MindAddress,
    role: Role,
    required: Type.Optional(Type.Boolean()),
  },
  {
    // 5.1: every debtor and creditor is `required`.
    if: { properties: { role: { enum: ["debtor", "creditor"] } }, required: ["role"] },
    then: { properties: { required: { const: true } }, required: ["required"] },
  },
);
export type Party = Static<typeof Party>;

export const Commitment = Type.Object(
  {
    ...layer2,
    type: Type.Literal("Commitment"),
    parties: Type.Array(Party, {
      minItems: 2,
      maxItems: 64,
      // 5.1: at least one debtor and at least one creditor.
      allOf: [
        { contains: { properties: { role: { const: "debtor" } }, required: ["role"] } },
        { contains: { properties: { role: { const: "creditor" } }, required: ["role"] } },
      ],
    }),
    promise: Type.String({ maxLength: 8192 }),
    terms: Type.Object({
      deadline: Type.Optional(Timestamp),
      deliverables: Type.Optional(Type.Unknown()),
      price: Type.Optional(
        Type.Object({
          amount: Amount,
          currency: Type.String({ minLength: 1 }),
          payer: MindAddress,
          payee: MindAddress,
        }),
      ),
      conditions: Type.Optional(Type.Unknown()),
      selfReport: Type.Optional(Type.Boolean()),
    }),
    resolves: Type.Optional(Type.Array(RecordRef)),
    closesIntent: Type.Optional(Type.Boolean()),
    onBehalfOf: Type.Optional(MindAddress),
  },
  {
    ...meta("Commitment", "A promise between parties, binding on those whose signatures count (Layer 2, Section 5)."),
    ...statusNeedsSupersedes,
  },
);
export type Commitment = Static<typeof Commitment>;

export const Receipt = Type.Object(
  {
    ...layer2,
    type: Type.Literal("Receipt"),
    about: RecordRef,
    outcome: Type.Union([
      Type.Literal("accepted"),
      Type.Literal("progress"),
      Type.Literal("fulfilled"),
      Type.Literal("broken"),
      Type.Literal("cancelled"),
      Type.Literal("disputed"),
      Type.Literal("revoked"),
      Namespaced,
    ]),
    statement: Type.Optional(Type.String({ maxLength: 8192 })),
    evidence: Type.Optional(Type.Array(Evidence, { maxItems: 64 })),
    rating: Type.Optional(Type.Object({ score: UnitDecimal })),
  },
  {
    ...meta("Receipt", "A signed statement about a record, usually about how a Commitment went (Layer 2, 6.1)."),
    ...statusNeedsSupersedes,
    // 6.1: a `revoked` Receipt supersedes an earlier Receipt by the same author.
    if: { properties: { outcome: { const: "revoked" } }, required: ["outcome"] },
    then: { required: ["supersedes"] },
  },
);
export type Receipt = Static<typeof Receipt>;

/** Layer 2, 6.2: a power a role confers. A reserved command grants nothing, but is not malformed. */
export const Power = Type.Object({
  command: Command,
  policy: Type.Optional(ref(Policy)),
});
export type Power = Static<typeof Power>;

export const Collective = Type.Object(
  {
    ...layer2,
    type: Type.Literal("Collective"),
    name: Type.String({ maxLength: 128 }),
    purpose: Type.String(),
    roles: Type.Optional(
      Type.Unsafe<Readonly<Record<string, { purpose?: string; powers?: Power[] }>>>({
        type: "object",
        additionalProperties: {
          type: "object",
          properties: {
            purpose: { type: "string" },
            powers: { type: "array", items: Power },
          },
        },
      }),
    ),
    assignments: Type.Optional(
      Type.Array(Type.Object({ mind: MindAddress, role: Type.String({ minLength: 1 }) })),
    ),
    procedures: Type.Optional(JsonObject),
  },
  {
    ...meta("Collective", "A collective's charter: its purpose, roles and assignments (Layer 2, 6.2)."),
    ...statusNeedsSupersedes,
  },
);
export type Collective = Static<typeof Collective>;
