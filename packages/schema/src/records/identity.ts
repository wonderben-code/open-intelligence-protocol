// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Identity-log events (Layer 1, Section 3). */

import { type Static, Type } from "typebox";

import { signedRecord } from "../common.ts";
import { define, meta } from "../naming.ts";
import {
  ContentId,
  Ed25519Multikey,
  HttpsOrigin,
  JsonObject,
  KeyHash,
  MAX_SAFE_INTEGER,
  MindAddress,
  Timestamp,
  VersionId,
  X25519Multikey,
} from "../primitives.ts";

const closed = { additionalProperties: false } as const;

/** Layer 1, 3.4: the keys an event reveals and the commitments to the keys that sign the next. */
export const KeyController = define(
  "keyController",
  Type.Object(
    {
      keys: Type.Array(Ed25519Multikey, { minItems: 1, maxItems: 16, uniqueItems: true }),
      next: Type.Array(KeyHash, { maxItems: 16, uniqueItems: true }),
      nextThreshold: Type.Optional(Type.Integer({ minimum: 1, maximum: 16 })),
    },
    closed,
  ),
);
export type KeyController = Static<typeof KeyController>;

/** Layer 1, 3.4: the member minds that control a collective, and their majority threshold. */
export const MemberController = define(
  "memberController",
  Type.Object(
    {
      members: Type.Array(MindAddress, { minItems: 1, maxItems: 256, uniqueItems: true }),
      threshold: Type.Integer({ minimum: 1, maximum: 256 }),
    },
    closed,
  ),
);
export type MemberController = Static<typeof MemberController>;

export const Controller = define("controller", Type.Union([KeyController, MemberController]));
export type Controller = Static<typeof Controller>;

const label = Type.Optional(Type.String({ maxLength: 64 }));

/** Layer 1, 3.5: an operational or invocation key. */
export const SigningKeyEntry = define(
  "signingKeyEntry",
  Type.Object({ key: Ed25519Multikey, label }, closed),
);
export type SigningKeyEntry = Static<typeof SigningKeyEntry>;

/** Layer 1, 3.5: an agreement key. */
export const AgreementKeyEntry = define(
  "agreementKeyEntry",
  Type.Object({ key: X25519Multikey, label }, closed),
);
export type AgreementKeyEntry = Static<typeof AgreementKeyEntry>;

/** Layer 1, 3.7: a key that can never be added again. */
export const RevokedKey = Type.Object({
  key: Ed25519Multikey,
  compromisedSince: Type.Optional(Timestamp),
});
export type RevokedKey = Static<typeof RevokedKey>;

/** Members that replace the identity state's values when present (Layer 1, 4.5). */
const stateFields = {
  keys: Type.Optional(Type.Array(SigningKeyEntry, { maxItems: 64 })),
  invocation: Type.Optional(Type.Array(SigningKeyEntry, { maxItems: 16 })),
  agreement: Type.Optional(Type.Array(AgreementKeyEntry, { maxItems: 16 })),
  homes: Type.Optional(Type.Array(HttpsOrigin, { maxItems: 8 })),
  alsoKnownAs: Type.Optional(Type.Array(Type.String({ minLength: 1 }), { maxItems: 16 })),
};

// Layer 1, 3.12: `recovery` is reserved, and an event that contains it is rejected.
const noRecovery = { required: ["recovery"] };

export const Genesis = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("Genesis"),
    kind: Type.String({ minLength: 1, maxLength: 64 }),
    controller: Controller,
    ...stateFields,
    parents: Type.Optional(
      Type.Array(Type.Object({ mind: MindAddress, at: VersionId }), { maxItems: 16 }),
    ),
    inherits: Type.Optional(JsonObject),
    height: Type.Optional(Type.Integer({ minimum: 1, maximum: 4 })),
  },
  {
    ...meta(
      "Genesis",
      "The first event of an identity log (Layer 1, 3.6). Its content ID is the mind's address.",
    ),
    // 3.2: a Genesis has no `mind`, `seq` or `prev`.
    not: {
      anyOf: [{ required: ["mind"] }, { required: ["seq"] }, { required: ["prev"] }, noRecovery],
    },
    allOf: [
      {
        // 3.6: a collective is member-controlled.
        if: { properties: { kind: { const: "collective" } }, required: ["kind"] },
        then: { properties: { controller: { required: ["members"] } } },
      },
      {
        // 3.6: only a member-controlled Genesis has `height`.
        if: { properties: { controller: { required: ["keys"] } }, required: ["controller"] },
        then: { not: { required: ["height"] } },
      },
    ],
  },
);
export type Genesis = Static<typeof Genesis>;

/** Layer 1, 3.2: the members of every event after the genesis. */
const laterEvent = {
  ...signedRecord,
  mind: MindAddress,
  seq: Type.Integer({ minimum: 1, maximum: MAX_SAFE_INTEGER }),
  prev: ContentId,
  controller: Type.Optional(Controller),
  ...stateFields,
  revoked: Type.Optional(Type.Array(RevokedKey)),
};

// 3.6: no event after a genesis has `height`.
const laterEventRules = { not: { anyOf: [{ required: ["height"] }, noRecovery] } };

export const Update = Type.Object(
  { ...laterEvent, type: Type.Literal("Update") },
  {
    ...meta(
      "Update",
      "Rotates control keys or changes a mind's keys, homes or aliases (Layer 1, 3.7).",
    ),
    ...laterEventRules,
  },
);
export type Update = Static<typeof Update>;

export const Fork = Type.Object(
  {
    ...laterEvent,
    type: Type.Literal("Fork"),
    child: MindAddress,
    terms: Type.Optional(JsonObject),
  },
  {
    ...meta(
      "Fork",
      "Records in the parent's identity log that a child mind was forked from it (Layer 1, 3.8).",
    ),
    ...laterEventRules,
  },
);
export type Fork = Static<typeof Fork>;

export const Retire = Type.Object(
  {
    ...laterEvent,
    type: Type.Literal("Retire"),
    successor: Type.Optional(MindAddress),
    reason: Type.Optional(Type.String()),
  },
  {
    ...meta("Retire", "Ends an identity log. No event may follow it (Layer 1, 3.10)."),
    ...laterEventRules,
    // 3.10: a key-controlled mind retires with `next` empty.
    if: { properties: { controller: { required: ["keys"] } }, required: ["controller"] },
    then: { properties: { controller: { properties: { next: { maxItems: 0 } } } } },
  },
);
export type Retire = Static<typeof Retire>;

export type IdentityEvent = Genesis | Update | Fork | Retire;
