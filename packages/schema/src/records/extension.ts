// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** A record of a type this revision does not define (core Section 7). */

import { type Static, Type } from "typebox";

import { ProofSet } from "../common.ts";
import { meta } from "../naming.ts";
import { Critical, Ext, Timestamp } from "../primitives.ts";

/**
 * The members every record shares, for a record whose `type` an extension
 * defines. Nothing says whether such a record is signed or is a container, so
 * `created` and `proof` are optional here and checked when present.
 */
export const ExtensionRecord = Type.Object(
  {
    oip: Type.Literal("1"),
    type: Type.String(),
    created: Type.Optional(Timestamp),
    expires: Type.Optional(Timestamp),
    ext: Type.Optional(Ext),
    critical: Type.Optional(Critical),
    proof: Type.Optional(ProofSet),
  },
  meta(
    "ExtensionRecord",
    "A record of a type this revision does not define, as an extension may define one (core Section 7). Only the members every record shares are checked.",
  ),
);
export type ExtensionRecord = Static<typeof ExtensionRecord>;
