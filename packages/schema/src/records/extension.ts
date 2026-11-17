// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** A record of a type this revision does not define (core Section 7). */

import { type Static, Type } from "typebox";

import { ProofSet } from "../common.ts";
import { meta } from "../naming.ts";
import { Ext, Timestamp } from "../primitives.ts";

/**
 * The members every record shares, for a record whose `type` an extension
 * defines. `created` is required, as in every record except the containers
 * and `Sealed` (core 7), which are types of this revision. Nothing says
 * whether such a record is signed, so `proof` is optional and checked when
 * present.
 *
 * Such a record lists the extension that defines its type in `critical`
 * (core 7), so `critical` is required and names at least one namespace.
 */
export const ExtensionRecord = Type.Object(
  {
    oip: Type.Literal("1"),
    type: Type.String(),
    created: Timestamp,
    expires: Type.Optional(Timestamp),
    ext: Type.Optional(Ext),
    critical: Type.Array(Type.String(), { minItems: 1 }),
    proof: Type.Optional(ProofSet),
  },
  meta(
    "ExtensionRecord",
    "A record of a type this revision does not define, as an extension may define one (core Section 7). Only the members every record shares are checked. It lists the extension that defines its type in `critical`.",
  ),
);
export type ExtensionRecord = Static<typeof ExtensionRecord>;
