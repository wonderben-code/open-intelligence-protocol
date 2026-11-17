// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The value syntaxes of core Sections 1, 3, 4 and 6, as patterns and as
 * schemas. Every pattern is written without lookaround or back-references, so
 * that the exported JSON Schemas also work with validators built on linear-time
 * regular-expression engines (RE2, Rust's `regex`).
 */

import { Type } from "typebox";

import { define } from "./naming.ts";

/** The largest integer a record may contain (core 1.2): 2^53 - 1. */
export const MAX_SAFE_INTEGER = 9007199254740991;

const CID = "bciq[a-p][a-z2-7]{50}[aiqy]";
const BASE58 = "[1-9A-HJ-NP-Za-km-z]";
const SEQ = "(?:0|[1-9][0-9]*)";
const ADDRESS = `did:oip:${CID}`;
const VERSION_ID = `${SEQ}-${CID}`;
const ED25519_MULTIKEY = `z6Mk${BASE58}{44}`;
const X25519_MULTIKEY = `z6LS${BASE58}{44}`;

// A real calendar date: the day must exist in its month, with leap years by
// the Gregorian rule (divisible by 4 and not by 100, or divisible by 400).
const DATE_31 = "(?:0[13578]|1[02])-(?:0[1-9]|[12][0-9]|3[01])";
const DATE_30 = "(?:0[469]|11)-(?:0[1-9]|[12][0-9]|30)";
const DATE_FEB = "02-(?:0[1-9]|1[0-9]|2[0-8])";
const LEAP_YEAR = "(?:[0-9]{2}(?:0[48]|[2468][048]|[13579][26])|(?:[02468][048]|[13579][26])00)";
const DATE = `(?:[0-9]{4}-(?:${DATE_31}|${DATE_30}|${DATE_FEB})|${LEAP_YEAR}-02-29)`;
const TIME = "(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\\.[0-9]{1,9})?";

const DURATION_TIME = "(?:[0-9]+H(?:[0-9]+M)?(?:[0-9]+S)?|[0-9]+M(?:[0-9]+S)?|[0-9]+S)";

/**
 * The patterns, anchored, as ECMAScript regular-expression sources. They are
 * exported so that other packages and other implementations use one spelling.
 */
export const patterns = {
  /** core 3.2: the one canonical spelling of a content ID. */
  contentId: `^${CID}$`,
  /** core 6.1 `mind-address`. */
  mindAddress: `^${ADDRESS}$`,
  /** core 6.1 `version-id`. */
  versionId: `^${VERSION_ID}$`,
  /** core 6.1 `versioned-mind`. */
  versionedMind: `^${ADDRESS}\\?versionId=${VERSION_ID}$`,
  /** core 6.1 `key-ref`. */
  keyRef: `^${ADDRESS}\\?versionId=${VERSION_ID}#z${BASE58}+$`,
  /** core 6.1 `control-key-ref`. That both keys are identical is a rule, not a pattern (core 6.2). */
  controlKeyRef: `^did:key:z${BASE58}+#z${BASE58}+$`,
  /** core 6.1 `record-ref`. */
  recordRef: `^${ADDRESS}/${CID}$`,
  /**
   * core 4.1: the form of an Ed25519 public key as a Multikey (48 characters).
   * Necessary, not sufficient: a few strings of this form decode to another
   * multicodec prefix, and none of them is checked to be a point of order L.
   * `@oip/core` decodes the key and applies core 4.2 and 4.4.
   */
  ed25519Multikey: `^${ED25519_MULTIKEY}$`,
  /** core 4.1: the form of an X25519 public key as a Multikey (48 characters). Necessary, not sufficient, as above. */
  x25519Multikey: `^${X25519_MULTIKEY}$`,
  /** core 5.2: `z` and the base58btc form of a 64-byte signature. */
  proofValue: `^z${BASE58}{64,88}$`,
  /** core 1.3: a decimal quantity. */
  decimal: "^-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?$",
  /** core 1.3: an amount, which is never negative. */
  amount: "^(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?$",
  /** A decimal from 0 to 1 inclusive (scores and ratings). Decimals compare numerically, so "-0" is 0. */
  unitDecimal: "^(?:-0(?:\\.0+)?|0(?:\\.[0-9]+)?|1(?:\\.0+)?)$",
  /** core 1.4: an RFC 3339 UTC timestamp that names a real date and time. */
  timestamp: `^${DATE}T${TIME}Z$`,
  /** core 1.5: an ISO 8601 duration of days, hours, minutes and seconds. */
  duration: `^P(?:[0-9]+D(?:T${DURATION_TIME})?|T${DURATION_TIME})$`,
  /** A SHA-256 digest of exact bytes (Layer 1, 10.1 and 12.2; Layer 2, 9). */
  sha256Digest: "^sha256:[0-9a-f]{64}$",
  /** Layer 1, 11.2: a command. */
  command: "^/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$",
  /** Layer 1, 11.2: the commands under `/oip`, all reserved except the five the specification lists. */
  oipCommandSpace: "^/oip(?:/|$)",
  /** core 8.1: a reverse-DNS extension namespace. */
  reverseDnsNamespace: "^[a-z0-9-]+(?:\\.[a-z0-9-]+)+$",
  /** core 8.1: a namespace reserved for profiles published by the OIP project. */
  oipNamespace: "^oip\\.",
  /** A namespaced name `<namespace>:<name>` (verbs, roles, outcomes, evidence kinds, tags). */
  namespaced: "^[^:]+:.+$",
  /** An HTTPS origin: scheme, host and optional port, with no path, query or fragment. */
  httpsOrigin: "^https://[^/?#@\\s]+$",
  /** Layer 1, 16.2: a capability subject. */
  capabilitySubject: "^[a-z0-9_-]+(?:\\.[a-z0-9_-]+)*$",
  /** base64url without padding (Layer 1, 12.6). */
  base64url: "^[A-Za-z0-9_-]+$",
} as const;

/** The commands under `/oip` that a delegation or a role may grant (Layer 1, 11.2). */
export const OIP_COMMANDS = [
  "/oip/sign/Intent",
  "/oip/sign/Offer",
  "/oip/sign/Commitment",
  "/oip/sign/Receipt",
  "/oip/send",
] as const;

/** The short extension namespaces core 8.1 recognises. */
export const SHORT_NAMESPACES = ["x402", "ap2", "acp", "l402", "vc", "as2"] as const;

/** core 1.4. Compared as an instant, never as a string. */
export const Timestamp = define(
  "timestamp",
  Type.String({ pattern: patterns.timestamp, maxLength: 30 }),
);

/** core 1.5. */
export const Duration = define("duration", Type.String({ pattern: patterns.duration }));

/** core 1.3. At most 64 characters, compared with exact decimal arithmetic. */
export const Decimal = define("decimal", Type.String({ pattern: patterns.decimal, maxLength: 64 }));

/** core 1.3. A decimal that is never negative. */
export const Amount = define("amount", Type.String({ pattern: patterns.amount, maxLength: 64 }));

/** A decimal string from "0" to "1" (Layer 1, 18.3; Layer 2, 6.1). */
export const UnitDecimal = define(
  "unitDecimal",
  Type.String({ pattern: patterns.unitDecimal, maxLength: 64 }),
);

/** core 1.2: a non-negative safe integer. */
export const Count = define("count", Type.Integer({ minimum: 0, maximum: MAX_SAFE_INTEGER }));

/** core 1.2: any safe integer. */
export const SafeInteger = define(
  "safeInteger",
  Type.Integer({
    minimum: -MAX_SAFE_INTEGER,
    maximum: MAX_SAFE_INTEGER,
  }),
);

/** core 3.2. */
export const ContentId = define("contentId", Type.String({ pattern: patterns.contentId }));

/** core 3.4. A key hash has the same form as a content ID. */
export const KeyHash = ContentId;

/** core 6.1 `mind-address`. */
export const MindAddress = define("mindAddress", Type.String({ pattern: patterns.mindAddress }));

/** core 6.1 `version-id`. */
export const VersionId = define("versionId", Type.String({ pattern: patterns.versionId }));

/** core 6.1 `versioned-mind`. */
export const VersionedMind = define(
  "versionedMind",
  Type.String({ pattern: patterns.versionedMind }),
);

/** core 6.1 `record-ref`. */
export const RecordRef = define("recordRef", Type.String({ pattern: patterns.recordRef }));

/** core 4.1. */
export const Ed25519Multikey = define(
  "ed25519Multikey",
  Type.String({ pattern: patterns.ed25519Multikey }),
);

/** core 4.1. */
export const X25519Multikey = define(
  "x25519Multikey",
  Type.String({ pattern: patterns.x25519Multikey }),
);

/** `"sha256:"` and 64 lower-case hex digits. */
export const Sha256Digest = define("sha256Digest", Type.String({ pattern: patterns.sha256Digest }));

/** A nonce of 8 to 64 characters (Layer 1, 11.1, 12.1 and 14.1). */
export const Nonce = define("nonce", Type.String({ minLength: 8, maxLength: 64 }));

/** An HTTPS origin. */
export const HttpsOrigin = define("httpsOrigin", Type.String({ pattern: patterns.httpsOrigin }));

/** Any JSON object. Its members are preserved and otherwise ignored (core 1.7). */
export const JsonObject = Type.Unsafe<Readonly<Record<string, unknown>>>({ type: "object" });

/** A namespaced name `<namespace>:<name>`. */
export const Namespaced = define("namespaced", Type.String({ pattern: patterns.namespaced }));

/** An array of strings with no further structure. */
export const Strings = Type.Array(Type.String());

/** core 8.1: extension blocks, keyed by namespace. */
export const Ext = define(
  "ext",
  Type.Unsafe<Readonly<Record<string, Readonly<Record<string, unknown>>>>>({
    type: "object",
    propertyNames: {
      anyOf: [
        { pattern: patterns.reverseDnsNamespace },
        { enum: [...SHORT_NAMESPACES] },
        { pattern: patterns.oipNamespace },
      ],
    },
    additionalProperties: { type: "object" },
  }),
);

/** core 8.3: the namespaces a reader must understand. Each also appears in `ext` (a rule). */
export const Critical = Type.Array(Type.String());
