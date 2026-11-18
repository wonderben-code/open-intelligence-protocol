// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Layer 1 records other than identity events and delegation: lineage, feeds,
 * packets, sessions, location records, profiles and indexer results.
 */

import { type Static, Type } from "typebox";

import { containerRecord, signedRecord, unsignedRecord } from "../common.ts";
import { meta, ref } from "../naming.ts";
import {
  ContentId,
  Count,
  Duration,
  HttpsOrigin,
  JsonObject,
  MAX_SAFE_INTEGER,
  MindAddress,
  Namespaced,
  Nonce,
  patterns,
  RecordRef,
  SafeInteger,
  Sha256Digest,
  Strings,
  Timestamp,
  UnitDecimal,
  VersionedMind,
  X25519Multikey,
} from "../primitives.ts";
import { CapabilityQuery, Evidence, OfferTerms } from "./web.ts";

export const Lineage = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("Lineage"),
    author: MindAddress,
    child: MindAddress,
    terms: Type.Optional(JsonObject),
  },
  meta(
    "Lineage",
    "A parent's acknowledgement of a child mind, made without its control keys (Layer 1, 8.3).",
  ),
);
export type Lineage = Static<typeof Lineage>;

export const Entry = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("Entry"),
    author: MindAddress,
    seq: Count,
    prev: Type.Optional(ContentId),
    object: ContentId,
    objectType: Type.String(),
    proofs: Type.Optional(Type.Array(Sha256Digest)),
  },
  {
    ...meta(
      "Entry",
      "One entry of a mind's public feed, committing to a record and to its proofs (Layer 1, 10.1).",
    ),
    // 10.1: `prev` is required when `seq` is greater than 0.
    if: { properties: { seq: { minimum: 1 } }, required: ["seq"] },
    then: { required: ["prev"] },
  },
);
export type Entry = Static<typeof Entry>;

export const Checkpoint = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("Checkpoint"),
    author: MindAddress,
    size: Type.Integer({ minimum: 1, maximum: MAX_SAFE_INTEGER }),
    head: ContentId,
    root: ContentId,
  },
  meta("Checkpoint", "The Merkle root over the first `size` entries of a feed (Layer 1, 10.5)."),
);
export type Checkpoint = Static<typeof Checkpoint>;

/** Layer 1, 12.3: an advisory verb. */
export const Verb = Type.Union([
  Type.Literal("inform"),
  Type.Literal("request"),
  Type.Literal("query"),
  Type.Literal("propose"),
  Type.Literal("accept"),
  Type.Literal("decline"),
  Type.Literal("deliver"),
  Type.Literal("ack"),
  Type.Literal("error"),
  Type.Literal("open"),
  Type.Literal("resume"),
  Type.Literal("branch"),
  Type.Literal("close"),
  Namespaced,
]);
export type Verb = Static<typeof Verb>;

/** Layer 1, 12.2: content carried in the packet. */
export interface InlineContent {
  mediaType: string;
  body: unknown;
}

/** Layer 1, 12.2: content carried by reference, with the digest of its exact bytes. */
export interface ReferencedContent {
  mediaType: string;
  ref: string;
  digest: string;
}

/** Layer 1, 12.2: up to 32 parts, none of which has parts of its own. */
export interface MultipartContent {
  parts: (InlineContent | ReferencedContent)[];
}

export type Content = InlineContent | ReferencedContent | MultipartContent;

const mediaType = { type: "string" };
const has = (...names: string[]) => ({ anyOf: names.map((name) => ({ required: [name] })) });
const inlineContent = {
  type: "object",
  properties: { mediaType },
  required: ["mediaType", "body"],
  not: has("ref", "digest", "parts"),
};
const referencedContent = {
  type: "object",
  properties: { mediaType, ref: { type: "string" }, digest: Sha256Digest },
  required: ["mediaType", "ref", "digest"],
  not: has("body", "parts"),
};

/** Layer 1, 12.2: exactly one of the three forms. */
export const Content = Type.Unsafe<Content>({
  anyOf: [
    inlineContent,
    referencedContent,
    {
      type: "object",
      properties: {
        parts: {
          type: "array",
          maxItems: 32,
          items: { anyOf: [inlineContent, referencedContent] },
        },
      },
      required: ["parts"],
      not: has("mediaType", "body", "ref", "digest"),
    },
  ],
});

/** Layer 1, 12.1: the recipients of a packet. */
export const PacketTo = Type.Union([
  Type.Array(MindAddress, { minItems: 1, maxItems: 64 }),
  Type.Object({
    query: CapabilityQuery,
    brokers: Type.Optional(Type.Array(MindAddress, { minItems: 1, maxItems: 8 })),
    maxFanout: Type.Optional(Type.Integer({ minimum: 1, maximum: 50 })),
  }),
  Type.Object({ subject: Type.String() }),
]);
export type PacketTo = Static<typeof PacketTo>;

const threadId = Type.Optional(Type.String({ maxLength: 128 }));

export const Packet = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("Packet"),
    from: MindAddress,
    to: PacketTo,
    nonce: Nonce,
    session: Type.Optional(ContentId),
    seq: Type.Optional(Count),
    prev: Type.Optional(ContentId),
    instance: Type.Optional(Type.String({ maxLength: 64 })),
    thread: threadId,
    parentThread: threadId,
    replyTo: threadId,
    purpose: Type.Object({
      verb: Verb,
      goal: Type.Optional(Type.String({ maxLength: 256 })),
      schema: Type.Optional(Type.String()),
    }),
    content: Content,
    context: Type.Optional(
      Type.Object({
        refs: Type.Optional(Strings),
        summary: Type.Optional(Type.Unknown()),
        assumptions: Type.Optional(Type.Unknown()),
        language: Type.Optional(Type.String()),
        stateDoc: Type.Optional(Type.Unknown()),
      }),
    ),
    provenance: Type.Optional(
      Type.Object({
        derivedFrom: Type.Optional(Strings),
        generatedBy: Type.Optional(
          Type.Object({
            model: Type.Optional(Type.Unknown()),
            version: Type.Optional(Type.Unknown()),
            tool: Type.Optional(Type.Unknown()),
          }),
        ),
        onBehalfOf: Type.Optional(MindAddress),
      }),
    ),
    constraints: Type.Optional(
      Type.Object({
        retention: Type.Optional(Type.Union([Duration, Type.Literal("none")])),
        allowedUses: Type.Optional(Strings),
        prohibitedUses: Type.Optional(Strings),
        confidentiality: Type.Optional(Type.Unknown()),
        licence: Type.Optional(Type.String()),
        jurisdiction: Type.Optional(Type.Unknown()),
        forwardOk: Type.Optional(Type.Boolean()),
        maxHops: Type.Optional(SafeInteger),
      }),
    ),
    hints: Type.Optional(
      Type.Unsafe<Readonly<Record<string, string[]>>>({
        type: "object",
        propertyNames: { pattern: patterns.mindAddress },
        additionalProperties: {
          type: "array",
          // An HTTPS URL: the scheme, and no white space. URLs are parsed where they are used.
          items: { type: "string", pattern: "^https://\\S+$" },
        },
      }),
    ),
  },
  {
    ...meta("Packet", "A signed message from one mind to others (Layer 1, 12.1)."),
    // 12.1: `session` and `seq` appear together.
    dependentRequired: { session: ["seq"], seq: ["session"] },
    allOf: [
      // 12.1: a packet outside a session carries `expires`.
      { anyOf: [{ required: ["expires"] }, { required: ["session"] }] },
      {
        // 12.1: `prev` is required when `seq` is greater than 0.
        if: { properties: { seq: { minimum: 1 } }, required: ["seq"] },
        then: { required: ["prev"] },
      },
    ],
  },
);
export type Packet = Static<typeof Packet>;

export const Ack = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("Ack"),
    author: MindAddress,
    packet: ContentId,
    received: Timestamp,
    sealed: Type.Optional(ContentId),
    // 13.2: the digests of the proofs the packet carried on itself when it was received.
    proofs: Type.Optional(Type.Array(Sha256Digest, { maxItems: 256 })),
  },
  meta(
    "Ack",
    "A recipient's acknowledgement that it received a packet at a given time (Layer 1, 13.2).",
  ),
);
export type Ack = Static<typeof Ack>;

export const Hello = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("Hello"),
    author: MindAddress,
  },
  meta(
    "Hello",
    "Authenticates a mind to a server, with a proof over the server's challenge (Layer 1, 13.3).",
  ),
);
export type Hello = Static<typeof Hello>;

export const Session = Type.Object(
  {
    ...unsignedRecord,
    type: Type.Literal("Session"),
    participants: Type.Array(MindAddress, { minItems: 2, maxItems: 256, uniqueItems: true }),
    nonce: Nonce,
  },
  meta(
    "Session",
    "Names a session by its participants and a nonce. Unsigned; its content ID is the session ID (Layer 1, 14.1).",
  ),
);
export type Session = Static<typeof Session>;

const chainPosition = {
  seq: Count,
  packet: ContentId,
  instance: Type.Optional(Type.String({ maxLength: 64 })),
};

export const Resume = Type.Object(
  {
    ...unsignedRecord,
    type: Type.Literal("Resume"),
    session: ContentId,
    lastSent: Type.Optional(Type.Object(chainPosition)),
    lastReceived: Type.Array(Type.Object({ mind: MindAddress, ...chainPosition })),
  },
  meta(
    "Resume",
    "Says where each sending chain of a session stands, so that missing packets can be sent again (Layer 1, 14.4).",
  ),
);
export type Resume = Static<typeof Resume>;

export const Branch = Type.Object(
  {
    ...unsignedRecord,
    type: Type.Literal("Branch"),
    parentSession: ContentId,
    fork: VersionedMind,
  },
  meta(
    "Branch",
    "A fork's proposal to continue from its parent's session in a new one (Layer 1, 14.5).",
  ),
);
export type Branch = Static<typeof Branch>;

/** Layer 1, 15.1: one way to reach a mind. Endpoints with unknown bindings are ignored. */
export const Endpoint = Type.Object({
  binding: Type.String(),
  url: Type.String(),
  instance: Type.Optional(Type.String({ maxLength: 64 })),
  priority: Type.Optional(SafeInteger),
});
export type Endpoint = Static<typeof Endpoint>;

export const Location = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("Location"),
    author: MindAddress,
    seq: SafeInteger,
    ttl: Type.Integer({ minimum: 60, maximum: 86400 }),
    status: Type.Union([Type.Literal("active"), Type.Literal("paused"), Type.Literal("migrating")]),
    resumeAfter: Type.Optional(Timestamp),
    endpoints: Type.Array(Endpoint, { maxItems: 32 }),
    homes: Type.Optional(Type.Array(HttpsOrigin)),
    participant: Type.Optional(ContentId),
    feed: Type.Optional(Type.Object({ seq: Count, head: ContentId })),
  },
  meta(
    "Location",
    "Where a mind can be reached now (Layer 1, 15.1). Judged under the current-state rule.",
  ),
);
export type Location = Static<typeof Location>;

/** Layer 1, 16.2: something a mind can do. */
export const Capability = Type.Object({
  id: Type.String({ maxLength: 128 }),
  summary: Type.String(),
  tags: Type.Optional(Type.Array(Namespaced, { maxItems: 64 })),
  subject: Type.Optional(Type.String({ pattern: patterns.capabilitySubject })),
  inputs: Type.Optional(Strings),
  outputs: Type.Optional(Strings),
  terms: Type.Optional(OfferTerms),
  evidence: Type.Optional(Type.Array(Evidence)),
  attestations: Type.Optional(Strings),
});
export type Capability = Static<typeof Capability>;

export const Participant = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("Participant"),
    author: MindAddress,
    name: Type.String({ maxLength: 128 }),
    kind: Type.String({ minLength: 1, maxLength: 64 }),
    summary: Type.Optional(Type.String({ maxLength: 1024 })),
    capabilities: Type.Optional(Type.Array(Capability, { maxItems: 256 })),
    actsFor: Type.Optional(Type.Array(Type.Object({ mind: MindAddress, authority: RecordRef }))),
    interfaces: Type.Optional(
      Type.Unsafe<Readonly<Record<string, string>>>({
        type: "object",
        additionalProperties: { type: "string" },
      }),
    ),
    languages: Type.Optional(Strings),
    attestations: Type.Optional(Strings),
    supersedes: Type.Optional(RecordRef),
  },
  meta(
    "Participant",
    "A mind's profile: what it is and what it can do (Layer 1, 16.1). Judged under the current-state rule.",
  ),
);
export type Participant = Static<typeof Participant>;

export const QueryResult = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("QueryResult"),
    author: MindAddress,
    query: CapabilityQuery,
    results: Type.Array(
      Type.Object({
        mind: MindAddress,
        record: ContentId,
        capability: Type.Optional(Type.String({ maxLength: 128 })),
        score: UnitDecimal,
        why: Type.Optional(Type.String()),
        hints: Type.Optional(Strings),
      }),
    ),
  },
  meta("QueryResult", "An indexer's signed answer to a capability query (Layer 1, 18.3)."),
);
export type QueryResult = Static<typeof QueryResult>;

export const Forwarded = Type.Object(
  {
    ...signedRecord,
    type: Type.Literal("Forwarded"),
    broker: MindAddress,
    to: MindAddress,
    packet: ref(Packet),
  },
  meta(
    "Forwarded",
    "A broker's wrapper around a packet it delivers to a mind that matched the packet's query (Layer 1, 18.5).",
  ),
);
export type Forwarded = Static<typeof Forwarded>;

export const Sealed = Type.Object(
  {
    ...containerRecord,
    type: Type.Literal("Sealed"),
    to: MindAddress,
    key: X25519Multikey,
    suite: Type.Literal("hpke-base-x25519-sha256-chacha20poly1305"),
    enc: Type.String({ pattern: patterns.base64url }),
    ciphertext: Type.String({ pattern: patterns.base64url }),
  },
  meta(
    "Sealed",
    "A packet encrypted to one of the recipient's agreement keys with HPKE. Unsigned (Layer 1, 12.6).",
  ),
);
export type Sealed = Static<typeof Sealed>;
