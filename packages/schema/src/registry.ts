// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Every record type of core Section 11, by name. */

import type { Static } from "typebox";

import { Proof } from "./proof.ts";
import { Bundle, DuplicityEvidence, FeedPage, LogPage } from "./records/containers.ts";
import { Delegation, Policy, Revocation } from "./records/delegation.ts";
import { Fork, Genesis, Retire, Update } from "./records/identity.ts";
import {
  Ack,
  Branch,
  Checkpoint,
  Entry,
  Forwarded,
  Hello,
  Lineage,
  Location,
  Packet,
  Participant,
  QueryResult,
  Resume,
  Sealed,
  Session,
} from "./records/net.ts";
import { Collective, Commitment, Intent, Offer, Receipt } from "./records/web.ts";

/** The schema of each record type, in the order of the table in core Section 11. */
export const recordSchemas = {
  Genesis,
  Update,
  Fork,
  Retire,
  Delegation,
  Revocation,
  Lineage,
  Collective,
  Intent,
  Offer,
  Commitment,
  Receipt,
  Packet,
  Entry,
  Checkpoint,
  Ack,
  QueryResult,
  Forwarded,
  Location,
  Participant,
  Hello,
  Session,
  Resume,
  Branch,
  Bundle,
  LogPage,
  FeedPage,
  DuplicityEvidence,
  Sealed,
} as const;

/** Named schemas that are not records. */
export const sharedSchemas = { Proof, Policy } as const;

/** The static type of every record type, by name. */
export interface RecordTypes {
  Genesis: Genesis;
  Update: Update;
  Fork: Fork;
  Retire: Retire;
  Delegation: Delegation;
  Revocation: Revocation;
  Lineage: Lineage;
  Collective: Collective;
  Intent: Intent;
  Offer: Offer;
  Commitment: Commitment;
  Receipt: Receipt;
  Packet: Packet;
  Entry: Entry;
  Checkpoint: Checkpoint;
  Ack: Ack;
  QueryResult: QueryResult;
  Forwarded: Forwarded;
  Location: Location;
  Participant: Participant;
  Hello: Hello;
  Session: Session;
  Resume: Resume;
  Branch: Branch;
  Bundle: Bundle;
  LogPage: LogPage;
  FeedPage: FeedPage;
  DuplicityEvidence: DuplicityEvidence;
  Sealed: Sealed;
}

// The interface above and the schemas below must list the same types.
type SchemaTypes = { [K in keyof typeof recordSchemas]: Static<(typeof recordSchemas)[K]> };
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never;
true satisfies Same<RecordTypes, SchemaTypes>;

/** The name of a record type this revision defines. */
export type RecordType = keyof RecordTypes;

/** The static type of the record called `K`, as it stands after validation and before verification. */
export type RecordOf<K extends RecordType> = RecordTypes[K];

/** Any record this revision defines. */
export type OipRecord = RecordTypes[RecordType];

export const RECORD_TYPES = Object.freeze(Object.keys(recordSchemas) as RecordType[]);

/** core 11: `Merge` is reserved. A log that contains one is rejected (Layer 1, 3.9). */
export const RESERVED_RECORD_TYPES = Object.freeze(["Merge"] as const);

/** core 11: records that never carry `proof`. */
export const UNSIGNED_RECORD_TYPES = Object.freeze([
  "Session",
  "Resume",
  "Branch",
  "Bundle",
  "LogPage",
  "FeedPage",
  "DuplicityEvidence",
  "Sealed",
] as const satisfies readonly RecordType[]);

/** core 1.6: containers. The size limit applies to each record they contain. */
export const CONTAINER_RECORD_TYPES = Object.freeze([
  "Bundle",
  "LogPage",
  "FeedPage",
  "DuplicityEvidence",
] as const satisfies readonly RecordType[]);

/** Layer 1, 3.1: the events of an identity log. */
export const IDENTITY_EVENT_TYPES = Object.freeze([
  "Genesis",
  "Update",
  "Fork",
  "Retire",
] as const satisfies readonly RecordType[]);

/** core 11: records that carry `proof`. */
export const SIGNED_RECORD_TYPES = Object.freeze(
  RECORD_TYPES.filter((type) => !(UNSIGNED_RECORD_TYPES as readonly string[]).includes(type)),
);

/** Whether `name` is a record type this revision defines. */
export function isRecordType(name: unknown): name is RecordType {
  return typeof name === "string" && Object.hasOwn(recordSchemas, name);
}

/** The clause that defines each record type, cited when a record does not match its schema. */
export const DEFINING_CLAUSE: Readonly<Record<RecordType, string>> = Object.freeze({
  Genesis: "L1 3.6",
  Update: "L1 3.7",
  Fork: "L1 3.8",
  Retire: "L1 3.10",
  Delegation: "L1 11.1",
  Revocation: "L1 11.5",
  Lineage: "L1 8.3",
  Collective: "L2 6.2",
  Intent: "L2 4.1",
  Offer: "L2 4.2",
  Commitment: "L2 5.1",
  Receipt: "L2 6.1",
  Packet: "L1 12.1",
  Entry: "L1 10.1",
  Checkpoint: "L1 10.5",
  Ack: "L1 13.2",
  QueryResult: "L1 18.3",
  Forwarded: "L1 18.5",
  Location: "L1 15.1",
  Participant: "L1 16.1",
  Hello: "L1 13.3",
  Session: "L1 14.1",
  Resume: "L1 14.4",
  Branch: "L1 14.5",
  Bundle: "L1 13.1",
  LogPage: "L1 13.1",
  FeedPage: "L1 13.1",
  DuplicityEvidence: "L1 17.1",
  Sealed: "L1 12.6",
});
