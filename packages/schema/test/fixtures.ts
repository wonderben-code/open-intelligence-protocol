// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * One well-formed sample of every record type. Most come from the test
 * vectors. The types the vectors do not contain are assembled here from
 * vector records; their proofs are not valid signatures, which validation
 * does not look at.
 */

import { copy, type JsonObject, readVectors } from "@oip/testkit";

import type { RecordType } from "../src/index.ts";

const cases = readVectors().cases as Record<string, JsonObject> & Record<string, JsonObject[]>;

function fromCases(name: string): JsonObject {
  const value: unknown = cases[name];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`the vectors have no record called ${name}`);
  }
  return copy(value as JsonObject);
}

function event(log: string, index: number): JsonObject {
  const events: unknown = cases[log];
  const found: unknown = Array.isArray(events) ? events[index] : undefined;
  if (typeof found !== "object" || found === null) throw new Error(`no event ${log}[${index}]`);
  return copy(found as JsonObject);
}

export const AMINA = cases["amina"] as unknown as string;
export const LEXIS_AGENT = cases["lexis_agent"] as unknown as string;
export const CID = "bciqmwrzo6zt2xnoga2rkp77b7p2yicceqwiljl2d7dxoa4xpiugbgna";
export const OTHER_CID = "bciqm33shzk5mxdmurer5ezyl6ohbsc6n54b4hisoodgwx6cgvcazuui";
export const T0 = "2026-10-30T09:00:00Z";

const aminaUpdate = event("amina_log", 1);
const proof = (aminaUpdate["proof"] as JsonObject[])[0]!;
const controlKey = ((aminaUpdate["controller"] as JsonObject)["keys"] as string[])[0]!;
const agreementKey = (event("amina_log", 0)["agreement"] as JsonObject[])[0]!["key"] as string;

/** A well-formed record of each type. */
export const samples: Readonly<Record<RecordType, JsonObject>> = {
  Genesis: event("amina_log", 0),
  Update: aminaUpdate,
  Fork: event("lexis_agent_log", 1),
  Retire: {
    ...aminaUpdate,
    type: "Retire",
    controller: { keys: [controlKey], next: [] },
    reason: "Moved to a new address.",
  },
  Delegation: fromCases("delegation"),
  Revocation: {
    oip: "1",
    type: "Revocation",
    author: AMINA,
    revokes: `${AMINA}/${CID}`,
    created: T0,
    proof: [proof],
  },
  Lineage: fromCases("lineage"),
  Collective: fromCases("collective_charter"),
  Intent: fromCases("intent"),
  Offer: fromCases("offer"),
  Commitment: fromCases("commitment_accepted"),
  Receipt: fromCases("receipt"),
  Packet: fromCases("packet"),
  Entry: fromCases("feed_entry_1"),
  Checkpoint: fromCases("checkpoint"),
  Ack: fromCases("ack"),
  QueryResult: {
    oip: "1",
    type: "QueryResult",
    author: LEXIS_AGENT,
    created: T0,
    query: { want: "legal translation", tags: ["lang:ar"], limit: 5 },
    results: [
      { mind: AMINA, record: CID, capability: "translate", score: "0.87", why: "matches tags" },
    ],
    proof: [proof],
  },
  Forwarded: {
    oip: "1",
    type: "Forwarded",
    broker: LEXIS_AGENT,
    to: AMINA,
    packet: fromCases("packet"),
    created: T0,
    proof: [proof],
  },
  Location: fromCases("location"),
  Participant: fromCases("participant"),
  Hello: fromCases("hello"),
  Session: fromCases("session"),
  Resume: {
    oip: "1",
    type: "Resume",
    session: CID,
    lastSent: { seq: 3, packet: CID },
    lastReceived: [{ mind: LEXIS_AGENT, seq: 2, packet: OTHER_CID, instance: "laptop" }],
    created: T0,
  },
  Branch: {
    oip: "1",
    type: "Branch",
    parentSession: CID,
    fork: `${LEXIS_AGENT}?versionId=1-${CID}`,
    created: T0,
  },
  Bundle: {
    oip: "1",
    type: "Bundle",
    mind: LEXIS_AGENT,
    log: [event("lexis_agent_log", 0), event("lexis_agent_log", 1)],
    location: fromCases("location"),
    participant: fromCases("participant"),
    firstSeen: { [CID]: T0, [`sha256:${"ab".repeat(32)}`]: "2026-10-30T09:00:00.5Z" },
  },
  LogPage: {
    oip: "1",
    type: "LogPage",
    mind: AMINA,
    events: [event("amina_log", 0), aminaUpdate],
    next: 1,
  },
  FeedPage: {
    oip: "1",
    type: "FeedPage",
    mind: LEXIS_AGENT,
    entries: [fromCases("feed_entry"), fromCases("feed_entry_1")],
  },
  DuplicityEvidence: {
    oip: "1",
    type: "DuplicityEvidence",
    mind: AMINA,
    pairs: [[aminaUpdate, { ...aminaUpdate, created: "2026-11-01T00:00:00Z" }]],
  },
  Sealed: {
    oip: "1",
    type: "Sealed",
    to: AMINA,
    key: agreementKey,
    suite: "hpke-base-x25519-sha256-chacha20poly1305",
    enc: "3q2-7w",
    ciphertext: "AAECAwQFBgcICQ",
  },
};

/** A fresh copy of the sample of `type`, with `changes` applied on top. */
export function sample(type: RecordType, changes: JsonObject = {}): JsonObject {
  return { ...copy(samples[type]), ...changes };
}

/** A copy of `record` without the member `name`. */
export function without(record: JsonObject, name: string): JsonObject {
  const { [name]: _removed, ...rest } = record;
  return rest;
}

/** A well-formed proof, from the vectors. */
export function sampleProof(changes: JsonObject = {}): JsonObject {
  return { ...copy(proof), ...changes };
}

/** A proof whose `authority` carries an inline Delegation, from the vectors. */
export function delegatedProof(): JsonObject {
  const proofs = fromCases("commitment_accepted")["proof"] as JsonObject[];
  const found = proofs.find((candidate) => candidate["authority"] !== undefined);
  if (found === undefined) throw new Error("the vectors have no delegated proof");
  return copy(found);
}
