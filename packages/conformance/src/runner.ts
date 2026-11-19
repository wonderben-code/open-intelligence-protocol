// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Runs the golden vectors against an implementation, case by case. */

import { patterns } from "@oip/schema";

import {
  type ConformanceAdapter,
  METHOD_FOR_KIND,
  type ProofRequest,
  type VerifierView,
} from "./adapter.ts";
import {
  type CaseKind,
  type JsonObject,
  namedLog,
  namedRecord,
  positiveRecords,
  type Section,
  SECTIONS,
  type VectorCase,
  type Vectors,
} from "./vectors.ts";

/**
 * `pass`: the implementation gave the required verdict. `fail`: it did not.
 * `pending`: the adapter does not implement what the case needs yet.
 */
export type Outcome = "pass" | "fail" | "pending";

export interface CaseResult {
  readonly section: Section | "positive";
  readonly kind: CaseKind | "reproduce";
  readonly name: string;
  readonly outcome: Outcome;
  /** For a failure, what was required and what happened. */
  readonly detail?: string;
}

/** The verifier's view for a case: the baseline plus what the case adds. */
export function viewFor(vectors: Vectors, vectorCase: VectorCase): VerifierView {
  return {
    logs: vectors.baseline.logs.map((name) => namedLog(vectors, name)),
    extraLogs: vectorCase.extraLogs ?? [],
    branches: vectorCase.branches ?? [],
    records: vectors.baseline.records.map((name) => namedRecord(vectors, name)),
    extraRecords: vectorCase.extraRecords ?? [],
    seen: vectorCase.seen,
  };
}

/**
 * Whether a case's claim holds for the implementation: the log verifies, the
 * record counts for (or was sent for) the mind, the status or assurance is
 * the one expected, the record is well formed, or the text is JSON within
 * the profile. `undefined` when the adapter lacks the method the case needs.
 *
 * It lets an exception from the adapter through. A verifier judges hostile
 * input and answers; one that throws has not answered, and must never pass a
 * negative case by crashing on it.
 */
export function claimHolds(
  adapter: ConformanceAdapter,
  vectors: Vectors,
  vectorCase: VectorCase,
): boolean | undefined {
  if (adapter[METHOD_FOR_KIND[vectorCase.kind]] === undefined) return undefined;
  const view = viewFor(vectors, vectorCase);
  switch (vectorCase.kind) {
    case "log":
      return verdict(adapter.logVerifies?.(vectorCase.log, view));
    case "countsFor":
      return verdict(adapter.countsFor?.(vectorCase.record, vectorCase.mind, view));
    case "sentFor":
      return verdict(adapter.sentFor?.(vectorCase.record, vectorCase.mind, view));
    case "status":
      return (
        named(adapter.status?.(vectorCase.of, vectorCase.records, vectorCase.at, view)) ===
        vectorCase.expect
      );
    case "assurance":
      return named(adapter.assurance?.(vectorCase.record, view)) === vectorCase.expect;
    case "record":
      return verdict(adapter.recordIsWellFormed?.(vectorCase.record));
    case "json":
      return verdict(adapter.jsonIsWithinProfile?.(vectorCase.text));
  }
}

/**
 * An answer must be exactly `true` or `false`. Anything else (`undefined`
 * from a method that forgot to return, a truthy object) is not a verdict,
 * and reading it as "rejected" would pass the negative cases.
 */
function verdict(answer: unknown): boolean {
  if (typeof answer !== "boolean") {
    throw new TypeError(`the adapter answered ${describe(answer)}, not true or false`);
  }
  return answer;
}

function named(answer: unknown): string {
  if (typeof answer !== "string") {
    throw new TypeError(`the adapter answered ${describe(answer)}, not a string`);
  }
  return answer;
}

function describe(answer: unknown): string {
  if (answer === null || answer === undefined) return String(answer);
  return typeof answer === "object" ? "an object" : `a ${typeof answer}`;
}

/**
 * Whether a case requires its claim to hold. Must-accept cases and controls
 * do. A negative case requires it not to hold, except for `status` and
 * `assurance` cases, whose `expect` already is the safe result (not the one
 * an attacker wanted).
 */
export function claimMustHold(section: Section, kind: CaseKind): boolean {
  return section !== "negative" || kind === "status" || kind === "assurance";
}

/** Runs one case. An adapter that throws fails the case, whatever the case requires. */
export function runCase(
  adapter: ConformanceAdapter,
  vectors: Vectors,
  section: Section,
  vectorCase: VectorCase,
): CaseResult {
  const base = { section, kind: vectorCase.kind, name: vectorCase.name };
  let holds: boolean | undefined;
  try {
    holds = claimHolds(adapter, vectors, vectorCase);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ...base, outcome: "fail", detail: `the implementation threw: ${message}` };
  }
  if (holds === undefined) return { ...base, outcome: "pending" };
  const required = claimMustHold(section, vectorCase.kind);
  if (holds === required) return { ...base, outcome: "pass" };
  const wanted = required ? "accepted" : "rejected";
  const reason = vectorCase.reason === undefined ? "" : ` ${vectorCase.reason}`;
  return { ...base, outcome: "fail", detail: `must be ${wanted}.${reason}` };
}

const CONTENT_ID = new RegExp(patterns.contentId);

/** Every string in the vectors that has the shape of a content ID, wherever it stands. */
function contentIdsIn(value: unknown, found = new Set<string>()): Set<string> {
  if (typeof value === "string") {
    for (const match of value.matchAll(/\bb[a-z2-7]{55}\b/g)) found.add(match[0]);
  } else if (Array.isArray(value)) {
    for (const item of value) contentIdsIn(item, found);
  } else if (typeof value === "object" && value !== null) {
    for (const member of Object.values(value)) contentIdsIn(member, found);
  }
  return found;
}

const eventOf = (log: string, position: number) => (vectors: Vectors) =>
  namedLog(vectors, log)[position] ?? {};
const recordOf = (name: string) => (vectors: Vectors) => namedRecord(vectors, name);

/** The record each name in `cases.content_ids` is the content ID of. */
const CONTENT_ID_SOURCES: Readonly<Record<string, (vectors: Vectors) => JsonObject>> = {
  amina_genesis: eventOf("amina_log", 0),
  amina_update: eventOf("amina_log", 1),
  delegation: recordOf("delegation"),
  delegation_sub: recordOf("delegation_sub"),
  delegation_amina: recordOf("delegation_amina"),
  intent: recordOf("intent"),
  offer: recordOf("offer"),
  commitment: recordOf("commitment_proposed"),
  commitment_agents: recordOf("commitment_agents"),
  receipt: recordOf("receipt"),
  collective_charter: recordOf("collective_charter"),
  session: recordOf("session"),
  packet: recordOf("packet"),
  checkpoint: recordOf("checkpoint"),
  bridged_genesis: eventOf("bridged_log", 0),
};

/** The negative cases whose record carries a proof that must not verify, whoever it is for. */
const BAD_PROOF_CASES = ["signature-s-not-reduced", "signature-r-identity", "wrong-proof-purpose"];

/** Every identity log of the positive part, by name. A log `x_log` belongs to the mind named `x`. */
function logsOf(vectors: Vectors): [name: string, log: readonly JsonObject[]][] {
  return Object.keys(vectors.cases)
    .filter((name) => name.endsWith("_log"))
    .map((name) => [name, namedLog(vectors, name)]);
}

function controllerOf(event: JsonObject | undefined): JsonObject | undefined {
  const controller = event?.["controller"];
  return typeof controller === "object" && controller !== null
    ? (controller as JsonObject)
    : undefined;
}

function proofsOf(record: JsonObject): readonly JsonObject[] {
  const proofs = record["proof"];
  return Array.isArray(proofs) ? (proofs as readonly JsonObject[]) : [];
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from({ length: hex.length / 2 }, (_, i) =>
    Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16),
  );
}

/** Whether two JSON values are equal, whatever the order of their members. */
function sameMembers(a: unknown, b: unknown): boolean {
  if (typeof a !== "object" || a === null || typeof b !== "object" || b === null) return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((item, i) => sameMembers(item, b[i]))
    );
  }
  const names = Object.keys(a);
  return (
    names.length === Object.keys(b).length &&
    names.every(
      (name) =>
        Object.hasOwn(b, name) && sameMembers((a as JsonObject)[name], (b as JsonObject)[name]),
    )
  );
}

/** One check of the positive part of the vectors: values an implementation must reproduce. */
export interface PositiveCheck {
  readonly name: string;
  /** The milestone of the reference implementation in which the check turns green. */
  readonly milestone: string;
  /** Returns `undefined` when the adapter cannot run it yet, or a list of mismatches (empty for a pass). */
  run(adapter: ConformanceAdapter, vectors: Vectors): string[] | undefined;
}

const later = (name: string, milestone: string): PositiveCheck => ({
  name,
  milestone,
  run: () => undefined,
});

/**
 * The checks of the positive part, in the order of the Python checker's
 * `check()`. Those that need parts of the implementation that do not exist
 * yet are pending, and name the milestone that fills them in.
 */
export const POSITIVE_CHECKS: readonly PositiveCheck[] = [
  {
    name: "every record in the positive vectors is well formed",
    milestone: "M0",
    run(adapter, vectors) {
      if (adapter.recordIsWellFormed === undefined) return undefined;
      return positiveRecords(vectors)
        .filter(({ record }) => adapter.recordIsWellFormed?.(record) !== true)
        .map(({ name }) => `${name} was rejected`);
    },
  },
  {
    name: "JCS example",
    milestone: "M1",
    run(adapter, vectors) {
      if (adapter.canonicalize === undefined) return undefined;
      const example = vectors.cases["jcs_example"] as { input: unknown; output: string };
      const got = adapter.canonicalize(example.input);
      return got === example.output ? [] : [`expected ${example.output}, got ${got}`];
    },
  },
  {
    name: "content IDs use the canonical spelling and reproduce",
    milestone: "M1",
    run(adapter, vectors) {
      const contentId = adapter.contentId?.bind(adapter);
      if (contentId === undefined) return undefined;
      const mismatches: string[] = [];
      for (const id of contentIdsIn([vectors.cases, vectors.valid, vectors.controls])) {
        if (!CONTENT_ID.test(id)) mismatches.push(`${id} is not in the canonical spelling`);
      }
      const expected = vectors.cases["content_ids"] as Readonly<Record<string, string>>;
      for (const [name, id] of Object.entries(expected)) {
        const source = CONTENT_ID_SOURCES[name];
        if (source === undefined) {
          mismatches.push(`content_ids.${name}: this suite does not know which record it names`);
          continue;
        }
        const got = contentId(source(vectors));
        if (got !== id) mismatches.push(`content_ids.${name}: expected ${id}, got ${got}`);
      }
      for (const [name, log] of logsOf(vectors)) {
        const address = vectors.cases[name.slice(0, -"_log".length)];
        const got = `did:oip:${contentId(log[0] ?? {})}`;
        if (got !== address) mismatches.push(`${name}: the address should be ${got}`);
        log.forEach((event, i) => {
          const previous = log[i - 1];
          if (previous !== undefined && event["prev"] !== contentId(previous)) {
            mismatches.push(`${name}[${i}].prev is not the content ID of the event before it`);
          }
        });
      }
      return mismatches;
    },
  },
  {
    name: "key hashes reproduce: every revealed control key was committed to",
    milestone: "M1",
    run(adapter, vectors) {
      const keyHash = adapter.keyHash?.bind(adapter);
      if (keyHash === undefined) return undefined;
      const mismatches: string[] = [];
      for (const [name, log] of logsOf(vectors)) {
        log.forEach((event, i) => {
          const committed = controllerOf(log[i - 1])?.["next"];
          const revealed = controllerOf(event)?.["keys"];
          if (!Array.isArray(committed) || !Array.isArray(revealed)) return;
          for (const key of revealed as readonly string[]) {
            if (!committed.includes(keyHash(key))) {
              mismatches.push(`${name}[${i}]: the hash of ${key} is not in the event before`);
            }
          }
        });
      }
      return mismatches;
    },
  },
  {
    name: "every proofValue reproduces from its test key",
    milestone: "M1",
    run(adapter, vectors) {
      const createProof = adapter.createProof?.bind(adapter);
      if (createProof === undefined) return undefined;
      const seeds = new Map(
        Object.values(vectors.keys).map((key) => [key.multikey, hexToBytes(key.seed_hex)]),
      );
      const mismatches: string[] = [];
      for (const { name, record } of positiveRecords(vectors)) {
        proofsOf(record).forEach((proof, i) => {
          const { verificationMethod, created, challenge, domain, authority } = proof as Readonly<
            Record<string, unknown>
          > &
            ProofRequest;
          const seed = seeds.get(verificationMethod.split("#")[1] ?? "");
          if (seed === undefined) {
            mismatches.push(`${name} proof ${i}: the vectors have no test key for it`);
            return;
          }
          const request: ProofRequest = {
            verificationMethod,
            created,
            ...(challenge === undefined ? {} : { challenge }),
            ...(domain === undefined ? {} : { domain }),
            ...(authority === undefined ? {} : { authority }),
          };
          const got = createProof(record, request, seed);
          if (got["proofValue"] !== proof["proofValue"] || !sameMembers(got, proof)) {
            mismatches.push(`${name} proof ${i} was not reproduced`);
          }
        });
      }
      return mismatches;
    },
  },
  {
    name: "proofs verify, and signatures that break core 4.4 do not",
    milestone: "M1",
    run(adapter, vectors) {
      const proofVerifies = adapter.proofVerifies?.bind(adapter);
      if (proofVerifies === undefined) return undefined;
      const mismatches: string[] = [];
      for (const { name, record } of positiveRecords(vectors)) {
        proofsOf(record).forEach((proof, i) => {
          if (!verdict(proofVerifies(record, proof))) {
            mismatches.push(`${name} proof ${i} did not verify`);
          }
        });
      }
      for (const name of BAD_PROOF_CASES) {
        const found = vectors.negative.find((entry) => entry.name === name);
        const record = found !== undefined && "record" in found ? found.record : undefined;
        if (typeof record !== "object" || record === null) {
          mismatches.push(`the vectors have no negative case ${name}`);
          continue;
        }
        proofsOf(record as JsonObject).forEach((proof, i) => {
          if (verdict(proofVerifies(record as JsonObject, proof))) {
            mismatches.push(`${name}: proof ${i} verified, and must not`);
          }
        });
      }
      return mismatches;
    },
  },
  later("identity logs verify; addresses derive from genesis", "M2"),
  later("2-of-3 pre-rotation with distinct keys", "M2"),
  later("lineage acknowledged by a Fork event and by a Lineage record", "M2"),
  later("signatures count for their authors (purpose and key checks)", "M2"),
  later("DID documents, current and versioned", "M2"),
  later("packet sent on Amina's behalf under a /oip/send delegation", "M3"),
  later("co-signing keeps the content ID; delegated party proof", "M3"),
  later("two agents sign for their principals, in either order", "M3"),
  later("delegation policy enforced (120, 500 ok; 500.01, 900 not)", "M3"),
  later("two-step delegation chain (150 ok; 300 beyond the sub-limit)", "M3"),
  later("collective signs by 2-of-3 threshold and by a charter role", "M3"),
  later("Layer 2 status (every state of Intent, Offer and Commitment)", "M3"),
  later("feed entries commit to proofs; checkpoint Merkle root", "M4"),
  later("packet opens its session; Ack names the packet", "M4"),
  later("a bridged mind, attested in its gateway's feed", "M9"),
];

function runPositive(
  check: PositiveCheck,
  adapter: ConformanceAdapter,
  vectors: Vectors,
): CaseResult {
  const base = { section: "positive", kind: "reproduce", name: check.name } as const;
  let mismatches: string[] | undefined;
  try {
    mismatches = check.run(adapter, vectors);
  } catch (error) {
    mismatches = [`threw ${error instanceof Error ? error.message : String(error)}`];
  }
  if (mismatches === undefined) return { ...base, outcome: "pending" };
  if (mismatches.length === 0) return { ...base, outcome: "pass" };
  return { ...base, outcome: "fail", detail: mismatches.join("; ") };
}

/** Runs every positive check and every case. */
export function runVectors(adapter: ConformanceAdapter, vectors: Vectors): CaseResult[] {
  return [
    ...POSITIVE_CHECKS.map((check) => runPositive(check, adapter, vectors)),
    ...SECTIONS.flatMap((section) =>
      vectors[section].map((vectorCase) => runCase(adapter, vectors, section, vectorCase)),
    ),
  ];
}

/** How many results had each outcome. */
export function tally(results: readonly CaseResult[]): Record<Outcome, number> {
  const counts: Record<Outcome, number> = { pass: 0, fail: 0, pending: 0 };
  for (const result of results) counts[result.outcome]++;
  return counts;
}
