// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The adapter for this repository's implementation. It grows with each milestone. */

import {
  canonicalize,
  checkSize,
  contentId,
  createProofSync,
  type Instant,
  keyHash,
  parseJson,
  parseTimestamp,
  proofDigest,
  type ProofOptions,
  signerFromPrivateKey,
  verifyProof,
} from "@oip/core";
import {
  didDocument,
  type EvidenceView,
  judgeRecord,
  lineage,
  LogBook,
  ownSignedTime,
} from "@oip/identity";
import { isRecordType, validateExtensionRecord, validateRecord } from "@oip/schema";

import { type ConformanceAdapter, NOT_JUDGED, type VerifierView } from "./adapter.ts";
import type { JsonObject } from "./vectors.ts";

/**
 * The vectors take the verifier to hold every log in full (the `assumption`
 * member of the vectors). A log held as of the last instant a timestamp can
 * name lacks no later event.
 */
const ALWAYS = parseTimestamp("9999-12-31T23:59:59.999999999Z") ?? 0n;

const EVENT_TYPES: readonly unknown[] = ["Genesis", "Update", "Fork", "Retire"];

/**
 * The convention of the vectors, which is not a rule of the protocol: unless
 * `seen` names it, each proof and each identity event was obtained at its own
 * `created`, as by a witness that followed everything from the start. A live
 * verifier never assumes this: it records what it saw, and when.
 *
 * @param held - Everything the verifier holds or is asked about: the proofs
 *   and events found anywhere inside are given their conventional times.
 */
function assumedEvidence(held: unknown, seen: Readonly<Record<string, string>> = {}): EvidenceView {
  const times = new Map<string, Instant>();
  const note = (name: () => string, created: unknown): void => {
    const time = parseTimestamp(created);
    if (time === undefined) return;
    try {
      times.set(name(), time);
    } catch {
      // What has no digest or content ID has no evidence either.
    }
  };
  const walk = (value: unknown): void => {
    if (Array.isArray(value)) {
      value.forEach(walk);
    } else if (typeof value === "object" && value !== null) {
      const object = value as JsonObject;
      if (EVENT_TYPES.includes(object["type"])) note(() => contentId(object), object["created"]);
      const proofs = object["proof"];
      if (Array.isArray(proofs)) {
        for (const proof of proofs as unknown[]) {
          if (typeof proof === "object" && proof !== null) {
            note(() => proofDigest(proof), (proof as JsonObject)["created"]);
          }
        }
      }
      Object.values(object).forEach(walk);
    }
  };
  walk(held);
  for (const [name, time] of Object.entries(seen)) {
    const instant = parseTimestamp(time);
    if (instant !== undefined) times.set(name, instant);
  }
  return { proofSeen: (digest) => times.get(digest), eventSeen: (id) => times.get(id) };
}

/** The logs and the evidence of a verifier's view, with the subject it is asked about. */
function bookFor(view: VerifierView, subject: unknown): LogBook {
  const book = new LogBook(assumedEvidence([view, subject], view.seen));
  for (const log of [...view.logs, ...view.extraLogs]) book.hold(log, ALWAYS);
  for (const log of view.branches) book.holdBranch(log, ALWAYS);
  return book;
}

/** Whether any proof on a record names an authority: a delegation, or a charter role. */
function namesAuthority(record: JsonObject): boolean {
  const proofs = record["proof"];
  return (
    Array.isArray(proofs) &&
    proofs.some((proof) => typeof proof === "object" && proof !== null && "authority" in proof)
  );
}

/**
 * The reference implementation, as far as it is built. Kinds of case it does
 * not answer yet are reported as pending.
 */
export const referenceAdapter: ConformanceAdapter = {
  name: "OIP reference implementation (TypeScript)",
  recordIsWellFormed: (record) => {
    // A type this revision defines, or one an extension defines (core 7).
    const validated = isRecordType((record as { type?: unknown } | null)?.type)
      ? validateRecord(record)
      : validateExtensionRecord(record);
    return validated.ok && checkSize(validated.value).length === 0;
  },
  jsonIsWithinProfile: (text) => parseJson(text).ok,
  logVerifies: (log, view) => {
    const book = bookFor(view, log);
    // The log asked about takes the place of any log the view holds for the same mind.
    const mind = book.hold(log, ALWAYS);
    return mind.ok && book.log(mind.value).ok;
  },
  countsFor: (record, mind, view) => {
    // Signing through a delegation or a charter role is judged from M3 on.
    if (namesAuthority(record)) return NOT_JUDGED;
    const judged = judgeRecord(record);
    return judged.ok && ownSignedTime(judged.value, mind, bookFor(view, record)) !== undefined;
  },
  lineage: (child, view) => {
    const book = bookFor(view, undefined);
    const log = book.log(child);
    if (!log.ok) return {};
    const records = [...view.records, ...view.extraRecords].flatMap((record) => {
      const judged = judgeRecord(record);
      return judged.ok ? [judged.value] : [];
    });
    return Object.fromEntries(
      lineage(log.value, book, records).map((parent) => [parent.mind, parent.status]),
    );
  },
  didDocument: (mind, versionId, view) => {
    const log = bookFor(view, undefined).log(mind);
    if (!log.ok) return undefined;
    const resolved = didDocument(log.value, versionId === undefined ? {} : { versionId });
    return resolved.ok ? resolved.value : undefined;
  },
  canonicalize,
  contentId,
  keyHash,
  createProof: (record, request, privateKey) =>
    createProofSync(record, request as ProofOptions, signerFromPrivateKey(privateKey)),
  proofVerifies: (record, proof) => verifyProof(record, proof).ok,
};
