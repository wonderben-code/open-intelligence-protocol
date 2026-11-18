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
  mindAddress,
  parseJson,
  parseTimestamp,
  proofDigest,
  type ProofOptions,
  signerFromPrivateKey,
  verifyProof,
} from "@oip/core";
import { RecordSet, sentFor } from "@oip/delegation";
import {
  didDocument,
  type EvidenceView,
  FirstSeen,
  judgeRecord,
  lineage,
  LogBook,
  verifyLog,
  witnessLog,
} from "@oip/identity";
import {
  isRecordType,
  validateExtensionRecord,
  validateRecord,
  type Validation,
} from "@oip/schema";
import { countsFor } from "@oip/web";

import { type ConformanceAdapter, type VerifierView } from "./adapter.ts";
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

/**
 * Holds a log in place of whatever the book holds for its mind. A case's
 * `extraLogs`, and the log it asks about, replace the baseline's logs of the
 * same minds, an earlier state of one among them. A verifier never goes back
 * like that (Layer 1, 4.9), so `hold` alone refuses to.
 */
function replace(book: LogBook, log: unknown): Validation<string> {
  try {
    book.drop(mindAddress(contentId((log as readonly unknown[])[0])));
  } catch {
    // What has no genesis names no mind, and `hold` says so.
  }
  return book.hold(log, ALWAYS);
}

/** The logs and the evidence of a verifier's view, with the subject it is asked about. */
function bookFor(view: VerifierView, subject: unknown): LogBook {
  const book = new LogBook(assumedEvidence([view, subject], view.seen));
  for (const log of [...view.logs, ...view.extraLogs]) replace(book, log);
  for (const log of view.branches) book.hold(log, ALWAYS);
  return book;
}

/** The records of a verifier's view, each held with every proof that verified. */
function recordsOf(view: VerifierView): RecordSet {
  const records = new RecordSet();
  for (const record of [...view.records, ...view.extraRecords]) records.add(record);
  return records;
}

/**
 * The reference implementation, as far as it is built. Kinds of case it does
 * not answer yet are reported as pending.
 *
 * It is a test harness, and it answers under the convention of the vectors:
 * where a case gives no evidence, every proof and event is taken as seen at
 * its own `created`, and every log as known in full. That is how the vectors
 * are written. It is the one thing a verifier must never assume of anything
 * that arrives from outside (core 9.2), so nothing but a conformance test
 * should call this adapter. A verifier uses `@oip/identity` with its own
 * evidence.
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
    // The log as it stands (Layer 1, Section 4). A book would answer with
    // the events before an invalid event; the question here is the log's.
    const book = bookFor(view, log);
    return verifyLog(log, {
      evidence: book.evidence,
      asOf: ALWAYS,
      memberLog: (mind) => book.log(mind),
    }).ok;
  },
  logIntake: (log, view) => {
    const book = bookFor(view, log);
    // Nothing is recorded that matters: the view's evidence already has a time for every event.
    const witnessed = witnessLog(log, ALWAYS, new FirstSeen(), {
      evidence: book.evidence,
      memberLog: (mind) => book.log(mind),
    });
    return {
      verified: witnessed.log?.entries.length ?? 0,
      undecided: witnessed.failure === undefined ? null : witnessed.undecided,
    };
  },
  countsFor: (record, mind, view) => {
    const judged = judgeRecord(record);
    if (!judged.ok) return false;
    return countsFor(judged.value, mind, {
      identity: bookFor(view, record),
      records: recordsOf(view),
    });
  },
  sentFor: (packet, mind, view) => {
    const judged = judgeRecord(packet);
    if (!judged.ok) return false;
    const context = { identity: bookFor(view, packet), records: recordsOf(view) };
    return sentFor(judged.value, mind, context) !== undefined;
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
