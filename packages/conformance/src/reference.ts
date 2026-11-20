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
  type JudgedRecord,
  judgeRecord,
  lineage,
  LogBook,
  ownSignedTime,
  verifyLog,
  witnessLog,
} from "@oip/identity";
import {
  ackEvidence,
  currentLocation,
  currentParticipant,
  type ReceivedPacket,
  receivePacket,
  Sessions,
  verifyAck,
  verifyCheckpoint,
  verifyFeed,
  verifyHello,
} from "@oip/net";
import {
  isRecordType,
  type Packet,
  validateExtensionRecord,
  validateRecord,
  type Validation,
} from "@oip/schema";
import {
  assuranceOf,
  BRIDGE_BLOCK,
  countsFor,
  status,
  type WebRecords,
  WebRecordSet,
} from "@oip/web";

import {
  type ChainReading,
  type ConformanceAdapter,
  type NetworkAnswer,
  type VerifierView,
} from "./adapter.ts";
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

const SECOND = 1_000_000_000n;
const HOUR = 3600n * SECOND;

/** The records among `values` that are well formed, each as judged. */
function judgedAmong(values: readonly unknown[]): JudgedRecord[] {
  return values.flatMap((value) => {
    const judged = judgeRecord(value);
    return judged.ok ? [judged.value] : [];
  });
}

/** An answer whose claim holds when there is a value. */
function found<T>(value: T | undefined): NetworkAnswer<T | null> {
  return { holds: value !== undefined, value: value ?? null };
}

/** In the order of code points, as the Python checker sorts. */
function inOrder(strings: Iterable<string>): string[] {
  return [...strings].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/** The content ID of a value, if it has one. */
function idOf(value: unknown): string | undefined {
  try {
    return contentId(value);
  } catch {
    // A value with no canonical form is no record.
    return undefined;
  }
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
  status: (of, records, at, view) => {
    const judged = judgeRecord(of);
    const time = parseTimestamp(at);
    if (!judged.ok || time === undefined) return "";
    // As the vectors put the question: the records given are the copies the verifier
    // holds of them, and what refers to the record asked about is looked for among them.
    // What a record refers to besides is looked up in the rest of what the verifier holds.
    const held = recordsOf(view);
    const given = new WebRecordSet();
    for (const record of records) given.add(record);
    const known: WebRecords = {
      record: (id) => given.record(id) ?? held.record(id),
      revocationsOf: (id) => held.revocationsOf(id),
      chartersOf: (mind) => held.chartersOf(mind),
      supersedersOf: (id) => given.supersedersOf(id),
      resolversOf: (id) => given.resolversOf(id),
      receiptsAbout: (id) => given.receiptsAbout(id),
    };
    const answer = status(judged.value, time, {
      identity: bookFor(view, [of, records]),
      records: known,
    });
    return answer.ok ? answer.value : "";
  },
  assurance: (profile, view) => {
    const judged = judgeRecord(profile);
    if (!judged.ok) {
      // What is no record shows nothing. If it declares a bridge, that is a claim and no more.
      const { ext } = profile as { readonly ext?: unknown };
      const declares = typeof ext === "object" && ext !== null && Object.hasOwn(ext, BRIDGE_BLOCK);
      return declares ? "claimed" : "native";
    }
    return assuranceOf(judged.value, {
      identity: bookFor(view, profile),
      records: recordsOf(view),
    });
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
  feed: ({ entries, author }, view) => {
    const feed = verifyFeed(entries, author, bookFor(view, entries));
    if (!feed.ok) return { holds: false, value: { verified: 0, equivocation: [] } };
    const { entries: verified, equivocation, refused } = feed.value;
    const given = new Set(entries.map(idOf));
    return {
      holds: refused.length === 0 && equivocation.length === 0 && verified.length === given.size,
      value: { verified: verified.length, equivocation: equivocation.map((entry) => entry.id) },
    };
  },
  checkpoint: ({ checkpoint, entries }, view) => {
    const book = bookFor(view, [checkpoint, entries]);
    const judged = judgeRecord(checkpoint);
    const author = (checkpoint as { author?: unknown }).author;
    if (!judged.ok || typeof author !== "string") return found<readonly string[]>(undefined);
    const feed = verifyFeed(entries, author, book);
    if (!feed.ok) return found<readonly string[]>(undefined);
    const covered = verifyCheckpoint(judged.value, feed.value, book);
    return found(covered.ok ? inOrder(covered.value.proofs) : undefined);
  },
  receive: ({ arrived, receiver, at, window, holdsChain }, view) => {
    const now = parseTimestamp(at);
    if (now === undefined) return found<{ packet: string; broker: string | null }>(undefined);
    const received = receivePacket(arrived, {
      address: receiver,
      now,
      view: bookFor(view, arrived),
      accepted: () => false,
      window: window === undefined ? HOUR : BigInt(window) * SECOND,
      holdsChain: () => holdsChain === true,
    });
    return found(
      received.ok
        ? { packet: received.value.id, broker: received.value.broker ?? null }
        : undefined,
    );
  },
  chain: ({ session, packets, receiver }, view) => {
    const book = bookFor(view, packets);
    const sessionId = idOf(session);
    const sessions = new Sessions(receiver);
    const chains = new Map<string, { delivered: string[]; waited: Map<string, number> }>();
    let whole = true;
    // Each arrival is judged as it comes. One that is not taken says nothing against the
    // packet, which may come again: the claim is about the packets, by their content IDs.
    for (const value of packets) {
      const judged = judgeRecord(value);
      const packet = judged.ok ? (judged.value.record as Packet) : undefined;
      const time =
        judged.ok && packet?.type === "Packet"
          ? ownSignedTime(judged.value, packet.from, book)
          : undefined;
      if (
        !judged.ok ||
        packet === undefined ||
        time === undefined ||
        packet.session !== sessionId
      ) {
        continue;
      }
      const id = contentId(packet);
      const received: ReceivedPacket = {
        id,
        packet,
        judged: judged.value,
        time,
        duplicate: false,
        forgetAfter: ALWAYS,
        broker: undefined,
      };
      const placed = sessions.take(received);
      if (!placed.ok) continue;
      const key = `${packet.from}#${packet.instance ?? ""}`;
      let chain = chains.get(key);
      if (chain === undefined) {
        chain = { delivered: [], waited: new Map() };
        chains.set(key, chain);
      }
      if (placed.value.kind === "waiting") chain.waited.set(id, packet.seq ?? 0);
      if (placed.value.kind === "in order") {
        for (const one of placed.value.delivered) {
          chain.delivered.push(one.id);
          chain.waited.delete(one.id);
        }
      }
    }
    const value: Record<string, ChainReading> = {};
    for (const key of inOrder(chains.keys())) {
      const chain = chains.get(key);
      if (chain === undefined) continue;
      const [from = "", instance = ""] = key.split("#");
      const equivocation =
        sessionId === undefined
          ? undefined
          : sessions.equivocation({
              session: sessionId,
              from,
              instance: instance === "" ? undefined : instance,
            });
      // What waited at a place the chain has reached was no link, and is kept no longer.
      const ahead = [...chain.waited.values()].filter((seq) => seq > chain.delivered.length);
      value[key] = {
        delivered: chain.delivered,
        equivocation:
          equivocation === undefined
            ? null
            : { seq: equivocation.seq, packets: equivocation.packets },
        ahead: ahead.length,
      };
      if (equivocation !== undefined || ahead.length > 0) whole = false;
    }
    const delivered = new Set(Object.values(value).flatMap((chain) => chain.delivered));
    return {
      holds: whole && packets.every((packet) => delivered.has(idOf(packet) ?? "")),
      value,
    };
  },
  hello: ({ hello, origin, issued, at }, view) => {
    const now = parseTimestamp(at);
    if (now === undefined) return found<string>(undefined);
    const authenticated = verifyHello(hello, {
      origin,
      now,
      view: bookFor(view, hello),
      challenges: {
        issuedAt: (challenge) =>
          Object.hasOwn(issued, challenge) ? parseTimestamp(issued[challenge]) : undefined,
        use: () => undefined,
      },
    });
    return found(authenticated.ok ? authenticated.value.mind : undefined);
  },
  ack: ({ ack, packet }, view) => {
    const verified = verifyAck(ack, { view: bookFor(view, [ack, packet]) });
    const judged = judgeRecord(packet);
    if (!verified.ok || !judged.ok) return found<readonly string[]>(undefined);
    const evidence = ackEvidence(verified.value, judged.value);
    return found(evidence === undefined ? undefined : inOrder(evidence.proofs));
  },
  location: ({ record, records = [] }, view) => {
    const mind = (record as { author?: unknown }).author;
    const all = [record, ...records];
    const current =
      typeof mind === "string"
        ? currentLocation(judgedAmong(all), mind, bookFor(view, all))
        : undefined;
    return {
      holds: current !== undefined && current.id === idOf(record),
      value: current?.id ?? null,
    };
  },
  participant: ({ record, records = [], locations = [], entries = [] }, view) => {
    const mind = (record as { author?: unknown }).author;
    if (typeof mind !== "string") return { holds: false, value: null };
    const book = bookFor(view, [record, records, locations, entries]);
    const feed = verifyFeed(entries, mind, book);
    const current = currentParticipant(judgedAmong([record, ...records]), mind, book, {
      location: currentLocation(judgedAmong(locations), mind, book),
      feed: feed.ok ? feed.value : undefined,
    });
    return {
      holds: current !== undefined && current.id === idOf(record),
      value: current?.id ?? null,
    };
  },
  canonicalize,
  contentId,
  keyHash,
  createProof: (record, request, privateKey) =>
    createProofSync(record, request as ProofOptions, signerFromPrivateKey(privateKey)),
  proofVerifies: (record, proof) => verifyProof(record, proof).ok,
};
