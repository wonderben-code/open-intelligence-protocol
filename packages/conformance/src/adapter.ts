// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** How the suite calls an implementation. */

import type { JsonObject, Log, Seen } from "./vectors.ts";

/**
 * What the verifier holds when it judges a case: the baseline of the vectors,
 * and whatever the case adds. The adapter merges them, because replacing a
 * mind's log means knowing its address, which is the implementation's work.
 */
export interface VerifierView {
  /** The baseline identity logs, one per mind. */
  readonly logs: readonly Log[];
  /** Logs that replace the baseline logs of the same minds. */
  readonly extraLogs: readonly Log[];
  /** Further, conflicting branches of a mind's log (Layer 1, Section 7). */
  readonly branches: readonly Log[];
  /** The baseline records. */
  readonly records: readonly JsonObject[];
  /** Records the case adds. */
  readonly extraRecords: readonly JsonObject[];
  /**
   * Evidence of time (core 9.4), keyed by proof digest or by an identity
   * event's content ID. The map is partial: a proof or an event it does not
   * name is taken to have been obtained at its own `created` time, as a
   * witness that followed every log from the start would have obtained it.
   * When `seen` is `undefined`, that holds for every proof and event.
   */
  readonly seen: Seen | undefined;
}

/**
 * An implementation under test. Every member is optional: a case whose kind
 * the adapter does not implement is reported as `pending`, never as passed.
 *
 * A method answers; it does not throw. A verifier's work is to judge hostile
 * input, so the suite fails any case on which a method throws, including a
 * negative case: crashing on an attack is not rejecting it. If your
 * implementation signals rejection with an exception, catch that exception
 * (and only that one) in the adapter and return `false`.
 */
export interface ConformanceAdapter {
  /** The implementation's name, for reports. */
  readonly name: string;

  /** `record` cases: whether the value is a well-formed record. */
  recordIsWellFormed?(record: unknown): boolean;

  /** `log` cases: whether the identity log verifies (Layer 1, Section 4). */
  logVerifies?(log: Log, view: VerifierView): boolean;

  /** `countsFor` cases: whether the record counts for the mind (Layer 2, 7.1). */
  countsFor?(record: JsonObject, mind: string, view: VerifierView): boolean;

  /** `sentFor` cases: whether the packet counts as sent on the mind's behalf (Layer 1, 11.2). */
  sentFor?(packet: JsonObject, mind: string, view: VerifierView): boolean;

  /** `status` cases: the status of a record at a time, given the records known (Layer 2, Section 8). */
  status?(of: JsonObject, records: readonly JsonObject[], at: string, view: VerifierView): string;

  /** `assurance` cases: the assurance level of a profile (Layer 0, 1.3). */
  assurance?(profile: JsonObject, view: VerifierView): string;

  /** The canonical form of a JSON value, as a string (core Section 2). */
  canonicalize?(value: unknown): string;
}

/** The adapter method each kind of case needs. */
export const METHOD_FOR_KIND = {
  log: "logVerifies",
  countsFor: "countsFor",
  sentFor: "sentFor",
  status: "status",
  assurance: "assurance",
  record: "recordIsWellFormed",
} as const satisfies Record<string, keyof ConformanceAdapter>;
