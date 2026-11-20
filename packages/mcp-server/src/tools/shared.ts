// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** What the tools share: how a record is named, shown and sent on. */

import { carried, type Delivery, type Mind, TransportError } from "@oip/client";
import { contentId, type JsonObject, type JsonValue, OipError } from "@oip/core";
import { type Opened, UsageError } from "@oip/local";
import { validateRecordOfType } from "@oip/schema";

/**
 * A record this mind holds, by its content ID.
 *
 * A tool never reads a record from a file: an assistant that could name a
 * file could be talked into sending one.
 *
 * @param what - What the record is to the tool, for the message: "the offer".
 * @throws UsageError if the mind holds no such record.
 */
export function held(opened: Opened, id: string, what: string): JsonObject {
  const record = opened.mind.records().find((one) => contentId(one) === id);
  if (record === undefined) {
    throw new UsageError(
      `the mind holds no record ${id} for ${what}. It holds what it signed, what oip_inbox received and what oip_find found`,
    );
  }
  return record as unknown as JsonObject;
}

/** A record without its proofs and its version: what it says, and no signature to read past. */
export function saying(record: object): JsonObject {
  const said: Record<string, JsonValue> = {};
  for (const [name, value] of Object.entries(record)) {
    if (name !== "proof" && name !== "oip") said[name] = value as JsonValue;
  }
  return said;
}

/** Whom a Commitment binds now: each party, and whether a signature on it counts for that party. */
export async function binding(
  mind: Mind,
  record: JsonObject,
): Promise<{ mind: string; role: string; bound: boolean }[]> {
  const commitment = validateRecordOfType("Commitment", record);
  if (!commitment.ok) return [];
  const parties: { mind: string; role: string; bound: boolean }[] = [];
  for (const party of commitment.value.parties) {
    parties.push({
      mind: party.mind,
      role: party.role,
      bound: await mind.countsFor(record, party.mind),
    });
  }
  return parties;
}

/** What became of a packet for one recipient, as a result says it. */
export function delivered(delivery: Delivery): JsonObject {
  const { to, stored, sealed, queued, failure } = delivery;
  return {
    to,
    delivered: stored,
    sealed,
    ...(queued === true ? { waiting: "kept, and tried again when oip_inbox next reads" } : {}),
    ...(failure === undefined ? {} : { failure }),
  };
}

/**
 * Why something failed that came after a signature, as a result says it.
 * What is signed is signed: the tool says so, and says what did not follow.
 */
export function failureOf(error: unknown): string {
  if (error instanceof OipError) return error.code;
  if (error instanceof TransportError) return error.failure;
  throw error;
}

/**
 * Does with a signed record what the call asked: puts it on the mind's
 * feed, and sends it to the minds named.
 *
 * It does not throw for a service that could not be reached: the record
 * is signed by then, and the assistant must be told its ID whatever else
 * failed.
 *
 * @param verb - The verb of the packet that carries it.
 */
export async function share(
  mind: Mind,
  record: object,
  to: { readonly publish: boolean; readonly sendTo: readonly string[]; readonly verb: string },
): Promise<JsonObject> {
  const said: Record<string, JsonValue> = {};
  if (to.publish) {
    try {
      const entry = await mind.publishRecord(record);
      said["published"] = true;
      said["feedPosition"] = entry.seq;
      const missed = mind.publications.filter(({ taken }) => !taken);
      if (missed.length > 0) {
        said["servicesThatDidNotTakeIt"] = missed.map(({ service, origin, failure }) => ({
          service,
          origin,
          ...(failure === undefined ? {} : { failure }),
        }));
      }
    } catch (error) {
      said["published"] = false;
      said["publishFailure"] = failureOf(error);
    }
  }
  if (to.sendTo.length > 0) {
    try {
      const sent = await mind.send({ to: to.sendTo, verb: to.verb, content: carried(record) });
      said["packet"] = sent.id;
      said["deliveries"] = sent.deliveries.map((delivery) => delivered(delivery));
    } catch (error) {
      said["sendFailure"] = failureOf(error);
    }
  }
  return said;
}
