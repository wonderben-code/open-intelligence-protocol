// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Who a request is from (Layer 1, 13.3): the judging is `verifyRequest` of
 * `@oip/net`. What a service adds is the two things only it knows.
 *
 * - **Its own origin.** A signature covers the URI the client addressed.
 *   Behind a proxy a service is asked by another name, and the `Host` of a
 *   request is the sender's to choose. So the URI is put together from the
 *   origin the service is configured with and the path and query asked
 *   for, and from nothing else.
 * - **A memory of nonces that outlasts the process.** A signature is good
 *   for up to 300 seconds, and a service that restarts within them must
 *   still know the nonce was used. Two processes on one database must not
 *   both take it either: the second to record it is refused.
 */

import { OipError, type Instant } from "@oip/core";
import type { IdentityView } from "@oip/identity";
import { type AuthenticatedRequest, type SeenNonces, verifyRequest } from "@oip/net";
import { cutShort } from "@oip/schema";

import { Unavailable } from "./http.ts";
import { type Database, isConstraint } from "./storage.ts";

/**
 * The table of nonces seen, for a service's migrations. A row is kept until
 * the signature that used the nonce has expired.
 */
export const NONCES_SQL = [
  "CREATE TABLE request_nonces (keyid TEXT NOT NULL, nonce TEXT NOT NULL, until INTEGER NOT NULL, PRIMARY KEY (keyid, nonce)) STRICT, WITHOUT ROWID;",
  "CREATE INDEX request_nonces_until ON request_nonces (until);",
].join("\n");

/** Thrown where another request recorded the nonce first. */
class Replayed extends Error {}

/** The nonces a service has seen, kept in its database. */
export class StoredNonces implements SeenNonces {
  readonly #db: Database;

  constructor(db: Database) {
    this.#db = db;
  }

  seen(keyid: string, nonce: string): boolean {
    return (
      this.#db
        .prepare("SELECT 1 AS seen FROM request_nonces WHERE keyid = ? AND nonce = ?")
        .get(keyid, nonce) !== undefined
    );
  }

  remember(keyid: string, nonce: string, until: Instant): void {
    try {
      this.#db
        .prepare("INSERT INTO request_nonces (keyid, nonce, until) VALUES (?, ?, ?)")
        .run(keyid, nonce, until);
    } catch (error) {
      // Recorded since it was looked for: by another process, for the same request sent twice.
      if (isConstraint(error)) throw new Replayed();
      throw error;
    }
  }

  /**
   * Forgets every nonce whose signature has expired at `now`. A service
   * calls it now and then, so that the table holds the last 300 seconds.
   *
   * @returns How many were forgotten.
   */
  forget(now: Instant): number {
    return Number(this.#db.prepare("DELETE FROM request_nonces WHERE until < ?").run(now).changes);
  }
}

/** What a service authenticates requests with. */
export interface Authentication {
  /** The origin clients reach the service at, as it is configured: `https://host.example`. */
  readonly origin: string;
  /** The present: the service's clock, read for this request. */
  readonly now: Instant;
  /** The identity logs the service holds, and its evidence of time. */
  readonly view: IdentityView;
  /** The nonces it has seen. */
  readonly nonces: SeenNonces;
}

/**
 * Layer 1, 13.3: the mind a request is from.
 *
 * @param body - The request's body as it was read, which the signature's
 *   digest is checked against. Empty for a request without one.
 * @throws OipError `unauthorised` if the request carries no signature that
 *   meets the profile, or one whose nonce was used before.
 * @throws Unavailable if the check was cut short (ADR-0010).
 */
export function authenticate(
  request: Request,
  body: Uint8Array,
  service: Authentication,
): AuthenticatedRequest {
  const asked = new URL(request.url);
  let judged: ReturnType<typeof verifyRequest>;
  try {
    judged = verifyRequest(
      {
        method: request.method,
        // The service's own name for itself, and what was asked of it.
        url: `${service.origin}${asked.pathname}${asked.search}`,
        headers: [...request.headers],
        ...(body.length === 0 ? {} : { body }),
      },
      { now: service.now, view: service.view, nonces: service.nonces },
    );
  } catch (error) {
    if (error instanceof Replayed) {
      throw new OipError("unauthorised", "the signature's nonce has been used before", {
        clause: "L1 13.3",
      });
    }
    throw error;
  }
  if (judged.ok) return judged.value;
  if (judged === cutShort()) throw new Unavailable("the signature could not be judged just now");
  const [first] = judged.issues;
  throw new OipError("unauthorised", first.message, {
    clause: first.clause,
    issues: judged.issues,
  });
}
