// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { formatKeyRef, OipError, utf8 } from "@oip/core";
import { type IdentityView, LogBook } from "@oip/identity";
import { type HttpRequest, RequestNonces, type SeenNonces, signRequest } from "@oip/net";
import { noteCutShort } from "@oip/schema";
import { clause } from "@oip/testkit";
import { at, KeyMind, LATER, type Mind, witness } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  authenticate,
  type Authentication,
  Database,
  NONCES_SQL,
  StoredNonces,
  Unavailable,
} from "../src/index.ts";

const ORIGIN = "https://resolver.example";
const ada = new KeyMind("ada");
const eve = new KeyMind("eve");

const book = new LogBook(witness([ada.events, eve.events]));
for (const mind of [ada, eve]) book.hold(mind.events, LATER);

let directory: string;
let db: Database;

const open = (): Database =>
  Database.open(
    { path: join(directory, "service.db"), durable: false },
    [{ version: 1, name: "nonces", sql: NONCES_SQL }],
    { now: () => 0n },
  );

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-auth-"));
  db = open();
});
afterEach(() => {
  db.close();
  rmSync(directory, { recursive: true, force: true });
});

function service(seconds: number, more: Partial<Authentication> = {}): Authentication {
  return { origin: ORIGIN, now: at(seconds), view: book, nonces: new StoredNonces(db), ...more };
}

/**
 * A request as a client signs it for `url`, and as the service then gets
 * it: at the address a proxy passes it on to, with the `Host` the proxy set.
 */
async function arriving(
  url: string,
  options: { method?: string; body?: Uint8Array; by?: Mind; seconds?: number; nonce?: string } = {},
): Promise<{ request: Request; body: Uint8Array }> {
  const by = options.by ?? ada;
  const signedAs: HttpRequest = {
    method: options.method ?? "GET",
    url,
    headers: [["Accept", "application/oip+json"]],
    ...(options.body === undefined ? {} : { body: options.body }),
  };
  const added = await signRequest(
    signedAs,
    {
      keyRef: formatKeyRef(by.address, by.versionId(), by.operational().publicKey),
      created: at(options.seconds ?? 100),
      nonce: options.nonce ?? "nonce-0001",
    },
    by.operational(),
  );
  const asked = new URL(url);
  const request = new Request(`http://10.0.0.7:8080${asked.pathname}${asked.search}`, {
    method: signedAs.method,
    headers: [...signedAs.headers, ...added, ["Host", "10.0.0.7:8080"]].map(
      ([name, value]) => [name, value] as [string, string],
    ),
    ...(options.body === undefined ? {} : { body: options.body }),
  });
  return { request, body: options.body ?? new Uint8Array(0) };
}

function refused(work: () => unknown): OipError {
  try {
    work();
  } catch (error) {
    if (error instanceof OipError) return error;
    throw error;
  }
  throw new Error("the request was authenticated");
}

describe(`${clause("L1 13.3")} who a request is from`, () => {
  it("is the mind whose key signed it, for the URI clients address the service by", async () => {
    const { request, body } = await arriving(`${ORIGIN}/oip/v1/mbox/abc?after=17`);
    expect(authenticate(request, body, service(110))).toMatchObject({
      mind: ada.address,
      nonce: "nonce-0001",
    });
  });

  it("is nobody where the signature is for another origin: the service's own is what counts", async () => {
    // Signed for the address the proxy passes requests on to, or for another service.
    for (const url of [
      "http://10.0.0.7:8080/oip/v1/mbox/abc",
      "https://other.example/oip/v1/mbox/abc",
    ]) {
      const { request, body } = await arriving(url);
      const error = refused(() => authenticate(request, body, service(110)));
      expect(error.code).toBe("unauthorised");
      expect(error.clause).toBe("L1 13.3");
    }
    // And for another path, or another query, of this one.
    const { request, body } = await arriving(`${ORIGIN}/oip/v1/mbox/abc?after=17`);
    const moved = new Request(request.url.replace("after=17", "after=18"), request);
    expect(refused(() => authenticate(moved, body, service(110))).code).toBe("unauthorised");
  });

  it("covers the body: another body under the same signature is nobody's", async () => {
    const sent = utf8('{"oip":"1","type":"Location"}');
    const { request, body } = await arriving(`${ORIGIN}/oip/v1/resolve/x`, {
      method: "PUT",
      body: sent,
    });
    expect(authenticate(request, body, service(110)).mind).toBe(ada.address);
    const other = await arriving(`${ORIGIN}/oip/v1/resolve/x`, {
      method: "PUT",
      body: sent,
      nonce: "nonce-0002",
    });
    expect(
      refused(() => authenticate(other.request, utf8('{"oip":"1","type":"Bundle"}'), service(110)))
        .code,
    ).toBe("unauthorised");
    // A body that was not read is not the body that was signed.
    expect(refused(() => authenticate(other.request, new Uint8Array(0), service(110))).code).toBe(
      "unauthorised",
    );
  });

  it("is nobody without a signature, and the answer says why", () => {
    const bare = new Request("http://10.0.0.7:8080/oip/v1/mbox/abc");
    const error = refused(() => authenticate(bare, new Uint8Array(0), service(110)));
    expect(error.code).toBe("unauthorised");
    expect(error.toProblem()).toMatchObject({ status: 401, type: "urn:oip:error:unauthorised" });
    expect(error.issues.length).toBeGreaterThan(0);
  });

  it("is not called nobody where the check was cut short: the client asks again", async () => {
    const { request, body } = await arriving(`${ORIGIN}/oip/v1/mbox/abc`);
    const cut: IdentityView = {
      evidence: book.evidence,
      log: (mind) => {
        noteCutShort(new RangeError("Maximum call stack size exceeded"));
        return book.log(mind);
      },
    };
    const nonces = new StoredNonces(db);
    expect(() => authenticate(request, body, service(110, { view: cut, nonces }))).toThrow(
      Unavailable,
    );
    // Nothing was recorded of it, so the same request is good when asked again.
    expect(
      nonces.seen(
        formatKeyRef(ada.address, ada.versionId(), ada.operational().publicKey),
        "nonce-0001",
      ),
    ).toBe(false);
    expect(authenticate(request, body, service(110, { nonces })).mind).toBe(ada.address);
  });
});

describe(`${clause("L1 13.3")} a nonce a key has used`, () => {
  it("is not taken twice while its signature is valid", async () => {
    const { request, body } = await arriving(`${ORIGIN}/oip/v1/mbox/abc`);
    expect(authenticate(request, body, service(110)).mind).toBe(ada.address);
    const error = refused(() => authenticate(request, body, service(111)));
    expect(error.code).toBe("unauthorised");
    // Another key may use the same nonce, and the same key another.
    const others = [
      await arriving(`${ORIGIN}/oip/v1/mbox/abc`, { by: eve }),
      await arriving(`${ORIGIN}/oip/v1/mbox/abc`, { nonce: "nonce-0002" }),
    ];
    expect(
      others.map((other) => authenticate(other.request, other.body, service(111)).mind),
    ).toStrictEqual([eve.address, ada.address]);
  });

  it("is still known after the service has restarted", async () => {
    const { request, body } = await arriving(`${ORIGIN}/oip/v1/mbox/abc`);
    authenticate(request, body, service(110));
    db.close();
    db = open();
    expect(refused(() => authenticate(request, body, service(120))).code).toBe("unauthorised");
    // A memory that lasts only as long as the process would have taken it.
    expect(authenticate(request, body, service(120, { nonces: new RequestNonces() })).mind).toBe(
      ada.address,
    );
  });

  it("is taken by one of two processes that look at the same moment, and not by both", async () => {
    const { request, body } = await arriving(`${ORIGIN}/oip/v1/mbox/abc`);
    const stored = new StoredNonces(db);
    // This process looked before the other recorded, and records after it.
    const raced: SeenNonces = {
      seen: () => false,
      remember: (keyid, nonce, until) => {
        const other = open();
        new StoredNonces(other).remember(keyid, nonce, until);
        other.close();
        stored.remember(keyid, nonce, until);
      },
    };
    const error = refused(() => authenticate(request, body, service(110, { nonces: raced })));
    expect(error.code).toBe("unauthorised");
    expect(error.detail).toMatch(/used before/u);
  });

  it("is forgotten once its signature has expired, and not before", async () => {
    const stored = new StoredNonces(db);
    for (const [nonce, seconds] of [
      ["nonce-0001", 100],
      ["nonce-0002", 200],
    ] as const) {
      const { request, body } = await arriving(`${ORIGIN}/oip/v1/mbox/abc`, { nonce, seconds });
      authenticate(request, body, service(seconds + 1, { nonces: stored }));
    }
    const count = (): number =>
      (db.prepare("SELECT COUNT(*) AS n FROM request_nonces").get() as { n: number }).n;
    expect(count()).toBe(2);
    // The first signature expires 300 seconds after it was made.
    expect(stored.forget(at(400))).toBe(0);
    expect(stored.forget(at(401))).toBe(1);
    expect(count()).toBe(1);
    expect(stored.forget(at(10_000))).toBe(1);
    expect(stored.forget(at(10_000))).toBe(0);
  });

  it("does not make a failure of the database into a refusal", async () => {
    const { request, body } = await arriving(`${ORIGIN}/oip/v1/mbox/abc`);
    const nonces = new StoredNonces(db);
    db.close();
    // Whether it fails where the nonce is looked for, or where it is recorded.
    expect(() => authenticate(request, body, service(110, { nonces }))).toThrow(/not open/u);
    const recording: SeenNonces = { seen: () => false, remember: nonces.remember.bind(nonces) };
    expect(() => authenticate(request, body, service(110, { nonces: recording }))).toThrow(
      /not open/u,
    );
  });
});
