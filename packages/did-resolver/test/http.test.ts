// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The resolver's HTTP interface, as a driver of the DIF Universal Resolver has it. */

import { contentId } from "@oip/core";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { DID_JSON, handle, RESOLUTION_RESULT } from "../src/index.ts";
import { Place } from "./harness.ts";

let place: Place;
let ada: string;
let old: string;
let first: string;

beforeAll(async () => {
  place = await new Place().start();
  ada = await place.make("ada");
  old = await place.make("old");
  const opened = await place.mind("old");
  try {
    first = opened.mind.state.versionId;
    await opened.mind.retire({ control: opened.lock });
  } finally {
    opened.mind.close();
  }
});
afterAll(async () => {
  await place.close();
});

/** Asks the interface, and reads what it answers as JSON where it is JSON. */
async function get(path: string, accept?: string, method = "GET") {
  const answer = await handle(
    { method, path, ...(accept === undefined ? {} : { accept }) },
    place.options(),
  );
  const type = answer.headers["content-type"] ?? "";
  const body = (type.includes("json") ? JSON.parse(answer.body) : answer.body) as Record<
    string,
    unknown
  > &
    string;
  return { status: answer.status, type, body };
}

describe("GET /1.0/identifiers/<did>", () => {
  it(`${clause("L1 5.2")} gives the result of resolving a did:oip DID: the document, and what the resolution and the log say besides`, async () => {
    const answer = await get(`/1.0/identifiers/${ada}`);
    expect(answer).toMatchObject({ status: 200, type: RESOLUTION_RESULT });
    expect(answer.body).toMatchObject({
      "@context": "https://w3id.org/did-resolution/v1",
      didResolutionMetadata: { contentType: DID_JSON },
      didDocument: { id: ada },
      didDocumentMetadata: { deactivated: false },
    });
    // The same to a caller that asks for the result by its media type, or for anything.
    for (const accept of [RESOLUTION_RESULT, "application/did-resolution", "*/*", ""]) {
      expect((await get(`/1.0/identifiers/${ada}`, accept)).type, accept).toBe(RESOLUTION_RESULT);
    }
  });

  it("gives the document alone to a caller that asks for it", async () => {
    for (const accept of [DID_JSON, "application/json", `text/html, ${DID_JSON};q=0.9`]) {
      const answer = await get(`/1.0/identifiers/${ada}`, accept);
      expect(answer, accept).toMatchObject({ status: 200, type: DID_JSON });
      expect(answer.body["id"]).toBe(ada);
      expect(answer.body).not.toHaveProperty("didDocument");
    }
  });

  it("answers a caller that takes no representation there is with 406, and the reason", async () => {
    const answer = await get(`/1.0/identifiers/${ada}`, "application/did+ld+json");
    expect(answer).toMatchObject({
      status: 406,
      type: RESOLUTION_RESULT,
      body: {
        didResolutionMetadata: { error: "representationNotSupported" },
        didDocument: null,
        didDocumentMetadata: {},
      },
    });
  });

  it(`${clause("L1 2.4")} takes the parameters of a DID URL inside the name, or as the query of the request`, async () => {
    const inside = await get(`/1.0/identifiers/${encodeURIComponent(`${old}?versionId=${first}`)}`);
    const after = await get(`/1.0/identifiers/${old}?versionId=${first}`);
    for (const answer of [inside, after]) {
      // The mind has retired since its first version: 410, with the document of that version.
      expect(answer).toMatchObject({
        status: 410,
        body: {
          didDocument: { id: old },
          didDocumentMetadata: { versionId: first, deactivated: true },
        },
      });
    }
    expect(inside.body).toStrictEqual(after.body);
    // A version that is named by a time is no version this method has.
    expect(await get(`/1.0/identifiers/${old}?versionTime=2001-01-01T00:00:00Z`)).toMatchObject({
      status: 400,
      body: { didResolutionMetadata: { error: "invalidDidUrl" }, didDocument: null },
    });
  });

  it("answers for a mind that has retired with 410, and its document all the same", async () => {
    const result = await get(`/1.0/identifiers/${old}`);
    expect(result).toMatchObject({
      status: 410,
      body: { didDocument: { id: old }, didDocumentMetadata: { deactivated: true } },
    });
    const document = await get(`/1.0/identifiers/${old}`, DID_JSON);
    expect(document).toMatchObject({ status: 410, type: DID_JSON, body: { id: old } });
  });

  it.each([
    ["a mind no resolver holds", () => `did:oip:${contentId({ no: "mind" })}`, 404, "notFound"],
    ["what is no address", () => "did:oip:tooshort", 400, "invalidDid"],
    ["what cannot be read as a name", () => "did:oip:%E0%A4%A", 400, "invalidDid"],
    ["a DID of another method", () => "did:web:example.com", 501, "methodNotSupported"],
    ["what is no DID", () => "did:oip", 400, "invalidDid"],
    ["a DID that is not in small letters", () => "DID:OIP:abc", 400, "invalidDid"],
  ])(
    "answers for %s with the status of the error, and the error",
    async (_, did, status, error) => {
      const answer = await get(`/1.0/identifiers/${did()}`);
      expect(answer).toMatchObject({
        status,
        type: RESOLUTION_RESULT,
        body: { didResolutionMetadata: { error }, didDocument: null },
      });
      // A caller that asked for the document is told the same: there is none to give.
      expect(await get(`/1.0/identifiers/${did()}`, DID_JSON)).toMatchObject({
        status,
        type: RESOLUTION_RESULT,
      });
    },
  );

  it("answers with 500 where no resolver can be asked", async () => {
    const answer = await handle(
      { method: "GET", path: `/1.0/identifiers/${ada}` },
      place.options({ fetch: () => Promise.reject(new TypeError("fetch failed")) }),
    );
    expect(answer.status).toBe(500);
    expect(JSON.parse(answer.body)).toMatchObject({
      didResolutionMetadata: { error: "internalError" },
    });
  });
});

describe("the resolver's HTTP interface", () => {
  it("says that it serves, and which method it resolves", async () => {
    expect(await get("/healthz")).toMatchObject({ status: 200, body: "ok\n" });
    expect(await get("/1.0/methods")).toMatchObject({ status: 200, body: ["oip"] });
  });

  it("has nothing elsewhere, and resolves with GET alone", async () => {
    for (const path of ["/", "/1.0/identifiers", "/1.0/other/did:oip:x", "/identifiers/x"]) {
      expect((await get(path)).status, path).toBe(404);
    }
    expect((await get(`/1.0/identifiers/${ada}`, undefined, "POST")).status).toBe(405);
  });

  it("answers what is no path with 400: a client's mistake is not the resolver's fault", async () => {
    for (const path of ["//[", "http://[/x"]) {
      expect(await get(path), path).toStrictEqual({
        status: 400,
        type: "text/plain; charset=utf-8",
        body: "That is no path.\n",
      });
    }
  });
});
