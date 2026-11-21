// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * `did:oip` resolved through the DIF `did-resolver` library itself, against
 * a real resolver and host.
 */

import { LOCAL } from "@oip/cli";
import { Lookup } from "@oip/client";
import { contentId } from "@oip/core";
import { clause } from "@oip/testkit";
import { Resolver } from "did-resolver";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { DID_JSON, getResolver, resolveDid } from "../src/index.ts";
import { Place } from "./harness.ts";

let place: Place;
let ada: string;
let old: string;
/** The version the mind that retired had first: `0-` and the content ID of its genesis. */
let first: string;
let resolver: Resolver;

beforeAll(async () => {
  place = await new Place().start();
  ada = await place.make("ada");
  old = await place.make("old", "service");
  const opened = await place.mind("old");
  try {
    first = opened.mind.state.versionId;
    await opened.mind.retire({ control: opened.lock });
  } finally {
    opened.mind.close();
  }
  resolver = new Resolver(getResolver(place.options()));
});
afterAll(async () => {
  await place.close();
});

describe("a did:oip DID, resolved with the DIF did-resolver library", () => {
  it(`${clause("L1 5.2")} gives the mind's DID document: its keys by what they are for, its homes and where it takes packets`, async () => {
    const result = await resolver.resolve(ada);
    expect(result.didResolutionMetadata).toStrictEqual({ contentType: DID_JSON });
    const document = result.didDocument;
    // It is the document the client's own lookup makes of the mind's verified log.
    const looked = await new Lookup(place.options()).resolve(ada);
    expect(document).toStrictEqual(looked.did.didDocument);
    expect(result.didDocumentMetadata).toStrictEqual(looked.did.didDocumentMetadata);

    expect(document?.id).toBe(ada);
    const [signing] = looked.state.keys;
    const [agreement] = looked.state.agreement;
    expect(document?.verificationMethod).toContainEqual({
      id: `${ada}#${String(signing)}`,
      type: "Multikey",
      controller: ada,
      publicKeyMultibase: signing,
    });
    for (const purpose of ["authentication", "assertionMethod", "capabilityDelegation"] as const) {
      expect(document?.[purpose]).toStrictEqual([`${ada}#${String(signing)}`]);
    }
    expect(document?.keyAgreement).toStrictEqual([`${ada}#${String(agreement)}`]);
    expect(document?.service?.[0]).toStrictEqual({
      id: `${ada}#home-0`,
      type: "OIPHome",
      serviceEndpoint: LOCAL.host,
    });
    expect(document?.service?.slice(1).map(({ type }) => type)).toContain("OIPEndpoint");
    // What the log holds and the document does not.
    expect(result.didDocumentMetadata).toMatchObject({
      versionId: looked.state.versionId,
      deactivated: false,
      parents: [],
      children: [],
      nextThreshold: 1,
    });
    // The aliases a mind lists are shown once they are verified, and this driver verifies none.
    expect(document).not.toHaveProperty("alsoKnownAs");
  });

  it(`${clause("L1 5.2")} says of a mind that has retired that it is deactivated`, async () => {
    const result = await resolver.resolve(old);
    expect(result.didResolutionMetadata).toStrictEqual({ contentType: DID_JSON });
    expect(result.didDocument?.id).toBe(old);
    expect(result.didDocumentMetadata.deactivated).toBe(true);
  });

  it(`${clause("L1 2.4", "L1 5.2")} gives the document of an earlier version for a DID URL that names one, with its keys named as a proof pinned to it names them`, async () => {
    const result = await resolver.resolve(`${old}?versionId=${first}`);
    // The document is of the first version. That the mind has retired is said of the mind: a
    // verifier that follows a key reference of a proof is told so.
    expect(result.didDocumentMetadata).toMatchObject({ versionId: first, deactivated: true });
    const [method] = result.didDocument?.verificationMethod ?? [];
    expect(method?.id).toBe(`${old}?versionId=${first}#${String(method?.publicKeyMultibase)}`);
    // Where the mind takes packets is said of now, and is no part of an earlier document.
    expect(result.didDocument?.service?.map(({ type }) => type)).toStrictEqual(["OIPHome"]);
    // The latest version, named: the same keys, named by the version, with where it takes packets now.
    const latest = (await resolver.resolve(ada)).didDocumentMetadata.versionId ?? "";
    const pinned = await resolver.resolve(`${ada}?versionId=${latest}`);
    expect(pinned.didDocument?.verificationMethod?.[0]?.id).toContain(`?versionId=${latest}#`);
    expect(pinned.didDocument?.service?.map(({ type }) => type)).toContain("OIPEndpoint");
    // An earlier version of a mind that takes packets now: where it takes them now is no part
    // of what it was then.
    const opened = await place.mind("ada");
    let before: string;
    try {
      before = opened.mind.state.versionId;
      await opened.mind.addKey({ control: opened.lock, label: "second" });
    } finally {
      opened.mind.close();
    }
    const earlier = await resolver.resolve(`${ada}?versionId=${before}`);
    expect(earlier.didDocumentMetadata).toMatchObject({ versionId: before, deactivated: false });
    expect(earlier.didDocument?.service?.map(({ type }) => type)).toStrictEqual(["OIPHome"]);
    const now = await resolver.resolve(ada);
    expect(now.didDocumentMetadata.versionId).not.toBe(before);
    expect(now.didDocument?.service?.map(({ type }) => type)).toContain("OIPEndpoint");
    // A version the log does not have.
    const none = await resolver.resolve(`${ada}?versionId=7-${contentId({ no: "event" })}`);
    expect(none).toStrictEqual({
      didResolutionMetadata: {
        error: "notFound",
        message: "versionId names no event of the mind's log.",
      },
      didDocument: null,
      didDocumentMetadata: {},
    });
  });

  it("resolves the DID of a DID URL: a path or a fragment is the caller's to follow in the same document", async () => {
    const whole = await resolver.resolve(ada);
    const key = whole.didDocument?.verificationMethod?.[0]?.publicKeyMultibase ?? "";
    expect((await resolver.resolve(`${ada}#${key}`)).didDocument).toStrictEqual(whole.didDocument);
    expect((await resolver.resolve(`${ada}/some/path`)).didDocument).toStrictEqual(
      whole.didDocument,
    );
  });

  it("has no document for a mind no resolver holds, or for what is no address", async () => {
    const nobody = `did:oip:${contentId({ no: "mind" })}`;
    expect(await resolver.resolve(nobody)).toStrictEqual({
      didResolutionMetadata: {
        error: "notFound",
        message: "No resolver that was asked holds that mind.",
      },
      didDocument: null,
      didDocumentMetadata: {},
    });
    expect((await resolver.resolve("did:oip:tooshort")).didResolutionMetadata).toStrictEqual({
      error: "invalidDid",
      message: "That is no did:oip address: did:oip: and 56 characters of base32.",
    });
    // Asked without the library, which knows its drivers by their methods.
    expect(
      (await resolveDid("did:web:example.com", place.options())).didResolutionMetadata.error,
    ).toBe("methodNotSupported");
    // What is no DID at all is no DID of another method: the scheme and the method are in
    // small letters, and a method is followed by a colon and a name.
    for (const none of ["not a DID", "did:oip", "DID:OIP:abc", "did:OIP:abc", "did::abc", ""]) {
      expect((await resolveDid(none, place.options())).didResolutionMetadata, none).toStrictEqual({
        error: "invalidDid",
        message: "That is no DID: a DID is did:, a method, a colon and a name.",
      });
    }
  });

  it(`${clause("L1 2.4")} names a version by its identifier alone: a caller that names one by a time is not given today's document`, async () => {
    for (const url of [
      `${ada}?versionTime=2001-01-01T00:00:00Z`,
      `${ada}?versionId=${first}&versionTime=2001-01-01T00:00:00Z`,
    ]) {
      expect(await resolveDid(url, place.options())).toStrictEqual({
        didResolutionMetadata: {
          error: "invalidDidUrl",
          message:
            "A version of a did:oip mind is named by versionId: this method has no document by versionTime.",
        },
        didDocument: null,
        didDocumentMetadata: {},
      });
    }
    // What says where to go in the document is the caller's to follow.
    const whole = await resolveDid(ada, place.options());
    expect((await resolveDid(`${ada}?service=home-0`, place.options())).didDocument).toStrictEqual(
      whole.didDocument,
    );
  });

  it("represents a document as application/did+json, and in no other way", async () => {
    for (const accept of [
      DID_JSON,
      "application/json",
      "*/*",
      "text/html, application/*;q=0.5",
      "",
    ]) {
      expect((await resolver.resolve(ada, { accept })).didDocument?.id, accept).toBe(ada);
    }
    for (const accept of ["application/did+ld+json", "application/did+cbor, text/html"]) {
      expect((await resolver.resolve(ada, { accept })).didResolutionMetadata, accept).toStrictEqual(
        {
          error: "representationNotSupported",
          message:
            "A did:oip document is represented as application/did+json, and in no other way.",
        },
      );
    }
  });
});

describe("a resolution that cannot be made", () => {
  it("says so where no resolver can be asked", async () => {
    const cut = place.options({ fetch: () => Promise.reject(new TypeError("fetch failed")) });
    expect(await resolveDid(ada, cut)).toStrictEqual({
      didResolutionMetadata: {
        error: "internalError",
        message: "No resolver could be asked: unreachable.",
      },
      didDocument: null,
      didDocumentMetadata: {},
    });
  });

  it(`${clause("L1 17.1")} gives no document where what a resolver serves does not verify: nothing is taken on a resolver's word`, async () => {
    // A resolver that serves the mind's log with one character of a signature changed.
    const lying = place.options({
      fetch: async (asked) => {
        const answer = await fetch(asked);
        if (!new URL(asked.url).pathname.includes("/resolve/")) return answer;
        const served = await answer.text();
        const altered = served.replace(
          /"proofValue":"z(.)/u,
          (_, one: string) => `"proofValue":"z${one === "2" ? "3" : "2"}`,
        );
        expect(altered).not.toBe(served);
        return new Response(altered, { status: answer.status, headers: answer.headers });
      },
    });
    const result = await resolveDid(ada, lying);
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe("internalError");
    expect(result.didResolutionMetadata.message).toMatch(
      /^The mind's log could not be verified: [a-z-]+\.$/u,
    );
  });

  it("is no result where the caller's own options are none: that is a mistake, and is thrown", async () => {
    await expect(resolveDid(ada, { resolvers: [] })).rejects.toThrow(TypeError);
    // A fetch that throws is a resolver that could not be asked.
    const broken = place.options({
      fetch: () => {
        throw new RangeError("a fault of the caller's own fetch");
      },
    });
    expect((await resolveDid(ada, broken)).didResolutionMetadata.error).toBe("internalError");
  });
});
