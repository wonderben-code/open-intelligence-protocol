// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  base64urlToBytes,
  bytesToBase64,
  formatKeyRef,
  signEd25519,
  type SyncSigner,
  utf8,
  verifyEd25519,
} from "@oip/core";
import { LogBook } from "@oip/identity";
import { clause } from "@oip/testkit";
import { at, KeyMind, LATER, type Mind, witness } from "@oip/testkit/minds";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  contentDigest,
  type HttpRequest,
  type InnerList,
  parseDictionary,
  RequestNonces,
  type RequestVerifier,
  signatureBase,
  signRequest,
  verifyRequest,
} from "../src/index.ts";

/** RFC 9421, B.2: the test request, and B.1.4: the Ed25519 test key. */
const RFC = {
  request: {
    method: "POST",
    url: "https://example.com/foo?param=Value&Pet=dog",
    headers: [
      ["Host", "example.com"],
      ["Date", "Tue, 20 Apr 2021 02:07:55 GMT"],
      ["Content-Type", "application/json"],
      [
        "Content-Digest",
        "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
      ],
      ["Content-Length", "18"],
    ],
    body: utf8('{"hello": "world"}'),
  } satisfies HttpRequest,
  publicKey: base64urlToBytes("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs")!,
  privateKey: base64urlToBytes("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU")!,
  // B.2.6: signing a request using ed25519.
  input:
    'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length")' +
    ';created=1618884473;keyid="test-key-ed25519"',
  base: [
    '"date": Tue, 20 Apr 2021 02:07:55 GMT',
    '"@method": POST',
    '"@path": /foo',
    '"@authority": example.com',
    '"content-type": application/json',
    '"content-length": 18',
    '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length")' +
      ';created=1618884473;keyid="test-key-ed25519"',
  ].join("\n"),
  signature:
    "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:",
};

const listOf = (header: string, label: string): InnerList => {
  const member = parseDictionary(header)?.get(label);
  if (member?.kind !== "list") throw new Error("no inner list");
  return member;
};

describe("RFC 9421, Appendix B.2.6: signing a request using ed25519", () => {
  it("builds the RFC's signature base", () => {
    const base = signatureBase(RFC.request, listOf(RFC.input, "sig-b26"));
    expect(base).toStrictEqual({ ok: true, value: RFC.base });
  });

  it("verifies the RFC's signature with the RFC's key, and makes the same one", () => {
    const signature = parseDictionary(RFC.signature)?.get("sig-b26");
    if (signature?.kind !== "item" || signature.value.kind !== "bytes") throw new Error("no bytes");
    expect(verifyEd25519(signature.value.value, utf8(RFC.base), RFC.publicKey)).toBe(true);
    // Ed25519 is deterministic: the RFC's key over the RFC's base gives the RFC's signature.
    expect(bytesToBase64(signEd25519(utf8(RFC.base), RFC.privateKey))).toBe(
      RFC.signature.slice("sig-b26=:".length, -1),
    );
  });

  it("derives each component of the request's target", () => {
    const value = (name: string) => {
      const base = signatureBase(RFC.request, listOf(`s=("${name}")`, "s"));
      return base.ok ? base.value.split("\n")[0] : undefined;
    };
    expect(value("@target-uri")).toBe('"@target-uri": https://example.com/foo?param=Value&Pet=dog');
    expect(value("@scheme")).toBe('"@scheme": https');
    expect(value("@query")).toBe('"@query": ?param=Value&Pet=dog');
    expect(value("@request-target")).toBe('"@request-target": /foo?param=Value&Pet=dog');
    // A target with no path and no query has the path `/` and the query `?` (2.2.6, 2.2.7).
    const bare = { ...RFC.request, url: "https://EXAMPLE.com" };
    const of = (name: string) => {
      const base = signatureBase(bare, listOf(`s=("${name}")`, "s"));
      return base.ok ? base.value.split("\n")[0] : undefined;
    };
    expect(of("@path")).toBe('"@path": /');
    expect(of("@query")).toBe('"@query": ?');
    expect(of("@authority")).toBe('"@authority": example.com');
  });

  it("makes no base for a component the request does not have, or names twice", () => {
    const base = (input: string) => signatureBase(RFC.request, listOf(input, "s")).ok;
    expect(base('s=("@method" "date")')).toBe(true);
    expect(base('s=("@method" "@method")')).toBe(false);
    expect(base('s=("x-missing")')).toBe(false);
    expect(base('s=("@status")')).toBe(false);
    expect(base('s=("@unknown")')).toBe(false);
    // A field's name is given in lower case (2.1).
    expect(base('s=("Date")')).toBe(false);
    // Component parameters are not read here: a component that has one is an error (2.5).
    expect(base('s=("date";sf)')).toBe(false);
    expect(base("s=(date)")).toBe(false);
    // A target that is no URI has no parts to derive.
    expect(signatureBase({ ...RFC.request, url: "/foo" }, listOf('s=("@path")', "s")).ok).toBe(
      false,
    );
    // A value that is not printable ASCII has no place in a base.
    const odd = { ...RFC.request, headers: [["x-note", "café"]] } as HttpRequest;
    expect(signatureBase(odd, listOf('s=("x-note")', "s")).ok).toBe(false);
  });

  it("joins the instances of a field, each without the space around it (2.1)", () => {
    const request = {
      ...RFC.request,
      headers: [
        ["Cache-Control", " max-age=60 "],
        ["cache-control", "must-revalidate"],
      ],
    } as HttpRequest;
    const base = signatureBase(request, listOf('s=("cache-control")', "s"));
    expect(base.ok && base.value.split("\n")[0]).toBe(
      '"cache-control": max-age=60, must-revalidate',
    );
  });
});

describe("RFC 9530: the Content-Digest of a body, with SHA-256", () => {
  it("is the RFC's for the RFC's examples", () => {
    // Appendix A: the JSON object followed by a line feed, and no content at all.
    expect(contentDigest(utf8('{"hello": "world"}\n'))).toBe(
      "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:",
    );
    expect(contentDigest(new Uint8Array(0))).toBe(
      "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:",
    );
  });
});

// --- The profile of Layer 1, 13.3 ---------------------------------------

const ada = new KeyMind("ada");
const eve = new KeyMind("eve");

const keyRef = (mind: Mind, key = 0, position?: number): string =>
  formatKeyRef(mind.address, mind.versionId(position), mind.operational(key).publicKey);

function serverAt(seconds: number, minds: readonly Mind[] = [ada, eve]) {
  const book = new LogBook(witness(minds.map((mind) => mind.events)));
  for (const mind of minds) book.hold(mind.events, LATER);
  const nonces = new RequestNonces();
  const server: RequestVerifier = { now: at(seconds), view: book, nonces };
  return { server, nonces };
}

const drain: HttpRequest = {
  method: "GET",
  url: "https://mailbox.example/oip/mbox/abc?after=17",
  headers: [["Accept", "application/oip+json"]],
};
const publish: HttpRequest = {
  method: "POST",
  url: "https://resolver.example/oip/publish",
  headers: [["Content-Type", "application/oip+json"]],
  body: utf8('{"oip":"1","type":"Location"}'),
};

/** The request with the fields a mind's signature adds, made at `seconds`. */
async function signed(
  request: HttpRequest,
  by: Mind = ada,
  seconds = 100,
  more: { nonce?: string; label?: string; keyRef?: string; signer?: SyncSigner } = {},
): Promise<HttpRequest> {
  const added = await signRequest(
    request,
    {
      keyRef: more.keyRef ?? keyRef(by),
      created: at(seconds),
      nonce: more.nonce ?? "nonce-0001",
      ...(more.label === undefined ? {} : { label: more.label }),
    },
    more.signer ?? by.operational(),
  );
  return { ...request, headers: [...request.headers, ...added] };
}

function refusal(request: HttpRequest, server: RequestVerifier) {
  const result = verifyRequest(request, server);
  if (result.ok) throw new Error("the request was authenticated");
  return { clause: result.issues[0].clause, path: result.issues[0].path };
}

const header = (request: HttpRequest, name: string): string =>
  request.headers.find(([given]) => given.toLowerCase() === name)?.[1] ?? "";

/** The request with one header field's value changed. */
const withHeader = (request: HttpRequest, name: string, change: (value: string) => string) => ({
  ...request,
  headers: request.headers.map(
    ([given, value]) => [given, given.toLowerCase() === name ? change(value) : value] as const,
  ),
});

describe(`${clause("L1 13.3")} an authenticated request`, () => {
  it("is signed over its method and its target, and authenticates the mind whose key signed", async () => {
    const request = await signed(drain);
    expect(header(request, "signature-input")).toMatch(
      /^oip=\("@method" "@target-uri"\);created=\d+;expires=\d+;nonce="nonce-0001";keyid="did:oip:[^"]+";alg="ed25519"$/u,
    );
    const { server } = serverAt(110);
    expect(verifyRequest(request, server)).toStrictEqual({
      ok: true,
      value: {
        mind: ada.address,
        keyid: keyRef(ada),
        label: "oip",
        nonce: "nonce-0001",
        expires: at(400),
      },
    });
  });

  it("covers the digest of its body, when it has one", async () => {
    const request = await signed(publish);
    expect(header(request, "signature-input")).toContain(
      '("@method" "@target-uri" "content-digest")',
    );
    expect(header(request, "content-digest")).toBe(contentDigest(publish.body!));
    expect(verifyRequest(request, serverAt(110).server).ok).toBe(true);
    // Another body under the same digest and signature.
    const swapped = { ...request, body: utf8('{"oip":"1","type":"Participant"}') };
    expect(refusal(swapped, serverAt(110).server)).toStrictEqual({
      clause: "L1 13.3",
      path: "/content-digest",
    });
    // A body, and the digest that goes with it, under the old signature.
    const redigested = withHeader(swapped, "content-digest", () => contentDigest(swapped.body));
    expect(refusal(redigested, serverAt(110).server).path).toBe("/signature/oip");
    // A body added to a request that was signed without one.
    const grown = { ...(await signed(drain)), body: utf8("{}") };
    expect(refusal(grown, serverAt(110).server).path).toBe("/signature-input/oip");
  });

  it("is for one method and one target", async () => {
    const request = await signed(drain);
    const { server } = serverAt(110);
    for (const other of [
      { ...request, method: "DELETE" },
      { ...request, url: "https://mailbox.example/oip/mbox/abc?after=18" },
      { ...request, url: "https://mailbox.example/oip/mbox/abd?after=17" },
      { ...request, url: "https://other.example/oip/mbox/abc?after=17" },
      { ...request, url: "http://mailbox.example/oip/mbox/abc?after=17" },
    ]) {
      expect(refusal(other, server)).toStrictEqual({ clause: "L1 13.3", path: "/signature/oip" });
    }
  });

  it("is made within 300 seconds of the server's clock, and has not expired", async () => {
    const request = await signed(drain, ada, 1000);
    // It expires 300 seconds after it was made.
    expect(verifyRequest(request, serverAt(1300).server).ok).toBe(true);
    expect(refusal(request, serverAt(1300.5).server)).toStrictEqual({
      clause: "L1 13.3",
      path: "/signature-input/oip/expires",
    });
    // Made in the server's future, by as much as clocks may differ and no more.
    expect(verifyRequest(request, serverAt(700).server).ok).toBe(true);
    expect(refusal(request, serverAt(699.5).server)).toStrictEqual({
      clause: "L1 13.3",
      path: "/signature-input/oip/created",
    });
  });

  it("has `created`, `expires` at most 300 seconds later, and a nonce", async () => {
    const request = await signed(drain);
    const original = header(request, "signature-input");
    /** The request signed again by Ada, with its signature's input changed. */
    const resigned = (change: (input: string) => string): HttpRequest => {
      const input = change(original);
      const base = signatureBase(drain, listOf(input, "oip"));
      if (!base.ok) throw new Error(JSON.stringify(base.issues));
      const made = bytesToBase64(ada.operational().sign(utf8(base.value)));
      return {
        ...drain,
        headers: [...drain.headers, ["Signature-Input", input], ["Signature", `oip=:${made}:`]],
      };
    };
    // A server for each question, so that no nonce is seen twice.
    const passes = (change: (input: string) => string) =>
      verifyRequest(resigned(change), serverAt(110).server).ok;
    const refused = (change: (input: string) => string) =>
      refusal(resigned(change), serverAt(110).server);

    // Signed again as it was, it passes: what follows is refused for what was changed.
    expect(passes((input) => input)).toBe(true);
    const missing = { clause: "L1 13.3", path: "/signature-input/oip" };
    for (const parameter of [
      /;created=\d+/u,
      /;expires=\d+/u,
      /;nonce="[^"]+"/u,
      /;keyid="[^"]+"/u,
    ]) {
      expect(
        refused((input) => input.replace(parameter, "")),
        String(parameter),
      ).toStrictEqual(missing);
    }
    // A `created` that is no integer is none.
    expect(refused((input) => input.replace(/;created=(\d+)/u, ';created="$1"'))).toStrictEqual(
      missing,
    );

    const created = Number(/created=(\d+)/u.exec(original)?.[1]);
    const expiring = (seconds: number) => (input: string) =>
      input.replace(/expires=\d+/u, `expires=${created + seconds}`);
    expect(passes(expiring(300))).toBe(true);
    for (const seconds of [301, 0, -5]) {
      expect(refused(expiring(seconds)), String(seconds)).toStrictEqual({
        clause: "L1 13.3",
        path: "/signature-input/oip/expires",
      });
    }

    // The algorithm is Ed25519: named so, or not named.
    expect(passes((input) => input.replace(';alg="ed25519"', ""))).toBe(true);
    for (const alg of [';alg="rsa-pss-sha512"', ";alg=ed25519", ";alg"]) {
      expect(
        refused((input) => input.replace(';alg="ed25519"', alg)),
        alg,
      ).toStrictEqual({
        clause: "L1 13.3",
        path: "/signature-input/oip/alg",
      });
    }

    // The method and the target are covered, whatever else is.
    expect(passes((input) => input.replace('"@target-uri"', '"@target-uri" "accept"'))).toBe(true);
    for (const less of ['("@method")', '("@target-uri")', "()"]) {
      expect(
        refused((input) => input.replace('("@method" "@target-uri")', less)),
        less,
      ).toStrictEqual(missing);
    }
  });

  it("is signed by the key it names, which is a key of the mind now", async () => {
    const { server } = serverAt(110);
    // Eve signs, and names Ada's key.
    const forged = await signed(drain, ada, 100, { signer: eve.operational() });
    expect(refusal(forged, server)).toStrictEqual({ clause: "L1 13.3", path: "/signature/oip" });
    // Eve signs with her own key, under Ada's address.
    const borrowed = await signed(drain, eve, 100, {
      keyRef: formatKeyRef(ada.address, ada.versionId(), eve.operational().publicKey),
    });
    expect(refusal(borrowed, server)).toStrictEqual({ clause: "L1 6.1", path: "" });
    // A key the mind has removed signs no request, whenever the request says it was made.
    const zed = new KeyMind("zed");
    const old = await signed(drain, zed, 100);
    zed.update(50, { keys: [{ key: zed.operational(1).publicKey }] });
    expect(refusal(old, serverAt(110, [zed]).server).clause).toBe("L1 6.1");
    const current = await signed(drain, zed, 100, {
      keyRef: keyRef(zed, 1),
      signer: zed.operational(1),
    });
    expect(verifyRequest(current, serverAt(110, [zed]).server).ok).toBe(true);
    // A mind whose log the server does not hold.
    expect(verifyRequest(await signed(drain), serverAt(110, [eve]).server).ok).toBe(false);
    // A `keyid` that is no key reference.
    const named = withHeader(await signed(drain), "signature-input", (input) =>
      input.replace(/keyid="[^"]+"/u, 'keyid="test-key-ed25519"'),
    );
    expect(refusal(named, server)).toStrictEqual({
      clause: "L1 13.3",
      path: "/signature-input/oip/keyid",
    });
  });

  it("is accepted once: the key cannot use its nonce again while the signature is valid", async () => {
    const request = await signed(drain);
    const { server, nonces } = serverAt(110);
    expect(verifyRequest(request, server).ok).toBe(true);
    expect(nonces.size).toBe(1);
    expect(refusal(request, server)).toStrictEqual({
      clause: "L1 13.3",
      path: "/signature-input/oip/nonce",
    });
    // Another request with the same nonce, and another key with it.
    const other = await signed({ ...drain, method: "DELETE" });
    expect(refusal(other, server).path).toBe("/signature-input/oip/nonce");
    expect(verifyRequest(await signed(drain, eve), server).ok).toBe(true);
    expect(verifyRequest(await signed(drain, ada, 100, { nonce: "nonce-0002" }), server).ok).toBe(
      true,
    );
    // A request that fails uses no nonce up.
    const fresh = serverAt(110);
    expect(verifyRequest({ ...request, method: "PUT" }, fresh.server).ok).toBe(false);
    expect(fresh.nonces.size).toBe(0);
    expect(verifyRequest(request, fresh.server).ok).toBe(true);
  });

  it("is authenticated by the first of its signatures that passes", async () => {
    const first = await signed(drain, eve, 100, { label: "proxy", signer: ada.operational() });
    const second = await signed(drain, ada, 100, { label: "mind" });
    const both: HttpRequest = {
      ...drain,
      headers: [
        ...drain.headers,
        [
          "Signature-Input",
          `${header(first, "signature-input")}, ${header(second, "signature-input")}`,
        ],
        ["Signature", `${header(first, "signature")}, ${header(second, "signature")}`],
      ],
    };
    const result = verifyRequest(both, serverAt(110).server);
    expect(result.ok && result.value).toMatchObject({ mind: ada.address, label: "mind" });
    // With none that passes, the answer is about the first.
    const neither = withHeader(both, "signature-input", (input) =>
      input.replace(/mind=/u, "other="),
    );
    expect(refusal(neither, serverAt(110).server).path).toBe("/signature/proxy");
    // The fields may come in any case, and in several instances.
    const split: HttpRequest = {
      ...drain,
      headers: [
        ["SIGNATURE-INPUT", header(first, "signature-input")],
        ["signature-input", header(second, "signature-input")],
        ["SIGNATURE", header(first, "signature")],
        ["signature", header(second, "signature")],
      ],
    };
    expect(verifyRequest(split, serverAt(110).server).ok).toBe(true);
  });

  it("is not authenticated without a signature that can be read", async () => {
    const { server } = serverAt(110);
    const none = { clause: "L1 13.3", path: "/signature-input" };
    expect(refusal(drain, server)).toStrictEqual(none);
    const request = await signed(drain);
    expect(
      refusal(
        withHeader(request, "signature", () => "oip=broken"),
        server,
      ),
    ).toStrictEqual(none);
    expect(
      refusal(
        withHeader(request, "signature-input", (input) => `${input},`),
        server,
      ),
    ).toStrictEqual(none);
    // A signature under another label than its input.
    const relabelled = withHeader(request, "signature", (value) => value.replace("oip=", "sig="));
    expect(refusal(relabelled, server)).toStrictEqual(none);
  });

  it("never throws on what arrives", () => {
    const { server } = serverAt(110);
    for (const request of [
      undefined,
      null,
      7,
      "GET /",
      {},
      { method: "GET" },
      { ...drain, headers: [[1, 2]] },
    ]) {
      expect(verifyRequest(request as never, server).ok, JSON.stringify(request)).toBe(false);
    }
    fc.assert(
      fc.property(fc.string(), fc.string(), fc.string(), (method, input, signature) => {
        const request = {
          method,
          url: drain.url,
          headers: [
            ["signature-input", input],
            ["signature", signature],
          ],
        } as HttpRequest;
        expect(verifyRequest(request, server).ok).toBe(false);
      }),
      { numRuns: 300 },
    );
    expect(() => verifyRequest(drain, { ...server, now: 110 as never })).toThrow(TypeError);
  });
});

describe(`${clause("L1 13.3")} signing a request`, () => {
  const good = { keyRef: keyRef(ada), created: at(100), nonce: "nonce-0001" };
  const sign = (signature: object, request: HttpRequest = drain) =>
    signRequest(request, signature as never, ada.operational());

  it("is for at most 300 seconds, with a key reference, a nonce and a label that can be written", async () => {
    await expect(sign({ ...good, expires: at(400) })).resolves.toHaveLength(2);
    for (const wrong of [
      { ...good, expires: at(401) },
      { ...good, expires: at(100) },
      { ...good, expires: at(50) },
      { ...good, created: 100 },
      { ...good, keyRef: "test-key-ed25519" },
      { ...good, keyRef: ada.address },
      { ...good, nonce: "" },
      { ...good, nonce: "café" },
      { ...good, nonce: 7 },
      { ...good, label: "Sig" },
      { ...good, label: "" },
    ]) {
      await expect(
        sign(wrong),
        JSON.stringify(wrong, (_, v: unknown) => (typeof v === "bigint" ? String(v) : v)),
      ).rejects.toThrow(TypeError);
    }
    // A request whose target is no URI cannot be signed.
    await expect(sign(good, { ...drain, url: "/oip/mbox" })).rejects.toThrow(TypeError);
  });

  it("writes a nonce with quotes and backslashes so that it reads back as it was", async () => {
    const nonce = 'a "quoted" \\ nonce';
    const request = await signed(drain, ada, 100, { nonce });
    const result = verifyRequest(request, serverAt(110).server);
    expect(result.ok && result.value.nonce).toBe(nonce);
  });

  it("replaces a digest the request already carries with the digest of its body", async () => {
    const stale: HttpRequest = {
      ...publish,
      headers: [...publish.headers, ["Content-Digest", contentDigest(utf8("another body"))]],
    };
    const added = await signRequest(stale, good, ada.operational());
    expect(added.map(([name]) => name)).toStrictEqual([
      "Content-Digest",
      "Signature-Input",
      "Signature",
    ]);
    // The caller sends the request with the new field in place of the old.
    const sent: HttpRequest = { ...publish, headers: [...publish.headers, ...added] };
    expect(verifyRequest(sent, serverAt(110).server).ok).toBe(true);
  });
});

describe(`${clause("L1 13.3")} the nonces a server has seen`, () => {
  it("are remembered for each key until the signature that used them expires", () => {
    const nonces = new RequestNonces();
    nonces.remember("key-a", "nonce-1", at(400));
    nonces.remember("key-b", "nonce-1", at(500));
    expect(nonces.seen("key-a", "nonce-1")).toBe(true);
    expect(nonces.seen("key-a", "nonce-2")).toBe(false);
    expect(nonces.seen("key-c", "nonce-1")).toBe(false);
    expect(nonces.forget(at(400))).toBe(0);
    expect(nonces.forget(at(401))).toBe(1);
    expect(nonces.seen("key-a", "nonce-1")).toBe(false);
    expect(nonces.seen("key-b", "nonce-1")).toBe(true);
    expect(nonces.size).toBe(1);
    expect(() => nonces.forget(401 as never)).toThrow(TypeError);
  });
});
