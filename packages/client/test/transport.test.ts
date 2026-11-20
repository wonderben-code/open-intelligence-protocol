// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { MEDIA_TYPE, OipError, PROBLEM_MEDIA_TYPE, utf8 } from "@oip/core";
import { intentBy, KeyMind } from "@oip/testkit/minds";
import { describe, expect, it, vi } from "vitest";

import {
  askJson,
  askRecord,
  exchange,
  type Fetch,
  httpsOrigin,
  MAX_DETAIL_LENGTH,
  recordBody,
  TransportError,
} from "../src/index.ts";

const URL_ = "https://resolver.example/oip/v1/resolve/abc";

/** A service that answers every request the same way. */
const answering =
  (body: string | Uint8Array | ReadableStream<Uint8Array>, init: ResponseInit = {}): Fetch =>
  () =>
    Promise.resolve(new Response(body, init));

/** A record a service might serve: an Intent its author signed. */
const ada = new KeyMind("ada");
const record = JSON.parse(JSON.stringify(ada.sign(intentBy(ada, 10)))) as object;

/** What a call is refused with: the failure of a `TransportError`, or the code of an `OipError`. */
async function refusal(work: () => Promise<unknown>): Promise<string> {
  try {
    await work();
  } catch (error) {
    if (error instanceof TransportError) return `transport: ${error.failure}`;
    if (error instanceof OipError) return `oip: ${error.code}`;
    throw error;
  }
  throw new Error("nothing was refused");
}

describe("a request to a service", () => {
  it("is made over HTTPS, to a URL with nobody's name or password in it", async () => {
    expect(httpsOrigin(URL_)).toBe("https://resolver.example");
    expect(httpsOrigin("https://resolver.example:8443/x?y#z")).toBe(
      "https://resolver.example:8443",
    );
    for (const url of [
      "http://resolver.example/",
      "ftp://resolver.example/",
      "https://user@resolver.example/",
      "https://user:secret@resolver.example/",
      "resolver.example",
      "",
      "//resolver.example/",
    ]) {
      expect(httpsOrigin(url), url).toBeUndefined();
      let asked = false;
      const fetch: Fetch = () => {
        asked = true;
        return Promise.resolve(new Response("{}"));
      };
      expect(await refusal(() => exchange({ method: "GET", url }, { fetch })), url).toBe(
        "transport: url",
      );
      expect(asked).toBe(false);
    }
  });

  it("says what it accepts and what it sends, follows no redirect, and is given up in time", async () => {
    const seen: Request[] = [];
    const fetch: Fetch = (request) => {
      seen.push(request);
      return Promise.resolve(
        new Response("{}", { headers: { "content-type": "application/json" } }),
      );
    };
    await exchange({ method: "GET", url: URL_ }, { fetch });
    await exchange(
      {
        method: "PUT",
        url: URL_,
        body: recordBody(record),
        headers: [
          ["signature", "sig1=:AAAA:"],
          ["signature-input", "sig1=()"],
        ],
      },
      { fetch },
    );
    const [get, put] = seen;
    expect(get?.method).toBe("GET");
    expect(get?.redirect).toBe("error");
    expect(get?.signal.aborted).toBe(false);
    expect(get?.headers.get("accept")).toBe(
      `${MEDIA_TYPE}, ${PROBLEM_MEDIA_TYPE}, application/json`,
    );
    expect(get?.headers.get("content-type")).toBeNull();
    expect(put?.method).toBe("PUT");
    expect(put?.headers.get("content-type")).toBe(MEDIA_TYPE);
    expect(put?.headers.get("signature")).toBe("sig1=:AAAA:");
    expect(put?.headers.get("signature-input")).toBe("sig1=()");
    expect(JSON.parse((await put?.text()) ?? "")).toStrictEqual(record);
  });

  it("gives the status, the media type and the body of the answer", async () => {
    const answer = await exchange(
      { method: "GET", url: URL_ },
      {
        fetch: answering("hello", {
          status: 429,
          headers: { "content-type": "Text/Plain; charset=utf-8", "retry-after": "7" },
        }),
      },
    );
    expect(answer).toStrictEqual({
      origin: "https://resolver.example",
      status: 429,
      mediaType: "text/plain",
      body: utf8("hello"),
      retryAfter: "7",
    });
    const bare = await exchange(
      { method: "DELETE", url: URL_ },
      { fetch: () => Promise.resolve(new Response(null, { status: 204 })) },
    );
    expect(bare).toStrictEqual({
      origin: "https://resolver.example",
      status: 204,
      mediaType: "",
      body: new Uint8Array(),
      retryAfter: undefined,
    });
  });

  it("fails as unreachable if nothing answers, or the answer is a redirect, or it breaks off", async () => {
    const failing: Fetch = () => Promise.reject(new TypeError("fetch failed"));
    expect(await refusal(() => exchange({ method: "GET", url: URL_ }, { fetch: failing }))).toBe(
      "transport: unreachable",
    );
    for (const status of [301, 302, 307, 308]) {
      const redirecting = answering("", { status, headers: { location: "https://evil.example/" } });
      const error = await exchange({ method: "GET", url: URL_ }, { fetch: redirecting }).catch(
        (thrown: unknown) => thrown,
      );
      expect(error).toBeInstanceOf(TransportError);
      expect(error).toMatchObject({
        failure: "unreachable",
        status,
        origin: "https://resolver.example",
      });
    }
    const broken = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(utf8("{"));
        controller.error(new Error("connection reset"));
      },
    });
    expect(
      await refusal(() => exchange({ method: "GET", url: URL_ }, { fetch: answering(broken) })),
    ).toBe("transport: unreachable");
  });

  it("fails as timed out if no answer comes in time, or the answer does not end in time", async () => {
    const never: Fetch = (request) =>
      new Promise((_, reject) => {
        request.signal.addEventListener("abort", () => {
          reject(new DOMException("aborted", "AbortError"));
        });
      });
    expect(
      await refusal(() => exchange({ method: "GET", url: URL_ }, { fetch: never, timeoutMs: 20 })),
    ).toBe("transport: timeout");
    // The headers come, and the body never ends.
    const dripping: Fetch = (request) =>
      Promise.resolve(
        new Response(
          new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(utf8("{"));
              request.signal.addEventListener("abort", () => {
                controller.error(new DOMException("aborted", "AbortError"));
              });
            },
          }),
        ),
      );
    expect(
      await refusal(() =>
        exchange({ method: "GET", url: URL_ }, { fetch: dripping, timeoutMs: 20 }),
      ),
    ).toBe("transport: timeout");
  });

  it("reads no more of an answer than it was told to, whatever the answer says of its length", async () => {
    const big = "x".repeat(1025);
    // It says how long it is.
    const declared = answering(big, { headers: { "content-length": "1025" } });
    expect(
      await refusal(() =>
        exchange({ method: "GET", url: URL_ }, { fetch: declared, maxBytes: 1024 }),
      ),
    ).toBe("transport: too-large");
    // It does not say, and goes on for ever.
    let sent = 0;
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        sent += 1;
        controller.enqueue(new Uint8Array(512));
      },
    });
    expect(
      await refusal(() =>
        exchange({ method: "GET", url: URL_ }, { fetch: answering(endless), maxBytes: 1024 }),
      ),
    ).toBe("transport: too-large");
    // It stopped reading once it had too much.
    expect(sent).toBeLessThan(8);
    // An answer of exactly the most that is read is read.
    const most = await exchange(
      { method: "GET", url: URL_ },
      { fetch: answering("x".repeat(1024)), maxBytes: 1024 },
    );
    expect(most.body).toHaveLength(1024);
  });
});

describe("the platform's fetch", () => {
  it("makes the request, unless a client is given something else to make it", async () => {
    const seen: string[] = [];
    vi.stubGlobal("fetch", (request: Request) => {
      seen.push(request.url);
      return Promise.resolve(
        new Response("{}", { headers: { "content-type": "application/json" } }),
      );
    });
    try {
      expect(await askJson({ method: "GET", url: URL_ })).toStrictEqual({});
      expect(seen).toStrictEqual([URL_]);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("what a service answers", () => {
  const problem = (type: unknown, more: object = {}, status = 400): Fetch =>
    answering(JSON.stringify({ type, title: "A title", status, ...more }), {
      status,
      headers: { "content-type": PROBLEM_MEDIA_TYPE },
    });

  it("is a record, read as one, when it is asked for a record", async () => {
    const fetch = answering(JSON.stringify(record), { headers: { "content-type": MEDIA_TYPE } });
    expect(await askRecord({ method: "GET", url: URL_ }, { fetch })).toStrictEqual(record);
    // With a parameter on the media type it is a record still.
    const charset = answering(JSON.stringify(record), {
      headers: { "content-type": `${MEDIA_TYPE}; charset=utf-8` },
    });
    expect(await askRecord({ method: "GET", url: URL_ }, { fetch: charset })).toStrictEqual(record);
  });

  it("is refused as no record if it is something else, however it is labelled", async () => {
    const labelled = (body: string, type = MEDIA_TYPE) =>
      answering(body, { headers: { "content-type": type } });
    for (const body of [
      "not JSON",
      "[]",
      '{"oip":"1"}',
      '{"oip":"1","type":"Intent","n":1.5}',
      '{"a":1,"a":2}',
    ]) {
      const error = await askRecord({ method: "GET", url: URL_ }, { fetch: labelled(body) }).catch(
        (thrown: unknown) => thrown,
      );
      expect(error, body).toBeInstanceOf(OipError);
      expect(error, body).toMatchObject({ code: "invalid-record" });
      expect((error as OipError).detail).toMatch(
        /^https:\/\/resolver\.example served what is not a record: /u,
      );
      expect((error as OipError).issues.length).toBeGreaterThan(0);
    }
    for (const type of ["application/json", "text/html", ""]) {
      expect(
        await refusal(() =>
          askRecord(
            { method: "GET", url: URL_ },
            { fetch: labelled(JSON.stringify(record), type) },
          ),
        ),
        type,
      ).toBe("transport: not-oip");
    }
  });

  it("is the service's own refusal, with its code, when it is a problem of the protocol", async () => {
    const codes = [
      "invalid-record",
      "invalid-proof",
      "unsupported-critical",
      "expired",
      "stale-version",
      "duplicity",
      "unauthorised",
      "forbidden",
      "not-found",
      "too-large",
      "rate-limited",
    ];
    for (const code of codes) {
      const fetch = problem(`urn:oip:error:${code}`, { detail: "The service says why." });
      const error = await askRecord({ method: "GET", url: URL_ }, { fetch }).catch(
        (thrown: unknown) => thrown,
      );
      expect(error, code).toBeInstanceOf(OipError);
      expect(error, code).toMatchObject({
        code,
        detail: "https://resolver.example answered: The service says why.",
      });
    }
    // Without a detail the title stands for it, and without either the code does.
    const titled = await askJson(
      { method: "GET", url: URL_ },
      { fetch: problem("urn:oip:error:forbidden") },
    ).catch((thrown: unknown) => thrown);
    expect(titled).toMatchObject({ detail: "https://resolver.example answered: A title" });
    const bare = await askJson(
      { method: "GET", url: URL_ },
      { fetch: problem("urn:oip:error:forbidden", { title: 7 }) },
    ).catch((thrown: unknown) => thrown);
    expect(bare).toMatchObject({ detail: "https://resolver.example answered: forbidden" });
  });

  it("keeps a stranger's words short and plain", async () => {
    const detail = `Line one\nline two\u0007 ‮${"x".repeat(1000)}`;
    const error = (await askRecord(
      { method: "GET", url: URL_ },
      { fetch: problem("urn:oip:error:invalid-proof", { detail }) },
    ).catch((thrown: unknown) => thrown)) as OipError;
    const said = error.detail.slice("https://resolver.example answered: ".length);
    expect(said).toHaveLength(MAX_DETAIL_LENGTH);
    expect(said.startsWith("Line one line two")).toBe(true);
    expect(said.endsWith("…")).toBe(true);
    expect(/^[\x20-\x7e…]*$/u.test(said)).toBe(true);
    // Words with nothing printable in them are no words: the title stands for them.
    const blank = (await askRecord(
      { method: "GET", url: URL_ },
      { fetch: problem("urn:oip:error:invalid-proof", { detail: "\u0007\n\u202e " }) },
    ).catch((thrown: unknown) => thrown)) as OipError;
    expect(blank.detail).toBe("https://resolver.example answered: A title");
  });

  it("is no answer of the protocol if it fails without a problem a client knows", async () => {
    const cases: Fetch[] = [
      answering("Bad gateway", { status: 502, headers: { "content-type": "text/html" } }),
      problem("https://example.com/probs/out-of-credit"),
      problem("urn:oip:error:made-up"),
      problem(7),
      answering("not JSON", { status: 400, headers: { "content-type": PROBLEM_MEDIA_TYPE } }),
      answering("[]", { status: 400, headers: { "content-type": PROBLEM_MEDIA_TYPE } }),
      answering("", { status: 500 }),
    ];
    for (const fetch of cases) {
      const error = await askRecord({ method: "GET", url: URL_ }, { fetch }).catch(
        (thrown: unknown) => thrown,
      );
      expect(error).toBeInstanceOf(TransportError);
      expect(error).toMatchObject({ failure: "not-oip", origin: "https://resolver.example" });
      expect((error as TransportError).status).toBeGreaterThanOrEqual(400);
    }
  });

  it("is JSON, when it is asked for what a service stored or took in", async () => {
    const json = (body: string, type = "application/json", status = 202) =>
      answering(body, { status, headers: { "content-type": type } });
    expect(
      await askJson({ method: "PUT", url: URL_ }, { fetch: json('{"added":2}') }),
    ).toStrictEqual({
      added: 2,
    });
    expect(
      await askJson(
        { method: "POST", url: URL_ },
        { fetch: json(JSON.stringify(record), MEDIA_TYPE) },
      ),
    ).toStrictEqual(record);
    expect(
      await refusal(() =>
        askJson({ method: "PUT", url: URL_ }, { fetch: json("{", "application/json") }),
      ),
    ).toBe("transport: not-oip");
    expect(
      await refusal(() =>
        askJson({ method: "PUT", url: URL_ }, { fetch: json("{}", "text/plain") }),
      ),
    ).toBe("transport: not-oip");
    expect(
      await refusal(() => askJson({ method: "PUT", url: URL_ }, { fetch: json('{"n":1.5}') })),
    ).toBe("transport: not-oip");
  });

  it("names the origin it asked in its errors, and never the path", async () => {
    const error = (await exchange(
      { method: "GET", url: "https://resolver.example/oip/v1/resolve/a-private-path?token=secret" },
      { fetch: () => Promise.reject(new TypeError("fetch failed")) },
    ).catch((thrown: unknown) => thrown)) as TransportError;
    expect(error.message).toBe("https://resolver.example: the service could not be reached");
    expect(error.origin).toBe("https://resolver.example");
    expect(error.name).toBe("TransportError");
  });
});
