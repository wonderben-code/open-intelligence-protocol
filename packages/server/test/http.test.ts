// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { MEDIA_TYPE, OipError, PROBLEM_CODES, PROBLEM_MEDIA_TYPE, PROBLEMS } from "@oip/core";
import { noteCutShort } from "@oip/schema";
import { clause } from "@oip/testkit";
import { intentBy, KeyMind, T } from "@oip/testkit/minds";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  HttpFailure,
  problemResponse,
  readBody,
  readJson,
  readRecord,
  recordResponse,
  responseFor,
  StorageError,
  Unavailable,
} from "../src/index.ts";

const ada = new KeyMind("ada");
const intent = ada.sign(intentBy(ada, 10));

function post(
  body: string | Uint8Array | ReadableStream<Uint8Array> | null,
  headers: Record<string, string> = {},
): Request {
  return new Request("https://host.example/inbox", {
    method: "POST",
    body,
    headers: { "content-type": MEDIA_TYPE, ...headers },
    // A body that is a stream is sent as it comes.
    ...(body instanceof ReadableStream ? { duplex: "half" } : {}),
  });
}

/** A body sent in pieces, which says how many of them were asked for. */
function inPieces(pieces: readonly Uint8Array[]): {
  body: ReadableStream<Uint8Array>;
  asked: () => number;
} {
  let asked = 0;
  const body = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        const piece = pieces[asked];
        if (piece === undefined) controller.close();
        else controller.enqueue(piece);
        asked++;
      },
    },
    // Nothing is taken before it is asked for.
    { highWaterMark: 0 },
  );
  return { body, asked: () => asked };
}

async function thrownBy(work: () => Promise<unknown>): Promise<unknown> {
  try {
    await work();
  } catch (error) {
    return error;
  }
  throw new Error("nothing was thrown");
}

describe(`${clause("core 10.2")} the answer to a failure`, () => {
  it("is problem details with the type, title and status of its code", async () => {
    for (const code of PROBLEM_CODES) {
      const { response, unexpected } = responseFor(new OipError(code, "what went wrong"));
      expect(unexpected).toBe(false);
      expect(response.status).toBe(PROBLEMS[code].status);
      expect(response.headers.get("content-type")).toBe(PROBLEM_MEDIA_TYPE);
      expect(await response.json()).toStrictEqual({
        type: `urn:oip:error:${code}`,
        title: PROBLEMS[code].title,
        status: PROBLEMS[code].status,
        detail: "what went wrong",
      });
    }
  });

  it("carries the reasons a record was refused for, and nothing of what caused the error", async () => {
    const issues = [
      { path: "/author", message: "not a mind address", clause: "core 7.1" },
    ] as const;
    const error = new OipError("invalid-record", "/author: not a mind address", {
      issues,
      cause: new Error("the seed is 0102"),
    });
    const body = JSON.stringify(await responseFor(error).response.json());
    expect(JSON.parse(body)).toMatchObject({ issues });
    expect(body).not.toContain("seed");
    expect(body).not.toContain("stack");
  });

  it("says nothing of a failure nobody expected, and says that it was one", async () => {
    for (const error of [
      new Error("the key file /secrets/ed25519 could not be read"),
      new TypeError("x is not a function"),
      new StorageError("the database was not made by this program's migrations"),
      "a string",
      undefined,
      { status: 200 },
    ]) {
      const { response, unexpected } = responseFor(error);
      expect(unexpected).toBe(true);
      expect(response.status).toBe(500);
      expect(response.headers.get("content-type")).toBe(PROBLEM_MEDIA_TYPE);
      expect(await response.json()).toStrictEqual({
        type: "about:blank",
        title: "Internal Server Error",
        status: 500,
      });
    }
  });

  it("is 503 with a time to ask again where the failure will pass", async () => {
    const cases: [unknown, string][] = [
      [new Unavailable("cut short"), "1"],
      [new Unavailable("later", 30), "30"],
      // A database that another writer holds, as `node:sqlite` reports it.
      [Object.assign(new Error("database is locked"), { errcode: 5 }), "1"],
    ];
    for (const [error, after] of cases) {
      const { response, unexpected } = responseFor(error);
      expect(unexpected).toBe(false);
      expect(response.status).toBe(503);
      expect(response.headers.get("retry-after")).toBe(after);
      expect(await response.json()).toStrictEqual({
        type: "about:blank",
        title: "Service Unavailable",
        status: 503,
      });
    }
  });

  it("is the status HTTP has for it where core 10.2 has no code, with its headers", async () => {
    const { response, unexpected } = responseFor(
      new HttpFailure(405, "Method Not Allowed", { allow: "GET, PUT" }),
    );
    expect(unexpected).toBe(false);
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET, PUT");
    expect(await response.json()).toStrictEqual({
      type: "about:blank",
      title: "Method Not Allowed",
      status: 405,
    });
  });

  it("keeps the media type of a problem whatever headers go with it", () => {
    const response = problemResponse(
      { type: "about:blank", title: "Gone", status: 410 },
      { "content-type": "text/html", "x-request-id": "r1" },
    );
    expect(response.headers.get("content-type")).toBe(PROBLEM_MEDIA_TYPE);
    expect(response.headers.get("x-request-id")).toBe("r1");
  });
});

describe(`${clause("core 10.1")} what an endpoint answers with`, () => {
  it("is a record as `application/oip+json`", async () => {
    const response = recordResponse(intent, 202, { "content-type": "text/plain", etag: '"1"' });
    expect(response.status).toBe(202);
    expect(response.headers.get("content-type")).toBe(MEDIA_TYPE);
    expect(response.headers.get("etag")).toBe('"1"');
    expect(await response.json()).toStrictEqual(intent);
    expect(recordResponse({ stored: true }).status).toBe(200);
  });
});

describe(`${clause("core 1.6")} the body of a request`, () => {
  const bytes = (length: number, fill = 0x20): Uint8Array => new Uint8Array(length).fill(fill);

  it("is read whole when it is within the limit", async () => {
    expect(await readBody(post(bytes(100, 7)), 100)).toStrictEqual(bytes(100, 7));
    expect(await readBody(post(null), 100)).toStrictEqual(new Uint8Array(0));
    const { body } = inPieces([bytes(3, 1), bytes(2, 2), bytes(4, 3)]);
    expect(await readBody(post(body), 9)).toStrictEqual(Uint8Array.of(1, 1, 1, 2, 2, 3, 3, 3, 3));
  });

  it("is refused unread when it declares more than the limit", async () => {
    const { body, asked } = inPieces([bytes(10)]);
    const error = await thrownBy(() => readBody(post(body, { "content-length": "101" }), 100));
    expect(error).toBeInstanceOf(OipError);
    expect((error as OipError).code).toBe("too-large");
    expect(asked()).toBe(0);
  });

  it("is read no further than the limit when it declares nothing, or less than it sends", async () => {
    for (const headers of [{}, { "content-length": "5" }]) {
      const { body, asked } = inPieces([bytes(60), bytes(60), bytes(60), bytes(60)]);
      const error = await thrownBy(() => readBody(post(body, headers), 100));
      expect((error as OipError).code).toBe("too-large");
      // The second piece passed the limit. The third and fourth were never asked for.
      expect(asked()).toBe(2);
    }
  });

  it("takes a limit that is a number of bytes", async () => {
    for (const limit of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(await thrownBy(() => readBody(post(bytes(1)), limit))).toBeInstanceOf(TypeError);
    }
    expect(await readBody(post(null), 0)).toStrictEqual(new Uint8Array(0));
    expect(((await thrownBy(() => readBody(post(bytes(1)), 0))) as OipError).code).toBe(
      "too-large",
    );
  });
});

describe(`${clause("core 10.1", "core 10.2")} the record a request carries`, () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const LIMIT = 1024 * 1024;

  it("is read by the reader of the JSON profile", async () => {
    expect(await readRecord(post(JSON.stringify(intent)), LIMIT)).toStrictEqual(intent);
    // The media type may carry parameters, and its case does not matter.
    expect(
      await readRecord(
        post(JSON.stringify(intent), { "content-type": "Application/OIP+JSON; charset=utf-8" }),
        LIMIT,
      ),
    ).toStrictEqual(intent);
  });

  it("is refused as no record of another media type, before anything is read", async () => {
    for (const type of ["application/json", "text/plain", "", "application/oip+jsonx"]) {
      const { body, asked } = inPieces([new TextEncoder().encode(JSON.stringify(intent))]);
      const error = await thrownBy(() => readRecord(post(body, { "content-type": type }), LIMIT));
      expect(error, type).toBeInstanceOf(HttpFailure);
      expect((error as HttpFailure).status).toBe(415);
      expect((error as HttpFailure).headers).toStrictEqual({ accept: MEDIA_TYPE });
      expect(asked()).toBe(0);
    }
  });

  it("is refused as `invalid-record` where it is not well formed, with the reasons", async () => {
    for (const body of ["{", "[]", '{"oip":"1","type":"Intent"}', '{"a":1,"a":2}', "﻿{}"]) {
      const error = (await thrownBy(() => readRecord(post(body), LIMIT))) as OipError;
      expect(error, body).toBeInstanceOf(OipError);
      expect(error.code).toBe("invalid-record");
      expect(error.issues.length).toBeGreaterThan(0);
      expect(error.toProblem().status).toBe(400);
    }
  });

  it("is refused as `too-large` where it is longer than the endpoint reads", async () => {
    const text = JSON.stringify(intent);
    const padded = `${" ".repeat(600)}${text}`;
    const error = (await thrownBy(() => readRecord(post(padded), 500))) as OipError;
    expect(error.code).toBe("too-large");
    expect(error.toProblem().status).toBe(413);
    expect(await readRecord(post(padded), padded.length)).toStrictEqual(intent);
  });

  it("is refused as `too-large` where its canonical form is over the limit, though its text was read", async () => {
    // Well formed, and more than 1 MiB.
    const packet = {
      oip: "1",
      type: "Packet",
      from: ada.address,
      to: [ada.address],
      created: T(20),
      expires: T(3620),
      nonce: "nonce-0001",
      purpose: { verb: "inform" },
      content: { mediaType: "text/plain", body: "x".repeat(1_100_000) },
      proof: (intent as { proof: unknown }).proof,
    };
    const error = (await thrownBy(() =>
      readRecord(post(JSON.stringify(packet)), 4 * LIMIT),
    )) as OipError;
    expect(error.code).toBe("too-large");
    expect(error.clause).toBe("core 1.6");
  });

  it("is refused as no record where the request names no media type at all", async () => {
    const bare = new Request("https://host.example/inbox", {
      method: "POST",
      body: new TextEncoder().encode(JSON.stringify(intent)),
    });
    expect(bare.headers.has("content-type")).toBe(false);
    expect(((await thrownBy(() => readRecord(bare, LIMIT))) as HttpFailure).status).toBe(415);
  });

  it("is not called malformed where the check was cut short: the client asks again", async () => {
    // A failure for want of room, noted from inside the reader, as its own `catch` notes one.
    vi.spyOn(TextDecoder.prototype, "decode").mockImplementationOnce(() => {
      noteCutShort(new RangeError("Maximum call stack size exceeded"));
      throw new RangeError("Maximum call stack size exceeded");
    });
    const error = await thrownBy(() => readRecord(post(JSON.stringify(intent)), LIMIT));
    expect(error).toBeInstanceOf(Unavailable);
    expect(responseFor(error).response.status).toBe(503);
    expect(await readRecord(post(JSON.stringify(intent)), LIMIT)).toStrictEqual(intent);
  });
});

describe("a body that is JSON and no record", () => {
  const sending = (body: string, type = "application/json"): Request =>
    new Request("https://service.example/query", {
      method: "POST",
      body,
      headers: { "content-type": type },
    });

  it("is read within the JSON profile, when it is said to be JSON and is no longer than the limit", async () => {
    expect(await readJson(sending('{"want":"a lease","limit":3}'), 100)).toStrictEqual({
      want: "a lease",
      limit: 3,
    });
    expect(await readJson(sending("[]", "Application/JSON; charset=utf-8"), 100)).toStrictEqual([]);
    for (const [body, code] of [
      ["{", "invalid-record"],
      ['{"n":1.5}', "invalid-record"],
      ['{"a":1,"a":2}', "invalid-record"],
      [`"${"x".repeat(200)}"`, "too-large"],
    ] as const) {
      const error = await thrownBy(() => readJson(sending(body), 100));
      expect(error, body).toBeInstanceOf(OipError);
      expect((error as OipError).code, body).toBe(code);
    }
    for (const type of ["application/oip+json", "text/plain", ""]) {
      const refused = (await thrownBy(() => readJson(sending("{}", type), 100))) as HttpFailure;
      expect(refused.status, type).toBe(415);
      expect(refused.headers, type).toStrictEqual({ accept: "application/json" });
    }
  });

  it("is not called malformed where the check was cut short: the client asks again", async () => {
    vi.spyOn(TextDecoder.prototype, "decode").mockImplementationOnce(() => {
      noteCutShort(new RangeError("Maximum call stack size exceeded"));
      throw new RangeError("Maximum call stack size exceeded");
    });
    expect(await thrownBy(() => readJson(sending("{}"), 100))).toBeInstanceOf(Unavailable);
    expect(await readJson(sending("{}"), 100)).toStrictEqual({});
  });
});
