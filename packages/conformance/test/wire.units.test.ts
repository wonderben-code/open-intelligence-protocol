// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The parts the suite over the wire is made of, each alone. */

import { contentId, MEDIA_TYPE, proofDigest, sha256, utf8, verifyProofs } from "@oip/core";
import { verifyRequest } from "@oip/net";
import { describe, expect, it } from "vitest";

import {
  describe as described,
  expectProblem,
  expectRefused,
  expectStatus,
  type WireAnswer,
  WireClient,
} from "../src/wire/client.ts";
import { second, WireMind, word } from "../src/wire/minds.ts";
import {
  expect as required,
  Failed,
  need,
  NotApplicable,
  present,
  Recorder,
  Skipped,
} from "../src/wire/report.ts";
import {
  expectLog,
  idOf,
  isObject,
  recordOf,
  same,
  seenTime,
  verifies,
} from "../src/wire/shapes.ts";
import { Verifier } from "../src/wire/verifier.ts";

const NOW = 1_795_000_000_000_000_000n;
const T = "2026-11-18T11:06:40Z";
/** Randomness that is the same in every run, and another for each name: hashes of a counter. */
const counting = (name = "ada"): ((bytes: number) => Uint8Array) => {
  let next = 0;
  return (bytes) => {
    const out = new Uint8Array(bytes);
    for (let at = 0; at < bytes; at += 32)
      out.set(sha256(utf8(`${name}/${next++}`)).subarray(0, bytes - at), at);
    return out;
  };
};
const mind = (name = "ada"): WireMind => WireMind.create(counting(name), T);

/** An answer, as the client reads one. */
const answer = (status: number, body: unknown, type = "application/problem+json"): WireAnswer => {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return {
    status,
    headers: new Headers({ "content-type": type }),
    bytes: new TextEncoder().encode(text),
    text,
    json: typeof body === "string" ? undefined : body,
  };
};

describe("a check and what it builds on", () => {
  it("is recorded by how its run ended", async () => {
    const suite = new Recorder("host");
    const head = (id: string) => ({ id, clauses: ["L1 13.1"] as const, title: `The ${id}` });
    expect(await suite.check(head("first"), () => 7)).toBe(7);
    expect(
      await suite.check({ ...head("second"), level: "SHOULD" }, () => Promise.resolve("x")),
    ).toBe("x");
    const failing: [string, unknown][] = [
      ["failed", new Failed("required 200; got 500")],
      ["apart", new NotApplicable("there is no mailbox")],
      ["skipped", new Skipped("nothing to build on")],
      ["broken", new TypeError("fetch failed")],
      ["thrown", "a string"],
    ];
    for (const [id, error] of failing) {
      expect(
        await suite.check(head(id), () => {
          throw error;
        }),
      ).toBeUndefined();
    }
    const report = suite.report("https://host.example", NOW, NOW + 1_500_000_000n);
    expect(report).toEqual({
      suite: "oip-conformance-wire",
      oip: "1",
      profile: "host",
      target: "https://host.example",
      started: "2026-11-18T11:06:40Z",
      finished: "2026-11-18T11:06:41.5Z",
      checks: [
        {
          id: "host/first",
          clauses: ["L1 13.1"],
          level: "MUST",
          title: "The first",
          outcome: "pass",
        },
        {
          id: "host/second",
          clauses: ["L1 13.1"],
          level: "SHOULD",
          title: "The second",
          outcome: "pass",
        },
        {
          id: "host/failed",
          clauses: ["L1 13.1"],
          level: "MUST",
          title: "The failed",
          outcome: "fail",
          detail: "required 200; got 500",
        },
        {
          id: "host/apart",
          clauses: ["L1 13.1"],
          level: "MUST",
          title: "The apart",
          outcome: "not-applicable",
          detail: "there is no mailbox",
        },
        {
          id: "host/skipped",
          clauses: ["L1 13.1"],
          level: "MUST",
          title: "The skipped",
          outcome: "skipped",
          detail: "nothing to build on",
        },
        {
          id: "host/broken",
          clauses: ["L1 13.1"],
          level: "MUST",
          title: "The broken",
          outcome: "fail",
          detail: "the check could not be completed: TypeError: fetch failed",
        },
        {
          id: "host/thrown",
          clauses: ["L1 13.1"],
          level: "MUST",
          title: "The thrown",
          outcome: "fail",
          detail: "the check could not be completed: a string",
        },
      ],
      summary: { pass: 2, fail: 3, "not-applicable": 1, skipped: 1 },
      conforms: false,
    });
    // The report is JSON as it stands.
    expect(JSON.parse(JSON.stringify(report))).toEqual(report);
  });

  it("conforms when what is required passed or did not apply, whatever is recommended", async () => {
    const outcomes: [Error | undefined, "MUST" | "SHOULD", boolean][] = [
      [undefined, "MUST", true],
      [new NotApplicable("no"), "MUST", true],
      [new Failed("no"), "SHOULD", true],
      [new Skipped("no"), "SHOULD", true],
      [new Failed("no"), "MUST", false],
      [new Skipped("no"), "MUST", false],
    ];
    for (const [error, level, conforms] of outcomes) {
      const suite = new Recorder("resolver");
      await suite.check({ id: "one", clauses: ["L1 17.1"], title: "One", level }, () => {
        if (error !== undefined) throw error;
      });
      expect(suite.report("x", NOW, NOW).conforms).toBe(conforms);
    }
    expect(new Recorder("indexer").report("x", NOW, NOW).conforms).toBe(true);
  });

  it("has what it needs, or says what it lacks", () => {
    expect(need(0, "a count")).toBe(0);
    expect(() => need(undefined, "a bundle")).toThrow(
      new Skipped("it builds on a bundle, which the suite did not get"),
    );
    expect(present("")).toBe("");
    expect(() => present(undefined)).toThrow(TypeError);
    expect(() => {
      required(true, "never said");
    }).not.toThrow();
    expect(() => {
      required(false, "required a thing");
    }).toThrow(new Failed("required a thing"));
    expect([new Failed("x").name, new Skipped("x").name, new NotApplicable("x").name]).toEqual([
      "Failed",
      "Skipped",
      "NotApplicable",
    ]);
  });
});

describe("a mind of the suite", () => {
  it("has a log that verifies, and keys of its own", () => {
    const ada = mind();
    ada.update("2026-11-18T11:06:41Z");
    ada.update("2026-11-18T11:06:42Z");
    expect(ada.events).toHaveLength(3);
    expect(ada.address).toBe(`did:oip:${ada.id}`);
    expect(ada.id).toBe(contentId(ada.genesis));
    expect(verifies(ada.events, NOW)).toBe(true);
    expect(ada.keyRef).toBe(`${ada.address}?versionId=${ada.versionId}#${ada.signer.publicKey}`);
    expect(ada.versionId.startsWith("2-")).toBe(true);
    // Another mind has other keys, though it is made from the same kind of randomness.
    const random = counting();
    const [one, two] = [WireMind.create(random, T), WireMind.create(random, T)];
    expect(one.address).not.toBe(two.address);
    expect(one.agreementKey).not.toBe(two.agreementKey);
    expect(one.agreementSecret(one.agreementKey)).toHaveLength(32);
    expect(one.agreementSecret(two.agreementKey)).toBeUndefined();
    expect(WireMind.create(counting(), T, { kind: "service" }).genesis).toMatchObject({
      kind: "service",
    });
  });

  it("signs a record with its operational key, at the record's time or another", () => {
    const ada = mind();
    const record = { oip: "1", type: "Hello", author: ada.address, created: T };
    const hello = ada.sign(record, { challenge: "c".repeat(22), domain: "https://host.example" });
    expect(hello.proof).toHaveLength(1);
    expect(hello.proof[0]).toMatchObject({
      verificationMethod: ada.keyRef,
      created: T,
      challenge: "c".repeat(22),
      domain: "https://host.example",
      proofPurpose: "authentication",
    });
    const later = ada.sign(
      { oip: "1", type: "Intent", author: ada.address, created: T, want: "A thing." },
      { created: "2026-11-18T11:08:00Z" },
    );
    expect(later.proof[0]?.created).toBe("2026-11-18T11:08:00Z");
    // A second signature is added to the first.
    expect(ada.sign(later, { created: "2026-11-18T11:09:00Z" }).proof).toHaveLength(2);
  });

  it("has branches that share its keys and none of its later events", () => {
    const fay = mind();
    fay.update("2026-11-18T11:06:41Z");
    const rival = fay.branch(1);
    expect(rival.events).toEqual([fay.genesis]);
    rival.update("2026-11-18T11:06:41Z", { alsoKnownAs: ["https://rival.example/x"] });
    expect(rival.address).toBe(fay.address);
    expect(contentId(rival.events[1])).not.toBe(contentId(fay.events[1]));
    // Each is a log that verifies: the same control key signed both second events.
    expect(verifies(rival.events, NOW)).toBe(true);
    expect(verifies(fay.events, NOW)).toBe(true);
    expect(fay.events).toHaveLength(2);
  });

  it("makes a proof that verifies and counts for nothing", () => {
    const [ada, eve] = [mind(), WireMind.create(counting("eve"), "2026-11-18T11:06:45Z")];
    const stray = eve.strayProof(ada.genesis);
    const judged = verifyProofs({ ...ada.genesis, proof: [stray] });
    expect(judged.verified).toHaveLength(1);
    expect(stray.verificationMethod).not.toBe(ada.genesis.proof[0]?.verificationMethod);
    // The genesis with it does not verify as a log: the key is not one the event reveals.
    expect(verifies([{ ...ada.genesis, proof: [stray] }], NOW)).toBe(false);
  });

  it("gives bundles, whole seconds and words", () => {
    const ada = mind();
    expect(ada.bundle()).toEqual({ oip: "1", type: "Bundle", mind: ada.address, log: ada.events });
    expect(ada.bundle({ log: [], location: { a: 1 }, participant: { b: 2 } })).toEqual({
      oip: "1",
      type: "Bundle",
      mind: ada.address,
      log: [],
      location: { a: 1 },
      participant: { b: 2 },
    });
    expect(second(NOW + 999_999_999n)).toBe(T);
    expect(second(NOW)).toBe(T);
    expect(second(-1n)).toBe("1969-12-31T23:59:59Z");
    expect(word(() => Uint8Array.of(0, 15, 255))).toBe("000fff");
    expect(word(counting())).toHaveLength(16);
  });
});

describe("what an implementation answered, read without trust", () => {
  it("is an object, has a content ID, and is the same JSON as another, or not", () => {
    expect([{}, [], null, "x", 1].map(isObject)).toEqual([true, false, false, false, false]);
    expect(idOf({ a: 1 })).toBe(contentId({ a: 1 }));
    expect(idOf([1])).toBeUndefined();
    expect(idOf({ a: 1.5 })).toBeUndefined();
    expect(same({ a: 1, b: [2] }, { b: [2], a: 1 })).toBe(true);
    expect(same({ a: 1 }, { a: 2 })).toBe(false);
    expect(same({ a: 1.5 }, { a: 1.5 })).toBe(false);
  });

  it("is a record of a type, served as a record", () => {
    const bundle = { oip: "1", type: "Bundle", mind: "did:oip:x" };
    expect(
      recordOf(answer(200, bundle, `${MEDIA_TYPE}; charset=utf-8`), 200, "Bundle", "a bundle"),
    ).toEqual(bundle);
    const wrong: [WireAnswer, string][] = [
      [answer(404, bundle, MEDIA_TYPE), "a bundle: required 200 with a Bundle; got 404"],
      [
        answer(200, { ...bundle, type: "LogPage" }, MEDIA_TYPE),
        "a bundle: required 200 with a Bundle; got 200",
      ],
      [
        answer(200, { ...bundle, oip: "2" }, MEDIA_TYPE),
        "a bundle: required 200 with a Bundle; got 200",
      ],
      [answer(200, [bundle], MEDIA_TYPE), "a bundle: required 200 with a Bundle; got 200"],
      [
        answer(200, "not JSON", MEDIA_TYPE),
        "a bundle: required 200 with a Bundle; got 200 not JSON",
      ],
      [
        answer(200, bundle, "application/json"),
        'a bundle: a record is served as application/oip+json (core 10.1); got "application/json"',
      ],
    ];
    for (const [given, message] of wrong) {
      expect(() => recordOf(given, 200, "Bundle", "a bundle")).toThrow(
        expect.objectContaining({
          name: "Failed",
          message: expect.stringContaining(message) as string,
        }),
      );
    }
    const untyped = { ...answer(200, bundle), headers: new Headers() };
    expect(() => recordOf(untyped, 200, "Bundle", "a bundle")).toThrow(/got ""/u);
  });

  it("is a log of the events expected, each as signed", () => {
    const ada = mind();
    ada.update("2026-11-18T11:06:41Z");
    expect(() => {
      expectLog(JSON.parse(JSON.stringify(ada.events)), ada.events, "a log");
    }).not.toThrow();
    const [genesis, update] = ada.events;
    const wrong: unknown[] = [
      undefined,
      [genesis],
      [update, genesis],
      [genesis, { ...update, proof: [] }],
      [genesis, update, update],
      [genesis, 7],
    ];
    for (const served of wrong) {
      expect(() => {
        expectLog(served, ada.events, "a log");
      }).toThrow(Failed);
    }
    expect(() => {
      expectLog(undefined, ada.events, "a log");
    }).toThrow(/got no log$/u);
    expect(() => {
      expectLog([genesis, 7], ada.events, "a log");
    }).toThrow(new RegExp(`got ${ada.id}, \\?$`, "u"));
    expect(verifies([update], NOW)).toBe(false);
    expect(verifies("no log", NOW)).toBe(false);
  });

  it("is a first-seen time within the clock skew of when the thing was sent", () => {
    const span = [NOW, NOW + 2_000_000_000n] as const;
    const at = (seconds: number) => ({ key: second(NOW + BigInt(seconds) * 1_000_000_000n) });
    expect(seenTime(at(0), "key", span, "a time")).toBe(NOW);
    expect(seenTime(at(-300), "key", span, "a time")).toBe(NOW - 300_000_000_000n);
    expect(seenTime(at(302), "key", span, "a time")).toBe(NOW + 302_000_000_000n);
    for (const map of [at(-301), at(303), { key: "soon" }, { key: 5 }, {}, undefined, [T]]) {
      expect(() => seenTime(map, "key", span, "a time")).toThrow(Failed);
    }
    expect(() => seenTime({}, "key", span, "a time")).toThrow(
      "a time: firstSeen gives a timestamp for key; got undefined",
    );
  });
});

describe("the suite as a verifier", () => {
  it("holds the logs it made, learns the logs it is served, and judges by them", () => {
    const [ada, eve] = [mind(), WireMind.create(counting("eve"), "2026-11-18T11:06:45Z")];
    const verifier = new Verifier();
    verifier.holds(ada, NOW);
    const record = ada.sign({
      oip: "1",
      type: "Intent",
      author: ada.address,
      created: T,
      want: "A thing.",
    });
    expect(verifier.signedBy(record, ada.address, NOW)).toBe(true);
    expect(verifier.seen.proofSeen(proofDigest(record.proof[0]))).toBe(NOW);
    // By another mind, by a mind whose log is not held, and what is no record.
    expect(verifier.signedBy(record, eve.address, NOW)).toBe(false);
    const other = eve.sign({
      oip: "1",
      type: "Intent",
      author: eve.address,
      created: T,
      want: "A thing.",
    });
    expect(verifier.signedBy(other, eve.address, NOW)).toBe(false);
    expect(verifier.signedBy({ type: "Intent" }, ada.address, NOW)).toBe(false);
    expect(verifier.learns(eve.events, NOW)).toBe(true);
    expect(verifier.signedBy(other, eve.address, NOW)).toBe(true);
    // A copy without its proofs adds nothing and takes nothing away (Layer 1, 7.1) ...
    expect(verifier.learns([{ ...eve.genesis, proof: [] }], NOW)).toBe(true);
    // ... and alone it is no log that verifies.
    expect(new Verifier().learns([{ ...eve.genesis, proof: [] }], NOW)).toBe(false);
    expect(new Verifier().learns(eve.events.slice(1), NOW)).toBe(false);
    expect(verifier.learns("no log", NOW)).toBe(false);
    // A log the suite made that does not verify is a mistake in the suite.
    const broken = mind();
    broken.events.push(eve.genesis);
    expect(() => {
      new Verifier().holds(broken, NOW);
    }).toThrow(TypeError);
  });
});

describe("an answer held to core 10.2", () => {
  const problem = (code: string, status: number) =>
    answer(status, { type: `urn:oip:error:${code}`, title: "x", status });

  it("is the problem required, with its status, as problem details", () => {
    expect(() => {
      expectProblem(problem("not-found", 404), "not-found", "an unknown mind");
    }).not.toThrow();
    const wrong: WireAnswer[] = [
      problem("not-found", 400),
      problem("forbidden", 404),
      answer(404, "Not Found", "text/plain"),
      answer(404, { title: "x" }),
      answer(404, { type: "urn:oip:error:not-found" }, "application/json"),
      { ...problem("not-found", 404), headers: new Headers() },
    ];
    for (const given of wrong) {
      expect(() => {
        expectProblem(given, "not-found", "an unknown mind");
      }).toThrow(Failed);
    }
    expect(() => {
      expectProblem(problem("forbidden", 403), "not-found", "an unknown mind");
    }).toThrow(/^an unknown mind: required 404 with type urn:oip:error:not-found; got 403 \{/u);
  });

  it("is a refusal with a problem and the status of its code, whichever", () => {
    for (const given of [
      problem("invalid-record", 400),
      problem("forbidden", 403),
      problem("stale-version", 409),
    ]) {
      expect(() => {
        expectRefused(given, "a packet");
      }).not.toThrow();
    }
    const wrong: WireAnswer[] = [
      answer(202, { stored: true }),
      problem("forbidden", 400),
      problem("made-up", 400),
      answer(400, "Bad Request", "text/plain"),
      answer(500, { type: "urn:oip:error:invalid-record" }),
      answer(399, { type: "urn:oip:error:invalid-record" }),
    ];
    for (const given of wrong) {
      expect(() => {
        expectRefused(given, "a packet");
      }).toThrow(Failed);
    }
  });

  it("has the status required, and is told in a line", () => {
    expect(() => {
      expectStatus(answer(202, {}), 202, "a bundle");
    }).not.toThrow();
    expect(() => {
      expectStatus(answer(200, { added: 1 }), 202, "a bundle");
    }).toThrow(new Failed('a bundle: required 202; got 200 {"added":1}'));
    expect(described(answer(204, ""))).toBe("204");
    expect(described(answer(500, "x".repeat(400)))).toBe(`500 ${"x".repeat(300)}…`);
    expect(described(answer(500, "x".repeat(300)))).toBe(`500 ${"x".repeat(300)}`);
  });
});

describe("the client", () => {
  /** A client whose `fetch` is the one given, with a clock and randomness that stand still. */
  const client = (fetching: typeof fetch, more: { origin?: string; target?: string } = {}) =>
    new WireClient({
      target: more.target ?? "http://127.0.0.1:8080/",
      ...(more.origin === undefined ? {} : { origin: more.origin }),
      clock: () => NOW,
      randomness: counting(),
      fetch: fetching,
      timeoutMs: 400,
    });
  /** Keeps what `fetch` was asked, and answers each time with the next of the answers given. */
  const answering = (...answers: (() => Response)[]) => {
    const asked: { url: string; init: RequestInit }[] = [];
    let next = 0;
    const fetching: typeof fetch = (input, init) => {
      // The client asks with a URL as text.
      asked.push({ url: input as string, init: init ?? {} });
      const make = answers[Math.min(next++, answers.length - 1)];
      return Promise.resolve(make === undefined ? new Response(null) : make());
    };
    return { asked, fetching };
  };

  it("knows where it connects and what the implementation calls itself", () => {
    const { fetching } = answering();
    const plain = client(fetching);
    expect([plain.target, plain.origin]).toEqual([
      "http://127.0.0.1:8080",
      "http://127.0.0.1:8080",
    ]);
    const named = client(fetching, {
      target: "http://127.0.0.1:8080/base//",
      origin: "https://host.example",
    });
    expect([named.target, named.origin]).toEqual([
      "http://127.0.0.1:8080/base",
      "https://host.example",
    ]);
    expect(named.pathOf("https://host.example/oip/v1/minds/x")).toBe("/oip/v1/minds/x");
    expect(named.pathOf("https://host.example")).toBeUndefined();
    expect(named.pathOf("https://host.example.evil/oip")).toBeUndefined();
    // The platform's clock, randomness, fetch and WebSocket where none is given.
    const own = new WireClient({ target: "https://resolver.example" });
    expect(own.timeoutMs).toBe(10_000);
    expect(own.now()).toBeGreaterThan(NOW);
    expect(own.random(4)).toHaveLength(4);
  });

  it("sends a body as it is given: bytes, text, or anything else as JSON", async () => {
    const { asked, fetching } = answering(() => new Response('{"ok":true}', { status: 200 }));
    const asking = client(fetching);
    const told = await asking.ask("POST", "/a", { body: { b: 1 } });
    expect(told.status).toBe(200);
    expect(told.json).toEqual({ ok: true });
    expect(told.text).toBe('{"ok":true}');
    await asking.ask("POST", "/a", {
      body: "text",
      type: "text/plain",
      headers: { "x-more": "1" },
    });
    await asking.ask("POST", "/a", { body: Uint8Array.of(1, 2) });
    const none = await asking.ask("GET", "/a?b=c");
    expect(none.json).toEqual({ ok: true });
    const text = (body: unknown): string => new TextDecoder().decode(body as Uint8Array);
    expect(asked.map(({ url, init }) => [url, init.method, init.headers, init.redirect])).toEqual([
      ["http://127.0.0.1:8080/a", "POST", [["content-type", MEDIA_TYPE]], "manual"],
      [
        "http://127.0.0.1:8080/a",
        "POST",
        [
          ["x-more", "1"],
          ["content-type", "text/plain"],
        ],
        "manual",
      ],
      ["http://127.0.0.1:8080/a", "POST", [["content-type", MEDIA_TYPE]], "manual"],
      ["http://127.0.0.1:8080/a?b=c", "GET", [], "manual"],
    ]);
    expect(text(asked[0]?.init.body)).toBe('{"b":1}');
    expect(text(asked[1]?.init.body)).toBe("text");
    expect([...(asked[2]?.init.body as Uint8Array)]).toEqual([1, 2]);
    expect(asked[3]?.init.body).toBeUndefined();
  });

  it("reads an answer that is no JSON, and one with no body", async () => {
    const { fetching } = answering(
      () => new Response("plain", { status: 500 }),
      () => new Response(null, { status: 204 }),
    );
    const asking = client(fetching);
    expect(await asking.ask("GET", "/a")).toMatchObject({
      status: 500,
      text: "plain",
      json: undefined,
    });
    const empty = await asking.ask("GET", "/a");
    expect([empty.status, empty.text, empty.bytes.length, empty.json]).toEqual([
      204,
      "",
      0,
      undefined,
    ]);
  });

  it("signs a request as Layer 1, 13.3 asks, for the URL the implementation knows", async () => {
    const ada = mind();
    const { asked, fetching } = answering(() => new Response(null, { status: 204 }));
    const asking = client(fetching, { origin: "https://host.example" });
    await asking.ask("PUT", "/oip/v1/minds/x", { body: { a: 1 }, signedBy: ada });
    await asking.ask("GET", "/oip/v1/minds/x/mailbox", {
      signedBy: ada,
      signature: { created: NOW - 5_000_000_000n, expires: NOW + 5_000_000_000n },
    });
    const verifier = new Verifier();
    verifier.holds(ada, NOW);
    const judged = asked.map(({ url, init }) =>
      verifyRequest(
        {
          method: init.method ?? "",
          // The server sees its own origin, whatever address it was reached at.
          url: url.replace("http://127.0.0.1:8080", "https://host.example"),
          headers: init.headers as [string, string][],
          ...(init.body === undefined ? {} : { body: init.body as Uint8Array }),
        },
        { view: verifier.book, now: NOW, nonces: { seen: () => false, remember: () => undefined } },
      ),
    );
    expect(judged.map((result) => result.ok && result.value.mind)).toEqual([
      ada.address,
      ada.address,
    ]);
    const input = (at: number): string =>
      new Headers(asked[at]?.init.headers).get("signature-input") ?? "";
    expect(input(0)).toContain('"content-digest"');
    expect(input(1)).not.toContain('"content-digest"');
    expect(input(1)).toContain(`created=${(NOW - 5_000_000_000n) / 1_000_000_000n}`);
    expect(input(1)).toContain(`expires=${(NOW + 5_000_000_000n) / 1_000_000_000n}`);
    // Each signature has a nonce of its own.
    const nonce = (at: number): string => /nonce="([^"]+)"/u.exec(input(at))?.[1] ?? "";
    expect(nonce(0)).toHaveLength(32);
    expect(nonce(0)).not.toBe(nonce(1));
    // A request that is prepared once is sent as it is, each time.
    const prepared = await asking.prepare("GET", "/m", { signedBy: ada });
    await asking.send(prepared);
    await asking.send(prepared);
    expect(asked[2]?.init.headers).toEqual(asked[3]?.init.headers);
  });

  it("asks again when it is rate-limited, after the wait it is told, and not without end", async () => {
    const limited = (after?: string) => () =>
      new Response(null, {
        status: 429,
        headers: after === undefined ? {} : { "retry-after": after },
      });
    const soon = answering(limited("0"), limited("0.01"), () => new Response("ok"));
    const told = await client(soon.fetching).ask("GET", "/a");
    expect([told.status, told.text, soon.asked.length]).toEqual([200, "ok", 3]);
    const never = answering(limited("0"));
    expect((await client(never.fetching).ask("GET", "/a")).status).toBe(429);
    expect(never.asked).toHaveLength(6);
    // A wait that is not a number is a second.
    const vague = answering(limited("soon"), () => new Response("ok"));
    const before = Date.now();
    expect((await client(vague.fetching).ask("GET", "/a")).status).toBe(200);
    expect(Date.now() - before).toBeGreaterThanOrEqual(900);
    const silent = answering(limited(), () => new Response("ok"));
    expect((await client(silent.fetching).ask("GET", "/a")).status).toBe(200);
  });

  it("reads no more of an answer than it will hold", async () => {
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(4 * 1024 * 1024));
      },
    });
    const { fetching } = answering(() => new Response(endless));
    await expect(client(fetching).ask("GET", "/a")).rejects.toThrow(
      new Failed("the answer is longer than 16777216 bytes"),
    );
  });

  it("reads a stream event by event, whatever the line ends, and stops when it ends or nothing comes", async () => {
    const encoder = new TextEncoder();
    const chunks = [
      ": a comment\n\n",
      'id: 1\ndata: {"a":1}\n\nid: 2\r\ndata: first\r\ndata:second\r\n\r\n',
      'data: no id\nevent: named\nretry\n\nid: 3\ndata: {"cut":',
      "true}\n\n",
    ];
    const body = (hang: boolean) =>
      new ReadableStream<Uint8Array>({
        start(controller) {
          for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
          if (!hang) controller.close();
        },
      });
    const asked = answering(
      () =>
        new Response(body(false), {
          status: 200,
          headers: { "content-type": "text/event-stream" },
        }),
      () => new Response(body(true), { status: 200 }),
      () => new Response(null, { status: 503 }),
    );
    const asking = client(asked.fetching);
    const stream = await asking.stream("/oip/v1/stream?since=4", { "last-event-id": "4" });
    expect(stream.status).toBe(200);
    expect(stream.headers.get("content-type")).toBe("text/event-stream");
    const events = [];
    for (;;) {
      const event = await stream.next();
      if (event === undefined) break;
      events.push(event);
    }
    expect(events).toEqual([
      { id: "1", data: '{"a":1}' },
      { id: "2", data: "first\nsecond" },
      { id: undefined, data: "no id" },
      { id: "3", data: '{"cut":true}' },
    ]);
    expect(await stream.next(10)).toBeUndefined();
    stream.close();
    expect(asked.asked[0]?.url).toBe("http://127.0.0.1:8080/oip/v1/stream?since=4");
    expect(new Headers(asked.asked[0]?.init.headers).get("last-event-id")).toBe("4");
    expect(new Headers(asked.asked[0]?.init.headers).get("accept")).toBe("text/event-stream");

    // A stream that stays open: what has come is given, and then nothing within the time.
    const open = await asking.stream("/oip/v1/stream");
    for (let read = 0; read < 4; read++) expect(await open.next(200)).toBeDefined();
    const before = Date.now();
    expect(await open.next(60)).toBeUndefined();
    expect(Date.now() - before).toBeGreaterThanOrEqual(50);
    open.close();
    expect(await open.next(60)).toBeUndefined();
    // One with no body has ended before it began.
    const refused = await asking.stream("/oip/v1/stream");
    expect(refused.status).toBe(503);
    expect(await refused.next(60)).toBeUndefined();
  });

  it("refuses an event that has no end", async () => {
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new TextEncoder().encode("data: ".padEnd(4 * 1024 * 1024, "x")));
      },
    });
    const { fetching } = answering(() => new Response(endless));
    const stream = await client(fetching).stream("/oip/v1/stream");
    await expect(stream.next(5000)).rejects.toThrow(
      new Failed("the stream sent an event without end"),
    );
    stream.close();
  });

  it("gives up on a stream that does not open in time", async () => {
    const hanging: typeof fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new DOMException("aborted", "AbortError"));
        });
      });
    await expect(client(hanging).stream("/oip/v1/stream")).rejects.toThrow("aborted");
  });

  it("speaks over a WebSocket: messages and the close, in the order they come", async () => {
    /** A socket that opens, says what it is told to, and closes when asked. */
    class Fake {
      static made: Fake[] = [];
      readonly listeners = new Map<string, (event: unknown) => void>();
      readonly sent: string[] = [];
      readonly protocol: string;
      readonly url: string;
      constructor(url: string, asked: string) {
        this.url = url;
        this.protocol = asked;
        Fake.made.push(this);
        queueMicrotask(() => {
          this.tell(url.includes("refused") ? "error" : "open", {});
        });
      }
      tell(type: string, event: unknown): void {
        this.listeners.get(type)?.(event);
      }
      addEventListener(type: string, listener: (event: unknown) => void): void {
        this.listeners.set(type, listener);
      }
      send(text: string): void {
        this.sent.push(text);
      }
      close(): void {
        this.tell("close", { code: 1005, reason: "" });
      }
    }
    const asking = new WireClient({
      target: "https://host.example",
      webSocket: Fake as unknown as typeof WebSocket,
      timeoutMs: 200,
    });
    const socket = await asking.socket("/oip/v1/minds/x/ws", "oip.v1");
    const fake = present(Fake.made[0]);
    expect([fake.url, socket.protocol]).toEqual(["wss://host.example/oip/v1/minds/x/ws", "oip.v1"]);
    fake.tell("message", { data: "one" });
    fake.tell("message", { data: new Uint8Array(2) });
    expect(await socket.next()).toEqual({ message: "one" });
    // A message that is not text is none the suite can read.
    expect(await socket.next()).toEqual({ message: "" });
    expect(await socket.next(30)).toBeUndefined();
    setTimeout(() => {
      fake.tell("message", { data: "late" });
    }, 20);
    expect(await socket.next()).toEqual({ message: "late" });
    socket.send("hello");
    expect(fake.sent).toEqual(["hello"]);
    fake.tell("close", { code: 4401, reason: "who are you" });
    expect(await socket.next()).toEqual({ closed: 4401, reason: "who are you" });
    socket.close();
    expect(await socket.next()).toEqual({ closed: 1005, reason: "" });

    const plain = new WireClient({
      target: "http://127.0.0.1:8080",
      webSocket: Fake as unknown as typeof WebSocket,
      timeoutMs: 100,
    });
    await plain.socket("/ws", "oip.v1");
    expect(Fake.made.at(-1)?.url).toBe("ws://127.0.0.1:8080/ws");
    await expect(plain.socket("/refused", "oip.v1")).rejects.toThrow(
      new Failed("no WebSocket with subprotocol oip.v1 could be opened at /refused"),
    );
    /** One that never opens. */
    class Silent extends Fake {
      override tell(): void {
        // Nothing is ever told.
      }
    }
    const waiting = new WireClient({
      target: "http://127.0.0.1:8080",
      webSocket: Silent as unknown as typeof WebSocket,
      timeoutMs: 50,
    });
    await expect(waiting.socket("/ws", "oip.v1")).rejects.toThrow(Failed);
  });
});
