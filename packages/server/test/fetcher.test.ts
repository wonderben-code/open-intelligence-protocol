// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The guarded fetcher, against an HTTPS server on this machine.
 *
 * The server is at 127.0.0.1, which the fetcher refuses, as it must. The
 * tests that need a response allow that one address, by the option an
 * operator has for its own test network, and give the fetcher a resolver
 * that knows the names used here.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { IncomingHttpHeaders } from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TLSSocket } from "node:tls";

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { pinnedTo, raced, sameAddress } from "../src/fetcher.ts";
import { type FetchRefusal, FetchRefused, GuardedFetcher, type Resolve } from "../src/index.ts";

let server: Server;
let port: number;
let ca: string;
/** The requests the server has had since the test began: their paths and headers. */
let requests: { path: string; headers: IncomingHttpHeaders }[];

beforeAll(async () => {
  // A certificate for the names used here, made for this run and thrown away after it.
  const directory = mkdtempSync(join(tmpdir(), "oip-fetcher-"));
  try {
    execFileSync(
      "openssl",
      [
        ...["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"],
        ...["-keyout", join(directory, "key.pem"), "-out", join(directory, "cert.pem")],
        ...["-days", "2", "-subj", "/CN=home.example"],
        ...["-addext", "subjectAltName=DNS:home.example,DNS:other.example,IP:127.0.0.1"],
      ],
      { stdio: "ignore" },
    );
    ca = readFileSync(join(directory, "cert.pem"), "utf8");
    server = createServer(
      { key: readFileSync(join(directory, "key.pem")), cert: ca },
      (request, response) => {
        const path = request.url ?? "";
        requests.push({ path, headers: request.headers });
        const redirect = (location: string | undefined): void => {
          response.writeHead(302, location === undefined ? {} : { location }).end();
        };
        if (path === "/inbox") {
          // What was posted is said back, with how it was said to be.
          const chunks: Buffer[] = [];
          request.on("data", (chunk: Buffer) => chunks.push(chunk));
          request.on("end", () => {
            const said = `${request.method ?? ""} ${String(request.headers["content-type"])} ${Buffer.concat(chunks).toString("utf8")}`;
            response.writeHead(202, { "content-type": "application/json" }).end(said);
          });
        } else if (path === "/ok") {
          response.writeHead(200, { "content-type": "application/oip+json" }).end('{"ok":true}');
        } else if (path === "/missing") {
          response.writeHead(404, { "content-type": "application/problem+json" }).end("{}");
        } else if (path === "/declared") {
          response.writeHead(200, { "content-length": "5000" }).end(Buffer.alloc(5000, 0x61));
        } else if (path === "/chunked") {
          response.writeHead(200);
          for (let piece = 0; piece < 50; piece++) response.write(Buffer.alloc(100, 0x61));
          response.end();
        } else if (path === "/declared-and-stalled") {
          // The length is said, and the body never comes.
          response.writeHead(200, { "content-length": "5000" }).flushHeaders();
        } else if (path === "/stall") {
          // No answer comes.
        } else if (path === "/twice") {
          response
            .writeHead(200, [
              ["x-note", "first"],
              ["x-note", "second"],
              ["set-cookie", "a=1"],
              ["set-cookie", "b=2"],
            ])
            .end();
        } else if (path === "/cut") {
          // The length is said, a part of the body comes, and the connection is cut.
          response.writeHead(200, { "content-length": "1000" });
          response.write(Buffer.alloc(10, 0x61), () => {
            response.destroy();
          });
        } else if (path === "/redirect/same") redirect("/ok");
        else if (path === "/redirect/absolute") redirect(`https://home.example:${port}/ok`);
        else if (path === "/redirect/loop") redirect("/redirect/loop");
        else if (path === "/redirect/twice") redirect("/redirect/same");
        else if (path === "/redirect/other") redirect(`https://other.example:${port}/ok`);
        else if (path === "/redirect/http") redirect(`http://home.example:${port}/ok`);
        else if (path === "/redirect/port") redirect("https://home.example:1/ok");
        else if (path === "/redirect/inward") redirect("https://127.0.0.1/ok");
        else if (path === "/redirect/nowhere") redirect("https://[");
        else if (path === "/redirect/none") redirect(undefined);
        else response.writeHead(500).end();
      },
    );
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
});

beforeEach(() => {
  requests = [];
});

/** A resolver that knows the names given, and says how often it was asked. */
function resolverOf(
  names: Readonly<Record<string, readonly string[]>>,
): Resolve & { asked: string[] } {
  const asked: string[] = [];
  const resolve: Resolve = (hostname) => {
    asked.push(hostname);
    const found = names[hostname];
    return found === undefined ? Promise.reject(new Error("ENOTFOUND")) : Promise.resolve(found);
  };
  return Object.assign(resolve, { asked });
}

const HERE = { "home.example": ["127.0.0.1"], "other.example": ["127.0.0.1"] } as const;

/** A fetcher that may reach the server of these tests, and nothing else on this machine. */
function fetcherFor(
  resolve: Resolve = resolverOf(HERE),
  limits: { maxBytes?: number; timeoutMs?: number; maxRedirects?: number } = {},
): GuardedFetcher {
  return new GuardedFetcher({ resolve, allow: ["127.0.0.1/32"], ca, limits });
}

const at = (path: string, host = "home.example"): string => `https://${host}:${port}${path}`;

async function refusal(work: Promise<unknown>): Promise<FetchRefusal | "fetched"> {
  try {
    await work;
  } catch (error) {
    if (error instanceof FetchRefused) return error.reason;
    throw error;
  }
  return "fetched";
}

describe("a fetch for a stranger", () => {
  it("gets what an HTTPS URL on an allowed address serves", async () => {
    const resolve = resolverOf(HERE);
    const fetched = await fetcherFor(resolve).get(at("/ok"), "application/oip+json");
    expect(fetched.status).toBe(200);
    expect(fetched.url).toBe(at("/ok"));
    expect(fetched.headers["content-type"]).toBe("application/oip+json");
    expect(new TextDecoder().decode(fetched.body)).toBe('{"ok":true}');
    expect(resolve.asked).toStrictEqual(["home.example"]);
  });

  it("sends nothing of the service with the request", async () => {
    await fetcherFor().get(at("/ok"), "application/oip+json");
    expect(requests).toHaveLength(1);
    // Compared as a plain object: the headers Node.js gives have a prototype of their own
    // in some versions and none in others, and it is the headers that are asked about.
    expect({ ...requests[0]?.headers }).toStrictEqual({
      accept: "application/oip+json",
      "accept-encoding": "identity",
      "user-agent": "oip-server",
      host: `home.example:${port}`,
      connection: "close",
    });
  });

  it("gives an answer that is no success as the answer it is", async () => {
    const fetched = await fetcherFor().get(at("/missing"));
    expect(fetched.status).toBe(404);
    const twice = await fetcherFor().get(at("/twice"));
    expect(twice.headers["x-note"]).toBe("first, second");
    // A cookie is nothing a service takes from a stranger's host.
    expect(twice.headers).not.toHaveProperty("set-cookie");
    // A redirect that says where to nothing is an answer too.
    expect((await fetcherFor().get(at("/redirect/none"))).status).toBe(302);
  });

  it("is refused for what is not HTTPS, or carries credentials, before any name is resolved", async () => {
    const resolve = resolverOf(HERE);
    const fetcher = fetcherFor(resolve);
    for (const url of [
      `http://home.example:${port}/ok`,
      "ftp://home.example/ok",
      "file:///etc/passwd",
      "data:text/plain,x",
      "home.example/ok",
      "",
    ]) {
      expect(await refusal(fetcher.get(url)), url).toBe("not-https");
    }
    for (const url of [
      at("/ok").replace("https://", "https://user:secret@"),
      at("/ok").replace("https://", "https://user@"),
    ]) {
      expect(await refusal(fetcher.get(url)), url).toBe("credentials");
    }
    expect(resolve.asked).toStrictEqual([]);
    expect(requests).toStrictEqual([]);
  });
});

describe("a body posted for a stranger", () => {
  it("is sent as it is to an HTTPS URL on an allowed address, and the answer given", async () => {
    const body = new TextEncoder().encode('{"oip":"1"}');
    const posted = await fetcherFor().post(at("/inbox"), body, "application/oip+json");
    expect(posted.status).toBe(202);
    expect(new TextDecoder().decode(posted.body)).toBe('POST application/oip+json {"oip":"1"}');
    expect(requests.at(-1)?.headers).toMatchObject({
      accept: "*/*",
      "content-type": "application/oip+json",
      "content-length": "11",
      "user-agent": "oip-server",
    });
    // Nothing at all is a body too.
    const empty = await fetcherFor().post(at("/inbox"), new Uint8Array(0), "text/plain", "text/*");
    expect(new TextDecoder().decode(empty.body)).toBe("POST text/plain ");
    expect(requests.at(-1)?.headers).toMatchObject({ accept: "text/*", "content-length": "0" });
  });

  it("is sent with the further headers a protocol has, and with none that are the fetcher's own or frame the request", async () => {
    const body = new TextEncoder().encode("{}");
    await fetcherFor().post(at("/inbox"), body, "application/json", "application/json", {
      "A2A-Version": "1.0",
      "a2a-extensions": "https://example.com/ext/v1,https://example.com/ext/v2",
    });
    expect(requests.at(-1)?.headers).toMatchObject({
      accept: "application/json",
      "content-type": "application/json",
      "a2a-version": "1.0",
      "a2a-extensions": "https://example.com/ext/v1,https://example.com/ext/v2",
      "user-agent": "oip-server",
    });
    const sent = requests.length;
    for (const headers of [
      { Host: "elsewhere.example" },
      { "content-length": "0" },
      { "Transfer-Encoding": "chunked" },
      { "user-agent": "another" },
      { "x bad": "1" },
      { "": "1" },
      { "x-split": "one\r\nx-injected: two" },
      { "x-wide": "caf\u00e9" },
    ]) {
      await expect(
        fetcherFor().post(at("/inbox"), body, "application/json", "*/*", headers),
        JSON.stringify(headers),
      ).rejects.toThrow(TypeError);
    }
    // Nothing was sent for any of them.
    expect(requests).toHaveLength(sent);
  });

  it("is not sent on where the answer redirects: the redirect is the answer", async () => {
    const body = new TextEncoder().encode("{}");
    const answer = await fetcherFor().post(at("/redirect/same"), body, "application/json");
    expect(answer.status).toBe(302);
    expect(answer.headers["location"]).toBe("/ok");
    expect(requests.map((request) => request.path)).toStrictEqual(["/redirect/same"]);
  });

  it("is refused under the same guard as a fetch, before anything is sent", async () => {
    const body = new TextEncoder().encode("{}");
    const refusal = async (fetcher: GuardedFetcher, url: string): Promise<string> => {
      try {
        await fetcher.post(url, body, "application/json");
      } catch (error) {
        if (error instanceof FetchRefused) return error.reason;
        throw error;
      }
      return "sent";
    };
    expect(await refusal(fetcherFor(), `http://home.example:${port}/inbox`)).toBe("not-https");
    expect(await refusal(fetcherFor(), `https://u:p@home.example:${port}/inbox`)).toBe(
      "credentials",
    );
    // This machine, by its address and by a name that resolves to it, where it is not allowed.
    const strict = new GuardedFetcher({ resolve: resolverOf(HERE), ca });
    expect(await refusal(strict, `https://127.0.0.1:${port}/inbox`)).toBe("address");
    expect(await refusal(strict, at("/inbox"))).toBe("address");
    expect(requests).toStrictEqual([]);
  });
});

describe("the address a fetch goes to", () => {
  it("is not this machine or the network behind it, however the URL writes the address", async () => {
    // Nothing is allowed here but the public internet.
    const resolve = resolverOf({});
    const fetcher = new GuardedFetcher({ resolve, ca });
    for (const host of [
      "127.0.0.1",
      "127.1",
      "0x7f.0.0.1",
      "2130706433",
      "017700000001",
      "0.0.0.0",
      "10.0.0.1",
      "169.254.169.254",
      "192.168.0.1",
      "[::1]",
      "[::]",
      "[::ffff:127.0.0.1]",
      "[::ffff:7f00:1]",
      "[64:ff9b::7f00:1]",
      "[fe80::1]",
      "[fd00::1]",
    ]) {
      expect(await refusal(fetcher.get(`https://${host}:${port}/ok`)), host).toBe("address");
    }
    expect(resolve.asked).toStrictEqual([]);
    expect(requests).toStrictEqual([]);
  });

  it("is not one of them by a name that resolves there", async () => {
    const resolve = resolverOf({
      "loopback.example": ["127.0.0.1"],
      "metadata.example": ["169.254.169.254"],
      "inside.example": ["10.1.2.3"],
      "six.example": ["::1"],
      "mapped.example": ["::ffff:127.0.0.1"],
      // One address that is public does not carry the others.
      "mixed.example": ["93.184.216.34", "127.0.0.1"],
      "garbage.example": ["not an address"],
    });
    const fetcher = new GuardedFetcher({ resolve, ca });
    for (const host of Object.keys({
      "loopback.example": 0,
      "metadata.example": 0,
      "inside.example": 0,
      "six.example": 0,
      "mapped.example": 0,
      "mixed.example": 0,
      "garbage.example": 0,
    })) {
      expect(await refusal(fetcher.get(`https://${host}:${port}/ok`)), host).toBe("address");
    }
    expect(requests).toStrictEqual([]);
  });

  it("is allowed only as far as the operator's ranges say", async () => {
    // The range allows 127.0.0.1 and not the rest of the loopback network.
    const resolve = resolverOf({ "near.example": ["127.0.0.2"] });
    expect(await refusal(fetcherFor(resolve).get(at("/ok", "near.example")))).toBe("address");
    expect((await fetcherFor().get(at("/ok", "127.0.0.1"))).status).toBe(200);
    expect(() => new GuardedFetcher({ allow: ["127.0.0.1"] })).toThrow(TypeError);
    expect(() => new GuardedFetcher({ allow: ["localhost/8"] })).toThrow(TypeError);
  });

  it("is one that was checked: the name is resolved once, and not again for the connection", async () => {
    // A name that answers with this machine once, and with somewhere else ever after.
    let asked = 0;
    const turning: Resolve = () => Promise.resolve([asked++ === 0 ? "127.0.0.1" : "93.184.216.34"]);
    const fetched = await fetcherFor(turning).get(at("/ok"));
    expect(fetched.status).toBe(200);
    expect(asked).toBe(1);
    expect(requests).toHaveLength(1);
  });

  it("is checked again for a redirect, which a name that turns does not get past", async () => {
    let asked = 0;
    const turning: Resolve = () => Promise.resolve([asked++ === 0 ? "127.0.0.1" : "10.0.0.1"]);
    expect(await refusal(fetcherFor(turning).get(at("/redirect/same")))).toBe("address");
    expect(asked).toBe(2);
    expect(requests.map((request) => request.path)).toStrictEqual(["/redirect/same"]);
  });

  it("is refused where the name does not resolve, or the certificate is for another name", async () => {
    expect(await refusal(fetcherFor().get(at("/ok", "unknown.example")))).toBe("network");
    expect(
      await refusal(
        fetcherFor(resolverOf({ "empty.example": [] })).get(at("/ok", "empty.example")),
      ),
    ).toBe("network");
    // The server's certificate names `home.example` and `other.example`.
    const resolve = resolverOf({ "wrong.example": ["127.0.0.1"] });
    expect(await refusal(fetcherFor(resolve).get(at("/ok", "wrong.example")))).toBe("network");
    // And one that no authority the fetcher trusts has signed.
    const untrusting = new GuardedFetcher({ resolve: resolverOf(HERE), allow: ["127.0.0.1/32"] });
    expect(await refusal(untrusting.get(at("/ok")))).toBe("network");
  });
});

describe("the connection a fetch is made on", () => {
  it("is at the address that was checked, by whichever of its names the socket gives", () => {
    // A socket that speaks both families names an IPv4 address as IPv6 does.
    expect(sameAddress("127.0.0.1", "::ffff:127.0.0.1")).toBe(true);
    expect(sameAddress("::ffff:127.0.0.1", "127.0.0.1")).toBe(true);
    expect(sameAddress("2001:db8::1", "2001:DB8:0:0:0:0:0:1")).toBe(true);
    expect(sameAddress("127.0.0.1", "127.0.0.2")).toBe(false);
    expect(sameAddress("127.0.0.1", "::1")).toBe(false);
    expect(sameAddress("127.0.0.1", undefined)).toBe(false);
    expect(sameAddress("127.0.0.1", "not an address")).toBe(false);
    expect(sameAddress("not an address", "127.0.0.1")).toBe(false);
  });

  it("is given up where the socket is not at an address that was checked", async () => {
    // Node.js cannot be made to connect elsewhere while the lookup is pinned, so the socket
    // is made to say that it has.
    Object.defineProperty(TLSSocket.prototype, "remoteAddress", {
      configurable: true,
      get: () => "203.0.113.9",
    });
    try {
      expect(await refusal(fetcherFor().get(at("/ok")))).toBe("address");
    } finally {
      Reflect.deleteProperty(TLSSocket.prototype, "remoteAddress");
    }
    expect((await fetcherFor().get(at("/ok"))).status).toBe(200);
  });

  it("is asked for by a lookup that knows only the addresses checked, one or all", () => {
    const lookup = pinnedTo(["127.0.0.1", "2001:db8::1"]);
    const answers: unknown[] = [];
    lookup("anything.example", {}, (...answer) => answers.push(answer));
    lookup("anything.example", { all: false }, (...answer) => answers.push(answer));
    lookup("anything.example", { all: true }, (...answer) => answers.push(answer));
    expect(answers).toStrictEqual([
      [null, "127.0.0.1", 4],
      [null, "127.0.0.1", 4],
      [
        null,
        [
          { address: "127.0.0.1", family: 4 },
          { address: "2001:db8::1", family: 6 },
        ],
      ],
    ]);
  });

  it("is resolved by the system where no resolver is given, and checked the same", async () => {
    // This machine's own name for itself resolves to this machine.
    const fetcher = new GuardedFetcher({ ca });
    expect(await refusal(fetcher.get(`https://localhost:${port}/ok`))).toBe("address");
    expect(requests).toStrictEqual([]);
  });

  it("fails as the network's failure where the response is cut off", async () => {
    expect(await refusal(fetcherFor().get(at("/cut")))).toBe("network");
  });

  it("gives up waiting at once where the time had run out before it began to wait", async () => {
    const reason = await raced(new Promise(() => undefined), AbortSignal.abort()).catch(
      (error: unknown) => (error instanceof FetchRefused ? error.reason : "other"),
    );
    expect(reason).toBe("timeout");
    // And passes on what the work gives, or what it fails with, while there is time.
    const open = new AbortController().signal;
    expect(await raced(Promise.resolve(7), open)).toBe(7);
    await expect(raced(Promise.reject(new Error("no")), open)).rejects.toThrow("no");
  });
});

describe("the limits of a fetch", () => {
  it("reads a response up to its limit of bytes, and one byte more is too many", async () => {
    expect(
      (await fetcherFor(undefined, { maxBytes: 5000 }).get(at("/declared"))).body,
    ).toHaveLength(5000);
    expect((await fetcherFor(undefined, { maxBytes: 5000 }).get(at("/chunked"))).body).toHaveLength(
      5000,
    );
    expect(await refusal(fetcherFor(undefined, { maxBytes: 4999 }).get(at("/declared")))).toBe(
      "too-large",
    );
    expect(await refusal(fetcherFor(undefined, { maxBytes: 4999 }).get(at("/chunked")))).toBe(
      "too-large",
    );
    expect(await refusal(fetcherFor(undefined, { maxBytes: 0 }).get(at("/ok")))).toBe("too-large");
    // A response that says it is too long is refused on its word, before its body is waited for.
    expect(
      await refusal(
        fetcherFor(undefined, { maxBytes: 4999, timeoutMs: 5000 }).get(at("/declared-and-stalled")),
      ),
    ).toBe("too-large");
  });

  it("gives up when the time runs out, with no answer or with a resolver that does not answer", async () => {
    const started = Date.now();
    expect(await refusal(fetcherFor(undefined, { timeoutMs: 300 }).get(at("/stall")))).toBe(
      "timeout",
    );
    const never: Resolve = () => new Promise(() => undefined);
    expect(await refusal(fetcherFor(never, { timeoutMs: 300 }).get(at("/ok")))).toBe("timeout");
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it("follows a redirect to the same origin, so many times and no more", async () => {
    for (const path of ["/redirect/same", "/redirect/absolute", "/redirect/twice"]) {
      const fetched = await fetcherFor().get(at(path));
      expect(fetched.status, path).toBe(200);
      expect(fetched.url).toBe(at("/ok"));
    }
    expect(await refusal(fetcherFor().get(at("/redirect/loop")))).toBe("redirect");
    // Three are followed: the first request and three more.
    expect(requests.filter((request) => request.path === "/redirect/loop")).toHaveLength(4);
    expect(
      await refusal(fetcherFor(undefined, { maxRedirects: 1 }).get(at("/redirect/twice"))),
    ).toBe("redirect");
    expect(
      await refusal(fetcherFor(undefined, { maxRedirects: 0 }).get(at("/redirect/same"))),
    ).toBe("redirect");
  });

  it("follows no redirect to another host, scheme or port, or to what is no URL", async () => {
    for (const path of [
      "/redirect/other",
      "/redirect/http",
      "/redirect/port",
      "/redirect/inward",
      "/redirect/nowhere",
    ]) {
      requests = [];
      expect(await refusal(fetcherFor().get(at(path))), path).toBe("redirect");
      // The one request, and none to where the redirect pointed.
      expect(requests.map((request) => request.path)).toStrictEqual([path]);
    }
  });

  it("takes limits that are whole numbers, not negative", () => {
    for (const wrong of [-1, 1.5, Number.NaN]) {
      for (const name of ["maxBytes", "timeoutMs", "maxRedirects"]) {
        expect(() => new GuardedFetcher({ limits: { [name]: wrong } })).toThrow(TypeError);
      }
    }
  });
});
