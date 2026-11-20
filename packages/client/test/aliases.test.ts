// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { clause } from "@oip/testkit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { type AliasOptions, Lookup, Mind } from "../src/index.ts";
import { freshKeystore } from "./helpers.ts";
import { World } from "./world.ts";

const A = "https://resolver-a.example";
const SITE = "https://ada.example";

let world: World;
beforeEach(() => {
  world = new World(100);
  world.resolver(A);
});
afterEach(() => {
  world.close();
});

/** A mind that lists aliases. */
async function named(aliases: readonly string[]) {
  const made = await freshKeystore(world, [A]);
  const mind = await Mind.create(made.options, { kind: "agent", alsoKnownAs: aliases });
  return { ...made, mind };
}

/** Puts a site at an origin: each path with what it answers, and nothing at any other path. */
function site(origin: string, paths: Readonly<Record<string, () => Response>>): void {
  world.put(origin, (request) => {
    const answer = paths[new URL(request.url).pathname];
    return answer === undefined ? new Response("no such page", { status: 404 }) : answer();
  });
}

const text =
  (body: string, type = "text/plain; charset=utf-8"): (() => Response) =>
  () =>
    new Response(body, { status: 200, headers: { "content-type": type } });
const json =
  (body: unknown): (() => Response) =>
  () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/did+json" },
    });

type DnsTxt = NonNullable<AliasOptions["dnsTxt"]>;

/** The DNS of a test: the TXT records of each name. */
const dns =
  (records: Readonly<Record<string, readonly (readonly string[])[]>>): DnsTxt =>
  (name) => {
    const found = records[name];
    return found === undefined
      ? Promise.reject(new Error(`queryTxt ENOTFOUND ${name}`))
      : Promise.resolve(found);
  };

const checker = (more: AliasOptions = {}) =>
  new Lookup({ resolvers: [A], fetch: world.fetch, clock: world.clock, ...more });

/** What one alias of a mind comes to, for a client with the options given. */
async function check(alias: string, mind: Mind, more: AliasOptions = {}): Promise<string> {
  const { checks } = await checker(more).aliases(mind.address);
  const found = checks.find((candidate) => candidate.alias === alias);
  return found === undefined ? "not listed" : (found.reason ?? "verified");
}

describe(`${clause("L1 5.3", "L0 4.1")} an alias a mind lists`, () => {
  it(`${clause("L0 4.2", "L1 5.2")} is the mind's once it points back, and the DID document names those that do`, async () => {
    const aliases = [
      SITE,
      "dns:ada.example",
      "did:web:ada.example",
      "did:web:example.org:people:ada",
      "did:web:localhost%3A8443",
      "did:plc:ewvi7nxzyoun6zhxrhs64oiz",
      "at://ada.example",
      "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "mailto:ada@example.com",
    ];
    const { mind } = await named(aliases);
    const me = mind.address;
    site(SITE, {
      "/.well-known/oip/did": text(`${me}\n`),
      "/.well-known/did.json": json({ id: "did:web:ada.example", alsoKnownAs: [me] }),
    });
    site("https://example.org", {
      "/people/ada/did.json": json({
        id: "did:web:example.org:people:ada",
        alsoKnownAs: ["https://elsewhere.example", me],
      }),
    });
    site("https://localhost:8443", {
      "/.well-known/did.json": json({ id: "did:web:localhost%3A8443", alsoKnownAs: [me] }),
    });
    const lookup = checker({
      dnsTxt: dns({
        // A value in two character-strings, as a long one is stored.
        "_oip.ada.example": [["v=spf1 -all"], ["did=did:oip:", me.slice("did:oip:".length)]],
        "_atproto.ada.example": [["did=did:plc:ewvi7nxzyoun6zhxrhs64oiz"]],
      }),
      resolveDid: (did) =>
        Promise.resolve(
          did === "did:plc:ewvi7nxzyoun6zhxrhs64oiz" ? { id: did, alsoKnownAs: [me] } : undefined,
        ),
    });
    const { checks, did } = await lookup.aliases(me);
    expect(checks).toStrictEqual([
      ...aliases.slice(0, 7).map((alias) => ({ alias, verified: true })),
      // A `did:key` has no document that could list the mind, and nothing asks for a mail address.
      { alias: aliases[7], verified: false, reason: "unsupported" },
      { alias: aliases[8], verified: false, reason: "unsupported" },
    ]);
    expect(did.didDocument.alsoKnownAs).toStrictEqual(aliases.slice(0, 7));
    // Resolving a mind verifies no alias, and presents none as verified.
    expect((await lookup.resolve(me)).did.didDocument.alsoKnownAs).toBeUndefined();
  });

  it("is not the mind's where an origin does not serve the address, alone, as plain text", async () => {
    const { mind } = await named([SITE]);
    const me = mind.address;
    const other = (await named([])).mind.address;
    const served: [what: string, answer: () => Response, outcome: string][] = [
      ["the address", text(me), "verified"],
      ["with a line ending", text(`${me}\r\n`), "verified"],
      ["as text/plain with no parameters", text(me, "text/plain"), "verified"],
      ["with two line endings", text(`${me}\n\n`), "not-pointing-back"],
      ["with a space before it", text(` ${me}`), "not-pointing-back"],
      ["with another address after it", text(`${me}\n${other}`), "not-pointing-back"],
      ["another address", text(other), "not-pointing-back"],
      ["as a web page", text(me, "text/html"), "not-pointing-back"],
      [
        "with bytes that are no text",
        () =>
          new Response(new Uint8Array([0xff, 0xfe]), {
            status: 200,
            headers: { "content-type": "text/plain" },
          }),
        "not-pointing-back",
      ],
      [
        "with a status that is not 200",
        () => new Response(me, { status: 203, headers: { "content-type": "text/plain" } }),
        "not-pointing-back",
      ],
      ["more than a client reads", text(me.padEnd(2000, " ")), "unreachable"],
      [
        "by a redirect",
        () => new Response(null, { status: 302, headers: { location: "/" } }),
        "unreachable",
      ],
    ];
    for (const [what, answer, outcome] of served) {
      site(SITE, { "/.well-known/oip/did": answer });
      expect(await check(SITE, mind), what).toBe(outcome);
    }
    site(SITE, {});
    expect(await check(SITE, mind)).toBe("not-pointing-back");
    world.remove(SITE);
    expect(await check(SITE, mind)).toBe("unreachable");
  });

  it("is an origin, and not a page of one", async () => {
    const page = `${SITE}/people/ada`;
    const { mind } = await named([page, `${SITE}/`, "https://user@ada.example"]);
    site(SITE, { "/.well-known/oip/did": text(mind.address) });
    const { checks } = await checker().aliases(mind.address);
    expect(checks.map((checked) => checked.reason)).toStrictEqual([
      "unsupported",
      "unsupported",
      "unsupported",
    ]);
  });

  it("is not the mind's where the DNS does not say so, and is not asked for where the client cannot ask", async () => {
    const alias = "dns:ada.example";
    const { mind } = await named([alias, "dns:not a name", "dns:"]);
    const me = mind.address;
    expect(await check(alias, mind)).toBe("unsupported");
    const answers: [records: readonly (readonly string[])[], outcome: string][] = [
      [[[`did=${me}`]], "verified"],
      [[["something else"], [`did=${me}`]], "verified"],
      [[[`did=${me} `]], "not-pointing-back"],
      [[[`DID=${me}`]], "not-pointing-back"],
      [[[me]], "not-pointing-back"],
      [[], "not-pointing-back"],
    ];
    for (const [records, outcome] of answers) {
      const dnsTxt = dns({ "_oip.ada.example": records });
      expect(await check(alias, mind, { dnsTxt }), JSON.stringify(records)).toBe(outcome);
    }
    // A name the DNS has no record for: the lookup fails, as lookups do.
    expect(await check(alias, mind, { dnsTxt: dns({}) })).toBe("unreachable");
    // What is no name is not looked up.
    let asked = 0;
    const counting: DnsTxt = () => {
      asked++;
      return Promise.resolve([]);
    };
    expect(await check("dns:not a name", mind, { dnsTxt: counting })).toBe("unsupported");
    expect(await check("dns:", mind, { dnsTxt: counting })).toBe("unsupported");
    // Each of the two checks asked for the one alias that is a name, and for no other.
    expect(asked).toBe(2);
  });

  it("is not the mind's where another DID's document does not list it", async () => {
    const web = "did:web:ada.example";
    const plc = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    const { mind } = await named([web, plc, "did:web:", "did:web:%zz", "did:web:ada.example:%zz"]);
    const me = mind.address;
    const documents: [what: string, answer: () => Response, outcome: string][] = [
      ["listing the mind", json({ id: web, alsoKnownAs: [me] }), "verified"],
      [
        "of another DID",
        json({ id: "did:web:eve.example", alsoKnownAs: [me] }),
        "not-pointing-back",
      ],
      ["listing nothing", json({ id: web }), "not-pointing-back"],
      ["listing others", json({ id: web, alsoKnownAs: ["did:oip:another"] }), "not-pointing-back"],
      ["with a name that is no list", json({ id: web, alsoKnownAs: me }), "not-pointing-back"],
      ["that is no object", json([me]), "not-pointing-back"],
      ["that is no JSON", text("{", "application/json"), "not-pointing-back"],
      ["that is not found", () => new Response("none", { status: 404 }), "not-pointing-back"],
    ];
    for (const [what, answer, outcome] of documents) {
      site(SITE, { "/.well-known/did.json": answer });
      expect(await check(web, mind), what).toBe(outcome);
    }
    // A DID that names no host, or one that cannot be read, has no document.
    expect(await check("did:web:", mind)).toBe("not-pointing-back");
    expect(await check("did:web:%zz", mind)).toBe("not-pointing-back");
    expect(await check("did:web:ada.example:%zz", mind)).toBe("not-pointing-back");
    // A method the client does not resolve itself: asked of what the application gives it.
    expect(await check(plc, mind)).toBe("unsupported");
    const resolving = (answer: () => Promise<{ alsoKnownAs?: unknown } | undefined>) =>
      check(plc, mind, { resolveDid: answer });
    expect(await resolving(() => Promise.resolve({ alsoKnownAs: [me] }))).toBe("verified");
    expect(await resolving(() => Promise.resolve({ alsoKnownAs: [] }))).toBe("not-pointing-back");
    expect(await resolving(() => Promise.resolve(undefined))).toBe("not-pointing-back");
    expect(await resolving(() => Promise.reject(new Error("the directory is away")))).toBe(
      "unreachable",
    );
  });

  it("may be another mind, which lists this one in turn", async () => {
    const other = await named([]);
    const stranger = (await named([])).mind.address;
    const unknown = "did:oip:bciqa2x5w6ybvrdcp6cnyjbaoixvnsvw3qkhv4mcorxc3pmxbfm3kvy";
    const { mind } = await named([other.mind.address, stranger, unknown]);
    expect(await check(other.mind.address, mind)).toBe("not-pointing-back");
    await other.mind.update({ alsoKnownAs: [mind.address] }, { control: other.lock });
    const { checks } = await checker().aliases(mind.address);
    expect(checks).toStrictEqual([
      { alias: other.mind.address, verified: true },
      { alias: stranger, verified: false, reason: "not-pointing-back" },
      // No resolver holds it: it could not be asked.
      { alias: unknown, verified: false, reason: "unreachable" },
    ]);
  });

  it("may be an AT Protocol handle, whose DID lists the mind", async () => {
    const alias = "at://ada.example";
    const { mind } = await named([alias, "at://not a handle"]);
    const me = mind.address;
    // With no DNS to ask, the handle's own site says which DID it is.
    site(SITE, {
      "/.well-known/atproto-did": text("did:web:ada.example\n"),
      "/.well-known/did.json": json({ id: "did:web:ada.example", alsoKnownAs: [alias, me] }),
    });
    expect(await check(alias, mind)).toBe("verified");
    // The DNS is asked first, where the client can ask it, and the site if the DNS has no record.
    const plc = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    const dnsTxt = dns({ "_atproto.ada.example": [["other"], [`did=${plc}`]] });
    expect(await check(alias, mind, { dnsTxt })).toBe("unsupported");
    const resolveDid = () => Promise.resolve({ alsoKnownAs: [alias] });
    expect(await check(alias, mind, { dnsTxt, resolveDid })).toBe("not-pointing-back");
    expect(await check(alias, mind, { dnsTxt: dns({}), resolveDid })).toBe("verified");
    expect(await check(alias, mind, { dnsTxt: dns({ "_atproto.ada.example": [] }) })).toBe(
      "verified",
    );
    // A handle that stands for no DID.
    site(SITE, { "/.well-known/atproto-did": text("ada") });
    expect(await check(alias, mind)).toBe("not-pointing-back");
    site(SITE, {});
    expect(await check(alias, mind)).toBe("not-pointing-back");
    expect(await check("at://not a handle", mind)).toBe("unsupported");
  });

  it("a failure that is nobody's answer reaches the caller as it is", async () => {
    const { mind } = await named([SITE]);
    // What stands in for `fetch` is broken for the site: its answer has headers that cannot be read.
    const broken: typeof world.fetch = (request) =>
      request.url.startsWith(SITE)
        ? Promise.resolve({
            status: 200,
            body: null,
            headers: {
              get: () => {
                throw new RangeError("not a response");
              },
            },
          } as unknown as Response)
        : world.fetch(request);
    const lookup = new Lookup({ resolvers: [A], fetch: broken, clock: world.clock });
    await expect(lookup.aliases(mind.address)).rejects.toThrow(RangeError);
  });

  it("is checked for a mind with none: there is nothing to verify", async () => {
    const { mind } = await named([]);
    const { checks, did } = await checker().aliases(mind.address);
    expect(checks).toStrictEqual([]);
    expect(did.didDocument.alsoKnownAs).toBeUndefined();
  });
});

describe(`${clause("L1 5.2")} the DID document of a resolved mind`, () => {
  it("has a service for each home, and for each endpoint of its current location record", async () => {
    world.host("https://host.example");
    const made = await freshKeystore(world, [A]);
    const mind = await Mind.create(made.options, {
      kind: "agent",
      homes: ["https://host.example"],
    });
    const services = async () =>
      (await checker().resolve(mind.address)).did.didDocument.service?.map((service) => [
        service.id.slice(mind.address.length),
        service.type,
        service.serviceEndpoint,
      ]);
    expect(await services()).toStrictEqual([["#home-0", "OIPHome", "https://host.example"]]);
    const location = await mind.publishLocation();
    expect(await services()).toStrictEqual([
      ["#home-0", "OIPHome", "https://host.example"],
      ["#endpoint-0", "OIPEndpoint", location.endpoints[0]?.url],
      ["#endpoint-1", "OIPEndpoint", location.endpoints[1]?.url],
    ]);
    const { did } = await checker().aliases(mind.address);
    expect(did.didDocument.service).toHaveLength(3);
  });
});
