// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { type Keychain, keychainLock } from "@oip/keystore";
import { repoRoot } from "@oip/testkit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { example as chartering } from "../examples/charter.ts";
import { example as founding } from "../examples/collective.ts";
import { example as dealing } from "../examples/deal.ts";
import { example as delegating } from "../examples/delegation.ts";
import { example as finding } from "../examples/find.ts";
import { example as living } from "../examples/keys.ts";
import { example as hearing } from "../examples/listen.ts";
import { example } from "../examples/first-mind.ts";
import { example as messaging } from "../examples/messages.ts";
import { example as moving } from "../examples/move.ts";
import { example as naming } from "../examples/names.ts";
import { example as keeping } from "../examples/outbox.ts";
import { example as publishing } from "../examples/publish.ts";
import { example as talking } from "../examples/session.ts";
import * as client from "../src/index.ts";
import { World } from "./world.ts";

const packageRoot = join(repoRoot, "packages", "client");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

let world: World;
beforeEach(() => {
  world = new World(100);
});
afterEach(() => {
  world.close();
});

function memoryKeychain(): Keychain {
  const kept = new Map<string, string>();
  return {
    get: (service, account) => Promise.resolve(kept.get(`${service}\n${account}`)),
    set: (service, account, secret) => {
      kept.set(`${service}\n${account}`, secret);
      return Promise.resolve();
    },
    delete: (service, account) => {
      kept.delete(`${service}\n${account}`);
      return Promise.resolve();
    },
  };
}

describe("the README", () => {
  it("shows its examples unchanged", () => {
    for (const name of [
      "first-mind.ts",
      "keys.ts",
      "names.ts",
      "delegation.ts",
      "charter.ts",
      "publish.ts",
      "find.ts",
      "messages.ts",
      "listen.ts",
      "outbox.ts",
      "session.ts",
      "move.ts",
      "deal.ts",
      "collective.ts",
    ]) {
      const source = readFileSync(join(packageRoot, "examples", name), "utf8");
      // The file's licence header is not part of what the README shows.
      const code = source.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
      expect(readme, name).toContain(`\`\`\`ts\n${code}\`\`\``);
    }
  });

  it("shows the output the example of delegation really gives, with time that passes", async () => {
    world.resolver("https://resolver.example");
    world.host("https://home.example");
    const output = await delegating(
      ["https://resolver.example"],
      "https://home.example",
      keychainLock(memoryKeychain(), "example"),
      // Each reading of the clock is later than the last: a revocation counts from when it is seen.
      { fetch: world.fetch, clock: { now: () => (world.clock.at += 1_000_000n) } },
    );
    expect(output).toStrictEqual([
      "Amina holds 1 record, an Offer",
      "it is the firm's offer: true",
      "one of 150 is the firm's: false",
      "the firm's feed has a Revocation",
      "it is the record the firm signed: true",
      "a later offer is the firm's: false",
      "the first still is: true",
      "kept with the offer: when 3 proofs came",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("shows the output the example of a charter really gives, with time that passes", async () => {
    world.resolver("https://resolver.example");
    const output = await chartering(
      ["https://resolver.example"],
      keychainLock(memoryKeychain(), "example"),
      { fetch: world.fetch, clock: { now: () => (world.clock.at += 1_000_000n) } },
    );
    expect(output).toStrictEqual([
      "the buyer, within the budget: true",
      "the buyer, beyond it: false",
      "now a collective of 4, of whom 3 act",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("shows the output the example of names really gives, with one site that points back", async () => {
    world.resolver("https://resolver.example");
    const sites = ["https://ada.example", "https://famous.example"] as const;
    // The mind's address is not known until the mind is made: the site answers with it then.
    let address = "";
    world.put(
      sites[0],
      () => new Response(`${address}\n`, { headers: { "content-type": "text/plain" } }),
    );
    world.put(
      sites[1],
      () => new Response("did:oip:another", { headers: { "content-type": "text/plain" } }),
    );
    world.before = (request) => {
      const made = /\/oip\/v1\/resolve\/([a-z0-9]+)/u.exec(request.url)?.[1];
      if (made !== undefined && address === "") address = `did:oip:${made}`;
    };
    const result = await naming(
      ["https://resolver.example"],
      sites,
      keychainLock(memoryKeychain(), "example"),
      { fetch: world.fetch, clock: world.clock },
    );
    world.before = undefined;
    expect(result.address).toBe(address);
    expect(result.output).toStrictEqual([
      "the mind lists 2 names",
      "https://ada.example: its own",
      "https://famous.example: not shown to be (not-pointing-back)",
    ]);
    expect(readme).toContain(`\`\`\`\n${result.output.join("\n")}\n\`\`\``);
  });

  it("shows the output the example of a mind's keys really gives", async () => {
    world.resolver("https://resolver.example");
    const output = await living(
      ["https://resolver.example"],
      keychainLock(memoryKeychain(), "example"),
      { fetch: world.fetch, clock: world.clock },
    );
    expect(output).toStrictEqual([
      "a key is added: the mind has 2",
      "the first is revoked: 1 is left",
      "the mind signs with the one it added: true",
      "opened again, the same mind: true",
      "it acknowledges 1 child",
      "the resolvers have its log up to event 3",
      "retired: true",
      "asked for a key to sign with, it is forbidden",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("shows the output the example of publishing really gives, against two resolvers and a host", async () => {
    const resolvers = ["https://resolver-one.example", "https://resolver-two.example"];
    for (const resolver of resolvers) world.resolver(resolver);
    world.host("https://home.example");
    const output = await publishing(
      resolvers,
      "https://home.example",
      keychainLock(memoryKeychain(), "example"),
      { fetch: world.fetch, clock: world.clock },
    );
    expect(output).toStrictEqual([
      "a profile is published: Ada, agent",
      "taken by: resolver, resolver, home",
      "its feed has an entry at 0 for a Participant",
      "its home is brought all of it again: true",
      "location record 1: paused, 2 endpoints, feed at 0",
      "another client reads: Ada, paused",
      "and its feed: 1 entry that verifies",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("shows the output the example really gives, against two resolvers", async () => {
    const resolvers = ["https://resolver-one.example", "https://resolver-two.example"];
    for (const resolver of resolvers) world.resolver(resolver);
    const output = await example(resolvers, keychainLock(memoryKeychain(), "example"), {
      fetch: world.fetch,
      clock: world.clock,
    });
    expect(output).toStrictEqual([
      "a mind is made, and 2 resolvers have its genesis",
      "it signs an Intent with 1 proof",
      "another client verifies its log: 1 event",
      "after an update it is at event 1, at https://new-home.example",
      "a backup is due for: control, operational, invocation, agreement",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("shows the output the example of finding really gives, against a resolver, a host and an indexer", async () => {
    const services = {
      resolvers: ["https://resolver.example"],
      indexers: ["https://indexer.example"],
      home: "https://home.example",
    };
    world.resolver("https://resolver.example");
    world.host(services.home);
    const indexer = world.indexer("https://indexer.example");
    // The indexer's own mind is with the resolver, so that its answers can be taken as its own.
    expect(await world.publish("https://resolver.example", indexer.mind)).toBe(202);
    const output = await finding(services, keychainLock(memoryKeychain(), "example"), {
      fetch: world.fetch,
      clock: world.clock,
    });
    expect(output).toStrictEqual([
      "listed by 1 indexer",
      "the indexer named 1 record",
      'found: Ada, for "Translation of legal texts", score 1',
      "named and not returned: 0",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("shows the output the example of sending and receiving really gives, against a resolver and two hosts", async () => {
    const homes = { ada: "https://home-one.example", bob: "https://home-two.example" };
    world.resolver("https://resolver.example");
    world.host(homes.ada);
    world.host(homes.bob);
    const output = await messaging(
      ["https://resolver.example"],
      homes,
      keychainLock(memoryKeychain(), "example"),
      { fetch: world.fetch, clock: world.clock },
    );
    expect(output).toStrictEqual([
      "sent sealed, taken by his inbox",
      "received from Ada: Could you translate a lease by Friday?",
      "a request, sealed",
      "refused: 0; left in the mailbox: 0",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("shows the output the example of listening really gives, over a socket to the host", async () => {
    const homes = { ada: "https://home-one.example", bob: "https://home-two.example" };
    world.resolver("https://resolver.example");
    world.host(homes.ada);
    world.host(homes.bob);
    const output = await hearing(
      ["https://resolver.example"],
      homes,
      keychainLock(memoryKeychain(), "example"),
      { fetch: world.fetch, clock: world.clock, webSocket: world.socket },
    );
    expect(output).toStrictEqual([
      "the socket is connecting",
      "the socket is open",
      "Bob hears from Ada: Sent while you were away.",
      "Bob hears from Ada: Sent while you listen.",
      "Bob heard 2 packets, and listens no more",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("shows the output the example of the outbox really gives, for a mind that is not there yet", async () => {
    world.resolver("https://resolver.example");
    world.host("https://home.example");
    const output = await keeping(
      ["https://resolver.example"],
      "https://home.example",
      keychainLock(memoryKeychain(), "example"),
      { fetch: world.fetch, clock: world.clock },
    );
    expect(output).toStrictEqual([
      "not taken (not-found): kept to be tried again",
      "the outbox holds a packet sent 1 time",
      "tried again: taken, 0 waiting",
      "Bob has 1 packet, the one that was signed: true",
      "given up: true",
      "the outbox holds 0 packets",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("shows the output the example of a session really gives, with one packet lost on its way", async () => {
    const homes = { ada: "https://home-one.example", bob: "https://home-two.example" };
    world.resolver("https://resolver.example");
    world.host(homes.ada);
    world.host(homes.bob);
    const run = () =>
      talking(["https://resolver.example"], homes, keychainLock(memoryKeychain(), "example"), {
        fetch: world.fetch,
        clock: world.clock,
      });
    // The second packet for Bob reaches neither his inbox nor his mailbox.
    let posted = 0;
    let losing = false;
    world.before = (request) => {
      if (request.method !== "POST" || !request.url.startsWith(homes.bob)) return;
      if (request.url.endsWith("/inbox") && ++posted === 2) losing = true;
      else if (!request.url.endsWith("/mailbox")) return;
      if (!losing) return;
      losing = request.url.endsWith("/inbox");
      throw new TypeError("fetch failed");
    };
    const output = await run();
    world.before = undefined;
    expect(output).toStrictEqual([
      "Ada sends packet 0: taken",
      "Ada sends packet 1: not taken",
      "Ada sends packet 2: taken",
      "Bob has packet 0: One.",
      "Bob lacks the packets from 1",
      "Bob asks for them, in a Resume",
      "Ada has packet 0: resume",
      "Ada sends 2 packets again",
      "Bob has packet 1: Two.",
      "Bob has packet 2: Three.",
      "Bob holds 3 of Ada's packets, in order",
      "Bob asks again: a resume, packet 1 of his own",
      "Ada leaves the session: true",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
    // With nothing lost there is nothing to ask for.
    expect(await run()).toStrictEqual([
      "Ada sends packet 0: taken",
      "Ada sends packet 1: taken",
      "Ada sends packet 2: taken",
      "Bob has packet 0: One.",
      "Bob has packet 1: Two.",
      "Bob has packet 2: Three.",
      "Bob holds 3 of Ada's packets, in order",
      "Bob asks again: a resume, packet 0 of his own",
      "Ada leaves the session: true",
    ]);
  });

  it("shows the output the example of changing hosts really gives, against a resolver and two hosts", async () => {
    const hosts = { from: "https://host-one.example", to: "https://host-two.example" };
    world.resolver("https://resolver.example");
    world.host(hosts.from);
    world.host(hosts.to);
    const output = await moving(
      ["https://resolver.example"],
      hosts,
      keychainLock(memoryKeychain(), "example"),
      { fetch: world.fetch, clock: world.clock },
    );
    expect(output).toStrictEqual([
      "at host-one.example, with a feed of 1 entry",
      "moved to host-two.example, at event 1",
      "its endpoints are at host-two.example",
      "its feed is read from 1 home: 1 entry",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("shows the output the example of a deal really gives, against a resolver and a host", async () => {
    world.resolver("https://resolver.example");
    world.host("https://home.example");
    // A clock that moves, as clocks do: a millisecond each time the client reads it.
    const clock = { now: () => (world.clock.at += 1_000_000n) };
    const output = await dealing(
      ["https://resolver.example"],
      "https://home.example",
      keychainLock(memoryKeychain(), "example"),
      { fetch: world.fetch, clock },
    );
    expect(output).toStrictEqual([
      "Amina's Intent is open",
      "the Commitment is proposed",
      "it binds the firm: true",
      "with her proof it is accepted",
      "and her Intent is satisfied",
      "the firm says it delivered: claimed-fulfilled",
      "Amina confirms: fulfilled",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("shows the output the example of a collective really gives, against a resolver", async () => {
    world.resolver("https://resolver.example");
    // A clock that moves, as clocks do: a millisecond each time the client reads it.
    const clock = { now: () => (world.clock.at += 1_000_000n) };
    const output = await founding(
      ["https://resolver.example"],
      keychainLock(memoryKeychain(), "example"),
      { fetch: world.fetch, clock },
    );
    expect(output).toStrictEqual([
      "a collective of 3, of whom 2 act",
      "signed by one: the collective's? false",
      "signed by two: the collective's? true",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
  });

  it("names only things the package exports, and every value it exports", () => {
    const table = readme.slice(
      readme.indexOf("## What it exports"),
      readme.indexOf("## What to know"),
    );
    const named = table
      .split("\n")
      .filter((line) => line.startsWith("| `"))
      .flatMap((line) => [...(line.split("|")[1] ?? "").matchAll(/`([A-Za-z_0-9]+)`/g)])
      .map((match) => match[1] ?? "");
    expect(new Set(named).size).toBe(named.length);
    const values = Object.keys(client);
    expect(values.length).toBeGreaterThan(10);
    // Every value the package exports is named, and what is named besides is a type.
    for (const value of values) expect(named, value).toContain(value);
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      [
        "Acting",
        "AliasCheck",
        "AliasOptions",
        "Answer",
        "Asking",
        "ChainView",
        "Clock",
        "CollectiveChanges",
        "ControlOptions",
        "Delivery",
        "DidLike",
        "Endpoint",
        "Fetch",
        "Fields",
        "Finding",
        "Found",
        "Grant",
        "HomeAnswer",
        "IdentityChanges",
        "Inbox",
        "IndexerAnswer",
        "KeyEntry",
        "Listed",
        "Listening",
        "ListenOptions",
        "LocationFields",
        "LookupOptions",
        "MailboxAnswer",
        "MemberOptions",
        "Message",
        "MindOptions",
        "NewCollective",
        "NewMind",
        "NotFound",
        "OpenSocket",
        "ProfileFields",
        "Publication",
        "Queued",
        "Ranking",
        "ReadFeed",
        "Received",
        "Resolved",
        "ResolverAnswer",
        "Retried",
        "Sent",
        "SessionEvent",
        "SessionView",
        "Sightings",
        "SocketLike",
        "SocketState",
        "TransportFailure",
        "TransportOptions",
      ].sort(),
    );
  });

  it("has a runnable example for every public method of a mind and of a lookup", () => {
    const examples = readdirSync(join(packageRoot, "examples"))
      .map((name) => readFileSync(join(packageRoot, "examples", name), "utf8"))
      .join("\n");
    /** The methods of a class: those of its instances, and its own. Not what is read as a value. */
    const methodsOf = (made: { prototype: object }): string[] =>
      [made.prototype, made].flatMap((holder) =>
        Object.entries(Object.getOwnPropertyDescriptors(holder))
          .filter(
            ([name, described]) => typeof described.value === "function" && name !== "constructor",
          )
          .map(([name]) => name),
      );
    const methods = [...methodsOf(client.Mind), ...methodsOf(client.Lookup)];
    expect(methods).toContain("retire");
    expect(methods).toContain("create");
    expect(methods).toContain("aliases");
    expect(methods.filter((name) => !examples.includes(`.${name}(`))).toStrictEqual([]);
    // And each example is one the README shows, with what it gives.
    for (const name of readdirSync(join(packageRoot, "examples"))) {
      expect(readme, name).toContain(`(examples/${name})`);
    }
  });

  it("gives the bounds the code has", () => {
    expect(readme).toContain("8 MiB and 10 seconds");
    expect([client.DEFAULT_MAX_BYTES, client.DEFAULT_TIMEOUT_MS]).toStrictEqual([
      8 * 2 ** 20,
      10_000,
    ]);
    expect(readme).toContain("cut to 256 printable characters");
    expect(client.MAX_DETAIL_LENGTH).toBe(256);
    expect(readme).toContain("64 logs at most for one mind");
    expect(client.DEFAULT_MAX_LOGS).toBe(64);
    expect(readme).toContain("10 000 entries of a feed from one home");
    expect(client.DEFAULT_MAX_FEED_ENTRIES).toBe(10_000);
    expect(readme).toContain("as many results as the query's `limit`, 100 at most");
    expect(client.MAX_RESULTS).toBe(100);
    expect(readme).toContain("for an hour unless you say, and for seven days at most");
    expect([
      client.DEFAULT_EXPIRES_IN,
      client.MAX_EXPIRES_IN,
      client.MAX_QUERY_EXPIRES_IN,
    ]).toStrictEqual([3600, 7 * 24 * 3600, 3600]);
    expect(client.MAX_MAILBOX_ITEMS).toBe(1000);
    expect(readme).toContain("good for an hour");
    expect(client.DEFAULT_TTL).toBe(3600);
  });
});
