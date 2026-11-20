// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { type Keychain, keychainLock } from "@oip/keystore";
import { repoRoot } from "@oip/testkit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { example as dealing } from "../examples/deal.ts";
import { example as finding } from "../examples/find.ts";
import { example } from "../examples/first-mind.ts";
import { example as messaging } from "../examples/messages.ts";
import { example as moving } from "../examples/move.ts";
import { example as publishing } from "../examples/publish.ts";
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
      "publish.ts",
      "find.ts",
      "messages.ts",
      "move.ts",
      "deal.ts",
    ]) {
      const source = readFileSync(join(packageRoot, "examples", name), "utf8");
      // The file's licence header is not part of what the README shows.
      const code = source.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
      expect(readme, name).toContain(`\`\`\`ts\n${code}\`\`\``);
    }
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
        "Clock",
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
        "LocationFields",
        "LookupOptions",
        "MailboxAnswer",
        "Message",
        "MindOptions",
        "NewMind",
        "NotFound",
        "ProfileFields",
        "Publication",
        "Ranking",
        "ReadFeed",
        "Received",
        "Resolved",
        "ResolverAnswer",
        "Sent",
        "TransportFailure",
        "TransportOptions",
      ].sort(),
    );
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
