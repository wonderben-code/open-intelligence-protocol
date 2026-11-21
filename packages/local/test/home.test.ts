// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  type Config,
  directoryOf,
  Home,
  isLocal,
  NETWORK_FILE,
  readNetwork,
  UsageError,
} from "../src/index.ts";

let root: string;
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "oip-local-home-"));
});
afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

const CONFIG: Config = {
  resolvers: ["https://resolver.example", "https://resolver.example.org"],
  indexers: ["https://indexer.example"],
  lock: "passphrase",
};

describe("a mind's directory", () => {
  it("is the one named, or the environment's, or `.oip` under the user's home", () => {
    const edges = { env: {}, home: "/home/ada" };
    expect(directoryOf(undefined, edges)).toBe("/home/ada/.oip");
    expect(directoryOf(undefined, { ...edges, env: { OIP_DIR: "/srv/mind" } })).toBe("/srv/mind");
    expect(directoryOf("/elsewhere", { ...edges, env: { OIP_DIR: "/srv/mind" } })).toBe(
      "/elsewhere",
    );
    expect(directoryOf("relative", edges)).toBe(resolve("relative"));
  });

  it("keeps what the mind is configured with, for its owner alone, written whole", () => {
    const home = new Home(join(root, "ada"));
    expect(home.exists).toBe(false);
    expect(() => home.read()).toThrow(UsageError);
    expect(() => home.read()).toThrow("there is no mind in");
    home.write(CONFIG);
    expect(home.exists).toBe(true);
    expect(home.read()).toStrictEqual(CONFIG);
    expect(statSync(home.dir).mode & 0o077).toBe(0);
    expect(statSync(join(home.dir, "config.json")).mode & 0o077).toBe(0);
    // With a network of this machine, which is a directory of the user's own naming.
    home.write({ ...CONFIG, lock: "keychain", network: join(root, "net") });
    expect(home.read()).toStrictEqual({ ...CONFIG, lock: "keychain", network: join(root, "net") });
    expect([home.keys, home.memory, home.records, home.inbox]).toStrictEqual(
      ["keys", "memory", "records", "inbox"].map((name) => join(home.dir, name)),
    );
  });

  it("does not take for a configuration what is none", () => {
    const home = new Home(join(root, "wrong"));
    mkdirSync(home.dir);
    for (const written of [
      "not JSON",
      "[]",
      "null",
      JSON.stringify({ ...CONFIG, resolvers: ["http://plain.example"] }),
      JSON.stringify({ ...CONFIG, indexers: "https://indexer.example" }),
      JSON.stringify({ ...CONFIG, lock: "none" }),
      JSON.stringify({ ...CONFIG, network: 5 }),
      JSON.stringify({ indexers: [], lock: "passphrase" }),
    ]) {
      writeFileSync(join(home.dir, "config.json"), written);
      expect(() => home.read(), written).toThrow(UsageError);
    }
  });
});

describe("what a network on this machine says of itself", () => {
  const SERVICES = {
    resolver: "https://resolver.oip.localhost",
    host: "https://host.oip.localhost",
    indexer: "https://indexer.oip.localhost",
  };

  it("is read from its directory: three origins, and where each is reached", () => {
    const directory = join(root, "net");
    mkdirSync(directory);
    expect(() => readNetwork(directory)).toThrow("no network is running from");
    const routes = {
      [SERVICES.resolver]: "http://127.0.0.1:4001",
      [SERVICES.host]: "http://127.0.0.1:4002",
      [SERVICES.indexer]: "http://127.0.0.1:65535",
    };
    writeFileSync(join(directory, NETWORK_FILE), JSON.stringify({ ...SERVICES, routes }));
    expect(readNetwork(directory)).toStrictEqual({ ...SERVICES, routes });
    expect(JSON.parse(readFileSync(join(directory, NETWORK_FILE), "utf8"))).toHaveProperty(
      "routes",
    );
  });

  it("leads to this machine and nowhere else, whoever wrote it", () => {
    for (const place of ["http://127.0.0.1:1", "http://127.0.0.1:8080", "http://127.0.0.1:65535"]) {
      expect(isLocal(place), place).toBe(true);
    }
    for (const place of [
      "https://127.0.0.1:8080",
      "http://localhost:8080",
      "http://127.0.0.1",
      "http://127.0.0.1:0",
      "http://127.0.0.1:8080/",
      "http://127.0.0.1:8080@evil.example",
      "http://evil.example:8080",
      "http://127.0.0.2:8080",
      8080,
      undefined,
    ]) {
      expect(isLocal(place), String(place)).toBe(false);
    }
    const directory = join(root, "forged");
    mkdirSync(directory);
    for (const forged of [
      "not JSON",
      JSON.stringify({ ...SERVICES, routes: { [SERVICES.resolver]: "http://evil.example:80" } }),
      JSON.stringify({ ...SERVICES, routes: { "http://plain.example": "http://127.0.0.1:80" } }),
      JSON.stringify({ ...SERVICES, resolver: "http://plain.example", routes: {} }),
      JSON.stringify({ resolver: SERVICES.resolver, routes: {} }),
    ]) {
      writeFileSync(join(directory, NETWORK_FILE), forged);
      expect(() => readNetwork(directory), forged).toThrow("is not what a running network wrote");
    }
  });
});
