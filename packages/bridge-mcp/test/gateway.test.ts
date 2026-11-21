// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A gateway bridges MCP servers (Layer 0, 1.2 and 2.1), against a real
 * resolver, host and indexer on ports of this machine. The server is its
 * list of tools: what a gateway reads before it calls one.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { UsageError } from "@oip/local";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  BridgeError,
  type Connect,
  type Credentials,
  CREDENTIALS_FILE,
  Gateway,
  jsonText,
  NOBODY,
  POLICY_FILE,
  readPolicy,
  type Target,
  WITHHELD,
} from "../src/index.ts";
import { LISTED, Place, Tools } from "./harness.ts";

const LEXIS: Target = { kind: "http", url: "https://tools.lexis.example/mcp" };
const ENDPOINT = "https://tools.lexis.example/mcp";

let place: Place;
let gatewayAddress: string;
let tools: Tools;

beforeAll(async () => {
  place = await new Place().start();
  gatewayAddress = await place.make("gateway", { kind: "service" });
  tools = new Tools();
});
afterAll(async () => {
  await place.close();
});

const gateway = (): Gateway => new Gateway(place.where("gateway"), { connect: tools.connect });

/** What bridging is refused with. */
async function refusal(target: Target): Promise<string> {
  try {
    await gateway().bridge(target);
  } catch (error) {
    if (error instanceof BridgeError) return error.code;
    throw error;
  }
  throw new Error("the server was bridged");
}

describe("a gateway bridging an MCP server", () => {
  it(`${clause("L0 1.2", "L0 2.1")} makes a bridged mind with a capability for each tool: its name, its description, and its input schema`, async () => {
    const bridged = await gateway().bridge(LEXIS);
    expect(bridged).toMatchObject({
      endpoint: ENDPOINT,
      target: LEXIS,
      tools: LISTED.length,
      left: [],
      withoutSchema: 0,
      directory: gateway().directoryOf(ENDPOINT),
    });
    expect(bridged.attestation.startsWith(`${gatewayAddress}/`)).toBe(true);
    // The tools were asked for once, and the connection closed.
    expect(tools.connections).toHaveLength(1);
    expect(tools.closed).toBe(1);

    // As anyone on the network finds it.
    const resolved = await place.reader().resolve(bridged.mind);
    expect(resolved.state.kind).toBe("service");
    const block = {
      protocol: "mcp",
      endpoint: ENDPOINT,
      gateway: gatewayAddress,
      assurance: "bridged",
    };
    expect(resolved.log.entries[0].event.ext).toStrictEqual({ "oip.bridge": block });
    const profile = resolved.participant?.record as unknown as {
      capabilities: { id: string; summary: string; ext?: Record<string, unknown> }[];
    };
    expect(profile).toMatchObject({
      // What the server calls itself.
      name: "Lexis tools",
      kind: "service",
      // Layer 1, 16.1: where the server itself is, for whoever speaks MCP.
      interfaces: { mcp: ENDPOINT },
      ext: { "oip.bridge": { ...block, attestation: bridged.attestation } },
    });
    expect(profile.capabilities.map(({ id }) => id)).toStrictEqual(
      LISTED.map((tool) => tool["name"]),
    );
    const [echo, scale] = profile.capabilities;
    expect(echo).toStrictEqual({
      id: "echo",
      summary: "Says what it is told.",
      inputs: ["application/json"],
      outputs: ["application/json"],
      ext: { "oip.mcp": { inputSchema: LISTED[0]?.["inputSchema"] } },
    });
    // A tool without a description is summarised by its title. A schema with a fraction in it
    // is no member of a record: it is there as its JSON text.
    expect(scale?.summary).toBe("Scale");
    expect(scale?.ext).toStrictEqual({
      "oip.mcp": { inputSchema: jsonText(LISTED[1]?.["inputSchema"]) },
    });
  });

  it(`${clause("L0 1.3")} is found \`bridged\` by a client that asks: the gateway's feed attests the mind`, async () => {
    const bridged = gateway().bridged(ENDPOINT);
    expect(await place.reader().assurance(bridged?.mind ?? "")).toStrictEqual({
      level: "bridged",
      gateway: gatewayAddress,
      protocol: "mcp",
      endpoint: ENDPOINT,
    });
  });

  it(`${clause("L0 2.1")} opens no tool to anybody until its operator says: the policy is there, and names nobody`, () => {
    const directory = gateway().directoryOf(ENDPOINT);
    expect(JSON.parse(readFileSync(join(directory, POLICY_FILE), "utf8"))).toStrictEqual({
      allow: {},
    });
    expect(readPolicy(directory)).toStrictEqual(NOBODY);
    expect(statSync(join(directory, POLICY_FILE)).mode & 0o077).toBe(0);
  });

  it("makes no second mind and signs nothing new for a server it bridges already", async () => {
    const before = gateway().bridged(ENDPOINT);
    const profile = (await place.reader().resolve(before?.mind ?? "")).participant?.id;
    const entries = (await place.reader().feed(gatewayAddress)).feed.entries.length;
    const again = await gateway().bridge(LEXIS);
    expect(again).toMatchObject({ ...before });
    expect((await place.reader().resolve(again.mind)).participant?.id).toBe(profile);
    expect((await place.reader().feed(gatewayAddress)).feed.entries).toHaveLength(entries);
    // The operator's policy is theirs: bridging again leaves it as it is.
    const policy = join(again.directory, POLICY_FILE);
    writeFileSync(policy, JSON.stringify({ allow: { echo: "anyone" } }));
    await gateway().bridge(LEXIS);
    expect(readPolicy(again.directory)).toStrictEqual({ allow: { echo: "anyone" } });
  });

  it("brings the mind's profile up to the tools, where the server lists others now", async () => {
    const before = gateway().bridged(ENDPOINT);
    tools.listed = [...LISTED, { name: "new_tool", description: "Is new." }];
    try {
      const after = await gateway().bridge(LEXIS);
      expect(after.mind).toBe(before?.mind);
      expect(after.attestation).toBe(before?.attestation);
      expect(after.profileDigest).not.toBe(before?.profileDigest);
      // A tool that gives no schema is a capability all the same, without one.
      expect(after).toMatchObject({ tools: LISTED.length + 1, withoutSchema: 1 });
      const profile = (await place.reader().resolve(after.mind)).participant?.record as unknown as {
        capabilities: { id: string; ext?: unknown }[];
      };
      expect(profile.capabilities.at(-1)).toStrictEqual({
        id: "new_tool",
        summary: "Is new.",
        inputs: ["application/json"],
        outputs: ["application/json"],
      });
      expect(gateway().bridged(ENDPOINT)).toStrictEqual({
        ...before,
        ...gateway().bridged(ENDPOINT),
      });
    } finally {
      tools.listed = LISTED;
      await gateway().bridge(LEXIS);
    }
  });

  it("bridges a server that is a command under the operator's name for it, and publishes no command", async () => {
    const files: Target = {
      kind: "stdio",
      label: "files",
      command: "/usr/local/bin/files-server",
      args: ["--root", "/srv/private"],
    };
    tools.name = undefined;
    try {
      const bridged = await gateway().bridge(files, { name: "The firm's files" });
      expect(bridged.endpoint).toBe("stdio:files");
      const resolved = await place.reader().resolve(bridged.mind);
      const profile = resolved.participant?.record as unknown as Record<string, unknown>;
      expect(profile["name"]).toBe("The firm's files");
      // A command has no place a stranger could reach: the profile lists none.
      expect(profile["interfaces"]).toBeUndefined();
      const published = JSON.stringify([profile, resolved.log.entries[0].event]);
      expect(published).not.toContain("files-server");
      expect(published).not.toContain("/srv/private");
      expect(published).toContain("stdio:files");
      // Without a name from the operator or the server, the label is the name.
      const other = await gateway().bridge({ ...files, label: "other" });
      const named = (await place.reader().resolve(other.mind)).participant?.record;
      expect((named as unknown as { name: string }).name).toBe("other");
      expect(
        gateway()
          .servers()
          .map(({ endpoint }) => endpoint),
      ).toStrictEqual([ENDPOINT, "stdio:files", "stdio:other"]);
    } finally {
      tools.name = "Lexis tools";
    }
  });

  it(`${clause("L0 2.1")} holds the credentials the server asks for: taken into the mind's directory, for its owner alone, and given to nobody but the server`, async () => {
    const target: Target = { kind: "http", url: "https://paid.example/mcp" };
    const given = join(place.root, "given.json");
    writeFileSync(given, JSON.stringify({ headers: { Authorization: "Bearer t0p-s3cret" } }), {
      mode: 0o600,
    });
    const bridged = await gateway().bridge(target, { credentials: given });
    const kept = join(bridged.directory, CREDENTIALS_FILE);
    expect(statSync(kept).mode & 0o777).toBe(0o600);
    expect(tools.connections.at(-1)).toStrictEqual({
      target,
      credentials: { headers: { Authorization: "Bearer t0p-s3cret" }, query: {}, env: {} },
    });
    // Nothing the gateway published, and nothing it wrote down of the server, has the secret.
    const resolved = await place.reader().resolve(bridged.mind);
    const published = [
      resolved.participant?.record,
      ...resolved.log.entries.map(({ event }) => event),
    ];
    expect(JSON.stringify(published)).not.toContain("t0p-s3cret");
    expect(JSON.stringify(gateway().bridged(bridged.endpoint))).not.toContain("t0p-s3cret");

    // A file that others can read is not taken, and one that is not there is not either.
    chmodSync(given, 0o644);
    await expect(gateway().bridge(target, { credentials: given })).rejects.toThrow(
      "can be read by others",
    );
    await expect(
      gateway().bridge(target, { credentials: join(place.root, "none.json") }),
    ).rejects.toThrow(UsageError);
  });

  it("makes nothing for a server it cannot reach, that will not list its tools, or that has none", async () => {
    const target: Target = { kind: "http", url: "https://absent.example/mcp" };
    const directory = gateway().directoryOf("https://absent.example/mcp");
    tools.down = true;
    expect(await refusal(target)).toBe("unreachable");
    tools.down = false;
    tools.mute = true;
    expect(await refusal(target)).toBe("unreachable");
    tools.mute = false;
    tools.listed = [{ description: "A tool without a name." }];
    expect(await refusal(target)).toBe("no-tools");
    tools.listed = LISTED;
    expect(existsSync(directory)).toBe(false);
    expect(gateway().bridged("https://absent.example/mcp")).toBeUndefined();
    await expect(gateway().relay("https://absent.example/mcp")).rejects.toThrow(
      "is no server this gateway bridges",
    );
  });

  it("cuts a name that a profile has no room for, and passes over a directory that is half made", async () => {
    const target: Target = { kind: "stdio", label: "long-name", command: "x", args: [] };
    const bridged = await gateway().bridge(target, { name: "n".repeat(200) });
    const profile = (await place.reader().resolve(bridged.mind)).participant?.record;
    const { name } = profile as unknown as { name: string };
    expect(Array.from(name)).toHaveLength(128);
    expect(name.endsWith(String.fromCodePoint(0x2026))).toBe(true);
    // A directory without the gateway's record of a server is of a mind not yet made whole.
    mkdirSync(join(place.root, "gateway", "servers", "0".repeat(40)), { recursive: true });
    expect(
      gateway()
        .servers()
        .map(({ endpoint }) => endpoint),
    ).toContain("stdio:long-name");
  });

  it("says what a connection says of how it was asked: what is the operator's to put right is not the server's fault", async () => {
    const asked = new Gateway(place.where("gateway"), {
      connect: () => Promise.reject(new UsageError("the credentials are not as they should be")),
    });
    await expect(asked.bridge({ kind: "http", url: "https://usage.example/mcp" })).rejects.toThrow(
      UsageError,
    );
    const rude = new Gateway(place.where("gateway"), {
      // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- a transport of another's making may reject with anything
      connect: () => Promise.reject("no error at all"),
    });
    await expect(rude.bridge({ kind: "http", url: "https://rude.example/mcp" })).rejects.toThrow(
      "the server https://rude.example/mcp could not be reached",
    );
    const mute = new Gateway(place.where("gateway"), {
      connect: () =>
        Promise.resolve({
          // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- as above
          tools: () => Promise.reject("nothing"),
          call: () => Promise.resolve({}),
          close: () => Promise.reject(new Error("it would not even close")),
        }),
    });
    await expect(mute.bridge({ kind: "http", url: "https://mute.example/mcp" })).rejects.toThrow(
      "the server https://mute.example/mcp did not list its tools",
    );
  });

  it("says nothing of the credentials where a server says them back as it fails", async () => {
    const target: Target = { kind: "http", url: "https://echoing.example/mcp" };
    const given = join(place.root, "echoed.json");
    writeFileSync(given, JSON.stringify({ headers: { "X-Api-Key": "k-0123456789abcdef" } }), {
      mode: 0o600,
    });
    const said = async (edges: { connect: Connect }): Promise<string> => {
      try {
        await new Gateway(place.where("gateway"), edges).bridge(target, { credentials: given });
      } catch (error) {
        expect(error).toBeInstanceOf(BridgeError);
        return (error as Error).message;
      }
      throw new Error("the server was bridged");
    };
    const echo = (credentials: Credentials): Error =>
      new Error(
        `HTTP 401: the header x-api-key: ${credentials.headers["X-Api-Key"] ?? ""} is not valid`,
      );
    expect(await said({ connect: (_, credentials) => Promise.reject(echo(credentials)) })).toBe(
      `the server https://echoing.example/mcp could not be reached: HTTP 401: the header x-api-key: ${WITHHELD} is not valid`,
    );
    expect(
      await said({
        connect: (_, credentials) =>
          Promise.resolve({
            tools: () => Promise.reject(echo(credentials)),
            call: () => Promise.resolve({}),
            close: () => Promise.resolve(),
          }),
      }),
    ).toBe(
      `the server https://echoing.example/mcp did not list its tools: HTTP 401: the header x-api-key: ${WITHHELD} is not valid`,
    );
  });

  it("names the mind by where the server is, where the server gives itself no name, and makes any name text a record holds", async () => {
    const nameOf = async (mind: string): Promise<string> => {
      const profile = (await place.reader().resolve(mind)).participant?.record;
      return (profile as unknown as { name: string }).name;
    };
    const before = tools.name;
    try {
      tools.name = "   ";
      const blank = await gateway().bridge({ kind: "http", url: "https://nameless.example/mcp" });
      expect(await nameOf(blank.mind)).toBe("nameless.example");
      tools.name = undefined;
      const none = await gateway().bridge({
        kind: "stdio",
        label: "nameless",
        command: "x",
        args: [],
      });
      expect(await nameOf(none.mind)).toBe("nameless");
      // Half a pair of surrogates is in no record (core 1.1).
      tools.name = `Tools${String.fromCodePoint(0xd800)} of a server`;
      const odd = await gateway().bridge({ kind: "http", url: "https://odd-name.example/mcp" });
      expect(await nameOf(odd.mind)).toBe(`Tools${String.fromCodePoint(0xfffd)} of a server`);
    } finally {
      tools.name = before;
    }
  });

  it("takes no target that is none", async () => {
    await expect(gateway().bridge({ kind: "http", url: "tools.example" })).rejects.toThrow(
      UsageError,
    );
    await expect(
      gateway().bridge({ kind: "http", url: "http://tools.example/mcp" }),
    ).rejects.toThrow("is reached over HTTPS");
    // A URL with a query is none: the whole of it would be published, a key in it too.
    await expect(
      gateway().bridge({ kind: "http", url: "https://tools.example/mcp?key=sk-1234567890" }),
    ).rejects.toThrow("carries no query");
    // And a name is text.
    for (const name of ["", "   "]) {
      await expect(gateway().bridge(LEXIS, { name })).rejects.toThrow("a name is text");
    }
    await expect(
      gateway().bridge({ kind: "stdio", label: "Has Spaces", command: "x", args: [] }),
    ).rejects.toThrow(UsageError);
  });

  it("is not a gateway without a home: it has no feed to attest in", async () => {
    await place.make("homeless", { kind: "service", homes: [] });
    const homeless = new Gateway(place.where("homeless"), { connect: tools.connect });
    await expect(homeless.bridge(LEXIS)).rejects.toThrow("names no home");
    expect(homeless.servers()).toStrictEqual([]);
  });

  it("takes for a server only what its own directory records of it", () => {
    const directory = gateway().directoryOf(ENDPOINT);
    const file = join(directory, "server.json");
    const kept = readFileSync(file, "utf8");
    try {
      // A record that names another server than its directory is of is no record of either.
      writeFileSync(file, kept.replaceAll("tools.lexis.example", "other.example"));
      expect(gateway().bridged(ENDPOINT)).toBeUndefined();
      expect(
        gateway()
          .servers()
          .map(({ endpoint }) => endpoint),
      ).not.toContain("https://other.example/mcp");
      writeFileSync(file, "not JSON");
      expect(gateway().bridged(ENDPOINT)).toBeUndefined();
    } finally {
      writeFileSync(file, kept);
    }
    expect(gateway().bridged(ENDPOINT)?.endpoint).toBe(ENDPOINT);
  });
});
