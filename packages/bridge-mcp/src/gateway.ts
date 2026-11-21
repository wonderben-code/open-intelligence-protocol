// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The gateway: a mind that makes minds for MCP servers (Layer 0, 1.1, 1.2
 * and 2.1).
 *
 * The gateway is a mind of its own, in a directory as the `oip` command
 * makes one. For each server it bridges it makes a **bridged mind** in a
 * directory under its own, with keys the gateway holds, as `withBridged`
 * of `@oip/local` makes one for any gateway. The mind's profile carries a
 * capability for each tool the server lists.
 *
 * The bridged mind's directory also holds what is the operator's to say:
 * who may call which tool (`policy.json`), and what the server asks of
 * whoever calls it (`credentials.json`).
 */

import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

import { systemClock } from "@oip/client";
import { canonicalBytes, sha256Digest } from "@oip/core";
import {
  fileNameOf,
  hold,
  keepRecords,
  openMind,
  recordText,
  UsageError,
  type Where,
  withBridged,
} from "@oip/local";

import { type Connect, endpointOf, type Server, type Target } from "./connect.ts";
import {
  CREDENTIALS_FILE,
  credentialsIn,
  readCredentials,
  secretsOf,
  withoutSecrets,
} from "./credentials.ts";
import { POLICY_FILE } from "./policy.ts";
import { Relay, type Relayed } from "./relay.ts";
import { capabilitiesOf, type Mapped } from "./tools.ts";

/** What a gateway reaches outside itself with. */
export interface GatewayEdges {
  /** Connects to an MCP server. */
  readonly connect: Connect;
}

/** Thrown when a server cannot be bridged, with why. Nothing was made, or what was made is gone on with later. */
export class BridgeError extends Error {
  override readonly name = "BridgeError";
  /** What was wrong: one word for a program. */
  readonly code: "unreachable" | "no-tools";

  constructor(code: BridgeError["code"], message: string) {
    super(message);
    this.code = code;
  }
}

/** A server the gateway bridges, as its directory records it. */
export interface Bridged {
  /** How the bridged mind names the server: its URL, or `stdio:` and the operator's name for it. */
  readonly endpoint: string;
  /** Where the server is. */
  readonly target: Target;
  /** The address of the bridged mind. */
  readonly mind: string;
  /** The reference to the entry of the gateway's feed that attests the mind. */
  readonly attestation: string;
  /** How many tools of the server are capabilities of the mind. */
  readonly tools: number;
  /** The digest of what the mind's profile says of the server: its name and those capabilities. */
  readonly profileDigest: string;
}

/** What bridging a server did. */
export interface BridgedNow extends Bridged {
  /** What the server listed that is no capability, each with why. */
  readonly left: Mapped["left"];
  /** How many capabilities carry no input schema. */
  readonly withoutSchema: number;
  /** The bridged mind's directory: the policy and the credentials are there. */
  readonly directory: string;
}

/** The protocol a gateway of this package bridges, as an `oip.bridge` block names it. */
export const PROTOCOL = "mcp";

const SERVER_FILE = "server.json";
/** The file that says a process relays for a bridged mind (`hold` of `@oip/local`), in the mind's directory. */
export const RELAY_HOLD_FILE = "relay.hold";
/** The longest name a profile carries (Layer 1, 16.1). */
const MAX_NAME = 128;

/** Whether a text names something: it has a character that is no space. */
const names = (text: string | undefined): text is string =>
  text !== undefined && text.trim() !== "";

/** A gateway, in the directory of its own mind. */
export class Gateway {
  readonly #where: Where;
  readonly #edges: GatewayEdges;

  /**
   * @param where - The machine, and the directory of the gateway's own
   *   mind, made with `oip init`. It has a home: its feed is where it attests.
   */
  constructor(where: Where, edges: GatewayEdges) {
    this.#where = where;
    this.#edges = edges;
  }

  /** The directory of the bridged mind of a server, by how the mind names the server. */
  directoryOf(endpoint: string): string {
    // An endpoint is not a name a file system takes: its digest is.
    return join(this.#where.dir, "servers", fileNameOf(endpoint));
  }

  /** What the gateway's directory records of a server, if it bridges it. */
  bridged(endpoint: string): Bridged | undefined {
    try {
      const text = readFileSync(join(this.directoryOf(endpoint), SERVER_FILE), "utf8");
      const read = JSON.parse(text) as Bridged;
      // What the directory of an endpoint records is of that endpoint, or it is nothing.
      return read.endpoint === endpoint && endpointOf(read.target) === endpoint ? read : undefined;
    } catch {
      return undefined;
    }
  }

  /** The servers the gateway bridges, by their endpoints in order. */
  servers(): Bridged[] {
    const under = join(this.#where.dir, "servers");
    let names: string[];
    try {
      names = readdirSync(under);
    } catch {
      return [];
    }
    return names
      .flatMap((name) => {
        try {
          const read = JSON.parse(readFileSync(join(under, name, SERVER_FILE), "utf8")) as Bridged;
          const again = this.bridged(read.endpoint);
          return again !== undefined && this.directoryOf(read.endpoint) === join(under, name)
            ? [again]
            : [];
        } catch {
          // A mind that is half made has no record yet: `bridge` goes on with it.
          return [];
        }
      })
      .sort((one, other) => (one.endpoint < other.endpoint ? -1 : 1));
  }

  /**
   * Bridges an MCP server (Layer 0, 2.1): lists its tools, and makes the
   * server's bridged mind with a capability for each, or brings the
   * mind's profile up to the tools where they have changed.
   *
   * @param options.name - The name the mind's profile gives. Default:
   *   what the server calls itself, or else where it is.
   * @param options.credentials - A file of credentials (`credentials.ts`)
   *   that the gateway takes into the bridged mind's directory first.
   * @throws BridgeError if the server cannot be reached or lists no tool
   *   that can be a capability. UsageError if the target is none, or the
   *   gateway's own mind is not one that can attest.
   */
  async bridge(
    target: Target,
    options: { readonly name?: string; readonly credentials?: string } = {},
  ): Promise<BridgedNow> {
    const endpoint = endpointOf(target);
    const directory = this.directoryOf(endpoint);
    if (options.name !== undefined && !names(options.name)) {
      throw new UsageError("a name is text: leave --name out for the server's own");
    }
    if (options.credentials !== undefined) {
      // Read where it is first: a file that is none, or that others can read, is not taken.
      if (!existsSync(options.credentials)) {
        throw new UsageError(`there is no file ${options.credentials}`);
      }
      credentialsIn(options.credentials);
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      const file = join(directory, CREDENTIALS_FILE);
      copyFileSync(options.credentials, `${file}.partial`);
      chmodSync(`${file}.partial`, 0o600);
      renameSync(`${file}.partial`, file);
    }
    // The tools first: no mind is made for a server that cannot be asked.
    let server: Server;
    let listed: unknown[];
    const credentials = readCredentials(directory);
    // What went wrong is the operator's to read. A server may say back what it was sent: of the
    // credentials, nothing is repeated.
    const why = (error: unknown): string =>
      error instanceof Error ? `: ${withoutSecrets(error.message, secretsOf(credentials))}` : "";
    try {
      server = await this.#edges.connect(target, credentials);
    } catch (error) {
      if (error instanceof UsageError) throw error;
      throw new BridgeError(
        "unreachable",
        `the server ${endpoint} could not be reached${why(error)}`,
      );
    }
    try {
      listed = await server.tools();
    } catch (error) {
      throw new BridgeError(
        "unreachable",
        `the server ${endpoint} did not list its tools${why(error)}`,
      );
    } finally {
      await server.close().catch(() => undefined);
    }
    const mapped = capabilitiesOf(listed);
    if (mapped.capabilities.length === 0) {
      throw new BridgeError(
        "no-tools",
        `the server ${endpoint} lists no tool that can be a capability: there is nothing to ask of its mind`,
      );
    }
    // A server's name for itself is a stranger's text: made text that a profile holds. What a
    // reader shows of it, the reader makes safe to show, as of every profile.
    const name = recordText(
      options.name ??
        (names(server.name)
          ? server.name
          : target.kind === "http"
            ? new URL(target.url).host
            : target.label),
      MAX_NAME,
    );
    const capabilities = [...mapped.capabilities];
    const profileDigest = sha256Digest(canonicalBytes({ name, capabilities }));
    const before = this.bridged(endpoint);
    const system = { protocol: PROTOCOL, endpoint, attestation: before?.attestation };
    const bridged = await withBridged(this.#where, directory, system, async ({ mind, block }) => {
      // The profile: what the server lists, as the mind's capabilities.
      if (before?.profileDigest !== profileDigest || mind.resolved.participant === undefined) {
        await mind.publishProfile({
          name,
          summary: `An MCP server, reached through a gateway that holds this mind's keys. Each of its tools is a capability.`,
          capabilities,
          // Layer 1, 16.1: where the server itself is, for whoever speaks MCP. A command has no such place.
          ...(target.kind === "http" ? { interfaces: { mcp: endpoint } } : {}),
          ext: { "oip.bridge": { ...block } },
        });
      }
      const made: Bridged = {
        endpoint,
        target,
        mind: mind.address,
        attestation: block.attestation,
        tools: capabilities.length,
        profileDigest,
      };
      // Written whole or not at all: a reader never finds half of it.
      const file = join(directory, SERVER_FILE);
      writeFileSync(`${file}.partial`, JSON.stringify(made, undefined, 2), { mode: 0o600 });
      renameSync(`${file}.partial`, file);
      return made;
    });
    const policy = join(directory, POLICY_FILE);
    if (!existsSync(policy)) {
      // There for the operator to find, and saying what holds until they say more: nobody.
      writeFileSync(policy, `${JSON.stringify({ allow: {} }, undefined, 2)}\n`, { mode: 0o600 });
    }
    return { ...bridged, left: mapped.left, withoutSchema: mapped.withoutSchema, directory };
  }

  /**
   * Relays once between a bridged mind and its server (Layer 0, 2.1):
   * reads the mind's mailbox, calls the tools that are asked for by minds
   * the operator's policy covers, and answers each request.
   *
   * One pass at a time relays for a bridged mind: the pass holds the
   * mind's directory (`relay.hold`) while it runs. Two that read one
   * mailbox would each call the tool a request names.
   *
   * What one packet could not be done with is in the result's `failed`,
   * and is tried again by the next pass: credentials that cannot be read,
   * say, or a server that is away.
   *
   * @param spent - Whether the pass has had the time it may take: see
   *   `RelayEdges.spent`. What is left when it says so waits for the next pass.
   * @throws UsageError if the gateway does not bridge the server, if
   *   another process relays for it, or if the policy cannot be read.
   *   Whatever keeps the mind from being opened or its mailbox from being
   *   read.
   */
  async relay(endpoint: string, spent?: () => boolean): Promise<Relayed> {
    const bridged = this.bridged(endpoint);
    if (bridged === undefined) {
      throw new UsageError(`${endpoint} is no server this gateway bridges: bridge it first`);
    }
    const directory = this.directoryOf(endpoint);
    const held = hold(directory, RELAY_HOLD_FILE, "relays for this bridged mind");
    try {
      const opened = await openMind({ edges: this.#where.edges, dir: directory });
      try {
        return await new Relay(opened, bridged, {
          connect: this.#edges.connect,
          clock: this.#where.edges.clock ?? systemClock,
          spent: () => {
            // Looked at where it lies, and not as it was a few seconds ago: a process that stood
            // still for half a minute has lost its hold to another, and calls nothing more.
            held.beat();
            return !held.held || spent?.() === true;
          },
        }).pass();
      } finally {
        try {
          // What the mind signed, it signed: its records are written down whatever became of the pass.
          keepRecords(opened);
        } finally {
          opened.mind.close();
        }
      }
    } finally {
      held.release();
    }
  }
}
