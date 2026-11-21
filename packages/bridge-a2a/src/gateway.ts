// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The gateway: a mind that makes minds for A2A agents (Layer 0, 1.1, 1.2
 * and 3.1).
 *
 * The gateway is a mind of its own, in a directory as the `oip` command
 * makes one. For each agent it bridges it makes a **bridged mind** in a
 * directory under its own, with keys the gateway holds, as `withBridged`
 * of `@oip/local` makes one for any gateway. The mind's profile carries
 * the capabilities made of the card's skills, and the digest of the card
 * the gateway read.
 */

import { readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { httpsOrigin, systemClock } from "@oip/client";
import {
  fileNameOf,
  keepRecords,
  openMind,
  recordText,
  UsageError,
  type Where,
  withBridged,
} from "@oip/local";

import type { Ask, Get } from "./a2a.ts";
import { type AgentInterface, CARD_PATH, interfaceOf, readCard, supports } from "./card.ts";
import { capabilitiesOf, OIP_EXTENSION } from "./mapping.ts";
import { Relay, type Relayed } from "./relay.ts";
import { type KeySource, verifySignatures } from "./signature.ts";

/** What a gateway reaches outside itself with. Each goes through the gateway's guard. */
export interface GatewayEdges {
  /** Gets a URL: an agent's card, or a file an agent names. The answer is given whatever its status. */
  readonly get: Get;
  /** Makes a request of an agent. */
  readonly ask: Ask;
  /**
   * The keys that may verify the signatures on a card: see `KeySource`.
   * The source is told the origin of the agent whose card it is, too.
   */
  readonly keys: (
    wanted: Parameters<KeySource>[0] & { readonly origin: string },
  ) => ReturnType<KeySource>;
}

/** Thrown when an agent cannot be bridged, with why. Nothing was made, or what was made is gone on with later. */
export class BridgeError extends Error {
  override readonly name = "BridgeError";
  /** What was wrong: one word for a program. */
  readonly code: "unreachable" | "no-card" | "invalid-card" | "unverified-card" | "no-interface";

  constructor(code: BridgeError["code"], message: string) {
    super(message);
    this.code = code;
  }
}

/** An agent the gateway bridges, as its directory records it. */
export interface Bridged {
  /** The agent's origin: where its card is. */
  readonly origin: string;
  /** The address of the bridged mind. */
  readonly mind: string;
  /** The reference to the entry of the gateway's feed that attests the mind. */
  readonly attestation: string;
  /** The digest of the card the gateway last read, as the mind's profile records it. */
  readonly cardDigest: string;
  /** Whether that card was signed, by a key the gateway takes. */
  readonly signed: boolean;
  /** The interface of the card the gateway speaks to. */
  readonly interface: AgentInterface;
  /** Whether the agent declares the OIP extension for A2A (Layer 0, 3.3). */
  readonly extension: boolean;
}

/** The protocol a gateway of this package bridges, as an `oip.bridge` block names it. */
export const PROTOCOL = "a2a";

const AGENT_FILE = "agent.json";
/** The longest name and summary a profile carries (Layer 1, 16.1). */
const MAX_NAME = 128;
const MAX_SUMMARY = 1024;

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

  /** The directory of the bridged mind of an agent, by the agent's origin. */
  #directory(origin: string): string {
    // An origin is not a name a file system takes: its digest is.
    return join(this.#where.dir, "agents", fileNameOf(origin));
  }

  /** What the gateway's directory records of an agent, if it bridges it. */
  bridged(origin: string): Bridged | undefined {
    try {
      const text = readFileSync(join(this.#directory(origin), AGENT_FILE), "utf8");
      return JSON.parse(text) as Bridged;
    } catch {
      return undefined;
    }
  }

  /** The agents the gateway bridges, by their origins in order. */
  agents(): Bridged[] {
    const under = join(this.#where.dir, "agents");
    let names: string[];
    try {
      names = readdirSync(under);
    } catch {
      return [];
    }
    return names
      .flatMap((name) => {
        try {
          const read = JSON.parse(readFileSync(join(under, name, AGENT_FILE), "utf8")) as Bridged;
          // What the directory of an origin records is of that origin, or it is nothing.
          return this.#directory(read.origin) === join(under, name) ? [read] : [];
        } catch {
          // A mind that is half made has no record yet: `bridge` goes on with it.
          return [];
        }
      })
      .sort((one, other) => (one.origin < other.origin ? -1 : 1));
  }

  /**
   * Bridges an A2A agent (Layer 0, 3.1): reads its card, verifies any
   * signatures on it, and makes the agent's bridged mind, or brings the
   * mind's profile up to the card where the card has changed.
   *
   * @param origin - The agent's HTTPS origin. Its card is at
   *   `/.well-known/agent-card.json` there.
   * @throws BridgeError if the card cannot be had, is no card, has
   *   signatures that do not verify, or names no interface this gateway
   *   speaks. UsageError if the gateway's own mind is not one that can attest.
   */
  async bridge(origin: string): Promise<Bridged> {
    if (httpsOrigin(origin) !== origin) {
      throw new UsageError(
        `${origin} is no HTTPS origin: an agent is named as https://agent.example`,
      );
    }
    // The card first: nothing is made for an agent whose card is not taken.
    let served: { status: number; body: Uint8Array };
    try {
      served = await this.#edges.get(origin + CARD_PATH);
    } catch (error) {
      throw new BridgeError(
        "unreachable",
        `the card of ${origin} could not be fetched${error instanceof Error ? `: ${error.message}` : ""}`,
      );
    }
    if (served.status !== 200) {
      throw new BridgeError(
        "no-card",
        `${origin} serves no card: it answered ${String(served.status)}`,
      );
    }
    const read = readCard(served.body);
    if (!read.ok) {
      const [{ path, message }] = read.issues;
      throw new BridgeError(
        "invalid-card",
        `the card of ${origin} is no card: ${message}, at ${path === "" ? "its top" : path}`,
      );
    }
    const signatures = await verifySignatures(read.value, (wanted) =>
      this.#edges.keys({ ...wanted, origin }),
    );
    if (!signatures.ok) {
      throw new BridgeError(
        "unverified-card",
        `the card of ${origin} is not taken: ${signatures.issues[0].message}`,
      );
    }
    const { card, digest } = read.value;
    const spoken = interfaceOf(card);
    if (spoken === undefined) {
      throw new BridgeError(
        "no-interface",
        `the card of ${origin} names no interface this gateway speaks: JSON-RPC, A2A 1.0, over HTTPS`,
      );
    }

    const before = this.bridged(origin);
    const dir = this.#directory(origin);
    const system = { protocol: PROTOCOL, endpoint: origin, attestation: before?.attestation };
    return withBridged(this.#where, dir, system, async ({ mind, block }) => {
      // The profile: what the card says the agent can do, and which card that was.
      if (before?.cardDigest !== digest || mind.resolved.participant === undefined) {
        const capabilities = capabilitiesOf(card);
        await mind.publishProfile({
          // A card's texts are a stranger's: each is made text that a profile holds.
          name: recordText(card.name, MAX_NAME),
          summary: recordText(card.description, MAX_SUMMARY),
          ...(capabilities.length === 0 ? {} : { capabilities }),
          // Layer 0, 3.2: what a profile lists for A2A is the URL of a card.
          interfaces: { a2a: origin + CARD_PATH },
          ext: {
            "oip.bridge": { ...block },
            "oip.a2a": { cardDigest: digest },
          },
        });
      }
      const bridged: Bridged = {
        origin,
        mind: mind.address,
        attestation: block.attestation,
        cardDigest: digest,
        signed: signatures.value.signed,
        interface: spoken,
        extension: supports(card, OIP_EXTENSION),
      };
      // Written whole or not at all: a reader never finds half of it.
      const file = join(dir, AGENT_FILE);
      writeFileSync(`${file}.partial`, JSON.stringify(bridged, undefined, 2), { mode: 0o600 });
      renameSync(`${file}.partial`, file);
      return bridged;
    });
  }

  /**
   * Relays once between a bridged mind and its agent (Layer 0, 3.1): reads
   * the mind's mailbox, sends the agent what is asked of it, and says in
   * OIP what the agent answered and what became of its tasks.
   *
   * What one packet or one task could not be done with is in the result's
   * `failed`, and is tried again by the next pass.
   *
   * @param spent - Whether the pass has had the time it may take: see
   *   `RelayEdges.spent`. What is left when it says so waits for the next pass.
   * @throws UsageError if the gateway does not bridge the agent. Whatever
   *   keeps the mind from being opened or its mailbox from being read.
   */
  async relay(origin: string, spent?: () => boolean): Promise<Relayed> {
    const bridged = this.bridged(origin);
    if (bridged === undefined) {
      throw new UsageError(`${origin} is not an agent this gateway bridges: bridge it first`);
    }
    const opened = await openMind({ edges: this.#where.edges, dir: this.#directory(origin) });
    try {
      const { ask, get } = this.#edges;
      const clock = this.#where.edges.clock ?? systemClock;
      return await new Relay(opened, bridged, {
        ask,
        get,
        clock,
        ...(spent === undefined ? {} : { spent }),
      }).pass();
    } finally {
      try {
        // What the mind signed, it signed: its records are written down whatever became of the pass.
        keepRecords(opened);
      } finally {
        opened.mind.close();
      }
    }
  }
}
