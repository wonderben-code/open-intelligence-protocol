// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind that a gateway makes for a system outside the network, and holds
 * the keys of (Layer 0, 1.1 and 1.2).
 *
 * The gateway is a mind of its own, in a directory as the `oip` command
 * makes one. For each system it bridges it makes a **bridged mind** in a
 * directory under its own:
 *
 * - the mind's `Genesis` names the gateway, in an `oip.bridge` block;
 * - an entry of the gateway's own feed names that `Genesis`: the
 *   attestation, which nobody but the gateway can sign;
 * - the mind's profile carries the block again with the reference to that
 *   entry. The profile is the caller's to write: it says what the system
 *   can do, in the terms of the protocol the gateway bridges.
 *
 * Each step is done once. A run that stops is gone on with by the next,
 * with the same keys: no second mind is made for a system.
 */

import { existsSync, mkdirSync } from "node:fs";

import { Mind } from "@oip/client";
import { contentId, formatRecordRef } from "@oip/core";
import { Keystore } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";

import { UsageError } from "./errors.ts";
import { Home } from "./home.ts";
import type { Where } from "./machine.ts";
import { lockOf, openMind, optionsOf } from "./mind.ts";

/** The system a gateway bridges, as an `oip.bridge` block names it (Layer 0, 1.2). */
export interface BridgedSystem {
  /** The protocol the system speaks: `mcp`, `a2a`. */
  readonly protocol: string;
  /** Where the system is, as the gateway reaches it. */
  readonly endpoint: string;
}

/** The `oip.bridge` block of a bridged mind's profile (Layer 0, 1.2). */
export interface BridgeBlock extends BridgedSystem {
  /** The address of the gateway. */
  readonly gateway: string;
  readonly assurance: "bridged";
  /** The reference to the entry of the gateway's feed that names the mind's `Genesis`. */
  readonly attestation: string;
}

/** A bridged mind in its gateway's hands. */
export interface Custody {
  /** The bridged mind, open. It is closed when the work with it ends. */
  readonly mind: Mind;
  /** The block its profile carries. */
  readonly block: BridgeBlock;
}

/**
 * Makes the bridged mind of a system, or goes on with one that an earlier
 * run made, and does a piece of work with it: publishing its profile, as a
 * rule.
 *
 * @param where - The machine, and the directory of the gateway's own
 *   mind. It has a home: its feed is where it attests.
 * @param dir - The directory of the bridged mind. It is made if it is not
 *   there. Its keys are sealed as the gateway's are.
 * @param system - What is bridged, and the attestation if an earlier run
 *   wrote it down: the gateway's feed is then not read for it.
 * @throws UsageError if the gateway's mind names no home.
 */
export async function withBridged<T>(
  where: Where,
  dir: string,
  system: BridgedSystem & { readonly attestation?: string | undefined },
  work: (held: Custody) => Promise<T>,
): Promise<T> {
  const gateway = await openMind(where);
  try {
    const homes = gateway.mind.state.homes;
    if (homes.length === 0) {
      throw new UsageError(
        "the gateway's mind names no home: it attests the minds it bridges in its feed, which a home serves",
      );
    }
    const block = {
      protocol: system.protocol,
      endpoint: system.endpoint,
      gateway: gateway.mind.address,
      assurance: "bridged" as const,
    };

    // The bridged mind: made once, with the gateway's lock, and gone on with if a run stopped.
    const at = { edges: where.edges, dir };
    const home = new Home(dir);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const fresh = !existsSync(home.keys);
    const lock = await lockOf(at, gateway.config.lock, false);
    const storage = fileStorage(home.keys);
    const keystore = fresh
      ? await Keystore.create({ storage, locks: lock })
      : await Keystore.open({ storage });
    home.write(gateway.config);
    const options = optionsOf(at, home, gateway.config, keystore, lock);
    const mind =
      keystore.mind === undefined
        ? await Mind.create(options, { kind: "service", homes, ext: { "oip.bridge": block } })
        : await Mind.open(options);
    try {
      if (mind.resolved.location === undefined) await mind.publishLocation();
      // The gateway's own word: an entry of its feed that names the genesis. Signed once.
      const genesis = mind.resolved.log.entries[0].event;
      let attestation = system.attestation;
      if (attestation === undefined) {
        // The feed says whether an earlier run attested the mind. If it cannot be read, nothing
        // is signed on a guess: the next run asks again.
        const { feed } = await gateway.mind.lookup.feed(gateway.mind.address);
        const attested = feed.entries.find(({ entry }) => entry.object === contentId(genesis));
        const entry = attested?.id ?? contentId(await gateway.mind.publishRecord(genesis));
        attestation = formatRecordRef(gateway.mind.address, entry);
      }
      return await work({ mind, block: { ...block, attestation } });
    } finally {
      mind.close();
    }
  } finally {
    gateway.mind.close();
  }
}
