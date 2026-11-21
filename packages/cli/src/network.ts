// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A network on this machine: the reference resolver, host and indexer, each
 * listening on a port of its own, for trying the protocol with nothing else
 * to hand.
 *
 * A client asks HTTPS origins only, and each service knows itself by one:
 * a signed request and a `Hello` name it (Layer 1, 13.3). So the services of
 * a local network have origins like any other, under `oip.localhost`, and
 * the command reaches them by a route: a request for the origin is sent to
 * the port on this machine instead. What is signed is the same as it would
 * be on the internet.
 */

import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { formatTimestamp, mindId } from "@oip/core";
import { start as startHost } from "@oip/host";
import { init as initIndexer, INIT_FILES, start as startIndexer } from "@oip/indexer";
import { routed } from "@oip/local";
import { start as startResolver } from "@oip/resolver";

/** The origins the services of a local network are known by. */
export const LOCAL = {
  resolver: "https://resolver.oip.localhost",
  host: "https://host.oip.localhost",
  indexer: "https://indexer.oip.localhost",
} as const;

/** A network that runs on this machine. */
export interface Network {
  /** The origin of its resolver. */
  readonly resolver: string;
  /** The origin of its host, which takes on any mind. */
  readonly host: string;
  /** The origin of its indexer. */
  readonly indexer: string;
  /** Where each origin is really reached: `http://127.0.0.1:<port>`. */
  readonly routes: Readonly<Record<string, string>>;
  /** Stops its services, in order. */
  stop(): Promise<void>;
}

/** What starting a network takes. */
export interface NetworkOptions {
  /** Where the services keep their databases, and the indexer its mind. */
  readonly directory: string;
  /** Where the services' logs go. Default: nowhere. */
  readonly sink?: (line: string) => void;
  /** The present, for the indexer's own mind. Default: the system's clock. */
  readonly now?: () => bigint;
  /** Random bytes, for the indexer's own keys. Default: the platform's generator. */
  readonly random?: (length: number) => Uint8Array;
}

/** The services of a local network are generous: every client is at one address. */
const GENEROUS = { BURST: "10000", PER_MINUTE: "600000" } as const;

/**
 * Starts a resolver, a host that takes on any mind, and an indexer with a
 * mind of its own, each on a port the system gives it.
 */
export async function startNetwork(options: NetworkOptions): Promise<Network> {
  const { directory } = options;
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const edges = { sink: options.sink ?? ((): void => undefined) };
  const local = "127.0.0.1";
  const routes: Record<string, string> = {};
  const stops: (() => Promise<unknown>)[] = [];
  const stop = async (): Promise<void> => {
    for (const stopping of stops.reverse()) await stopping();
    stops.length = 0;
  };
  /** Asks a service of this network, for a service of this network. */
  const get = async (
    url: string,
    accept: string,
  ): Promise<{ status: number; body: Uint8Array }> => {
    const answer = await routed(routes, fetch)(new Request(url, { headers: { accept } }));
    return { status: answer.status, body: new Uint8Array(await answer.arrayBuffer()) };
  };
  /** Posts to a service of this network, for the indexer that forwards a packet (18.5). */
  const post = async (
    url: string,
    body: Uint8Array,
    contentType: string,
  ): Promise<{ status: number }> => {
    const answer = await routed(
      routes,
      fetch,
    )(
      new Request(url, {
        method: "POST",
        headers: { "content-type": contentType },
        // Memory of this program's own, which a browser's types ask to be told.
        body: body as Uint8Array<ArrayBuffer>,
      }),
    );
    return { status: answer.status };
  };
  try {
    const resolver = await startResolver(
      {
        OIP_RESOLVER_ORIGIN: LOCAL.resolver,
        OIP_RESOLVER_HOST: local,
        OIP_RESOLVER_PORT: "0",
        OIP_RESOLVER_DATABASE: join(directory, "resolver.db"),
        OIP_RESOLVER_READ_BURST: GENEROUS.BURST,
        OIP_RESOLVER_READ_PER_MINUTE: GENEROUS.PER_MINUTE,
        OIP_RESOLVER_PUBLISH_BURST: GENEROUS.BURST,
        OIP_RESOLVER_PUBLISH_PER_MINUTE: GENEROUS.PER_MINUTE,
      },
      edges,
    );
    stops.push(() => resolver.stop("the network is stopping"));
    routes[LOCAL.resolver] = `http://${local}:${String(resolver.port)}`;

    const host = await startHost(
      {
        OIP_HOST_ORIGIN: LOCAL.host,
        OIP_HOST_HOST: local,
        OIP_HOST_PORT: "0",
        OIP_HOST_DATABASE: join(directory, "host.db"),
        OIP_HOST_OPEN: "true",
        OIP_HOST_RESOLVERS: LOCAL.resolver,
        OIP_HOST_READ_BURST: GENEROUS.BURST,
        OIP_HOST_READ_PER_MINUTE: GENEROUS.PER_MINUTE,
        OIP_HOST_DELIVER_BURST: GENEROUS.BURST,
        OIP_HOST_DELIVER_PER_MINUTE: GENEROUS.PER_MINUTE,
        OIP_HOST_OWNER_BURST: GENEROUS.BURST,
        OIP_HOST_OWNER_PER_MINUTE: GENEROUS.PER_MINUTE,
      },
      { ...edges, get },
    );
    stops.push(() => host.stop("the network is stopping"));
    routes[LOCAL.host] = `http://${local}:${String(host.port)}`;

    // The indexer signs what it answers, as a mind of its own. It is made once, and the
    // resolver is told of it, so that a client can check what the indexer signs.
    const own = join(directory, "indexer");
    const files = {
      bundle: join(own, INIT_FILES.bundle),
      key: join(own, INIT_FILES.key),
    };
    let bundle: string;
    try {
      bundle = readFileSync(files.bundle, "utf8");
    } catch {
      initIndexer({
        directory: own,
        created: formatTimestamp(options.now?.() ?? BigInt(Date.now()) * 1_000_000n),
        randomness: {
          bytes: options.random ?? ((length) => crypto.getRandomValues(new Uint8Array(length))),
        },
      });
      bundle = readFileSync(files.bundle, "utf8");
    }
    const mind = (JSON.parse(bundle) as { mind: string }).mind;
    const told = await routed(
      routes,
      fetch,
    )(
      new Request(`${LOCAL.resolver}/oip/v1/resolve/${mindId(mind) ?? ""}`, {
        method: "PUT",
        headers: { "content-type": "application/oip+json" },
        body: bundle,
      }),
    );
    if (!told.ok)
      throw new Error(`the resolver did not take the indexer's log: ${String(told.status)}`);
    const indexer = await startIndexer(
      {
        OIP_INDEXER_ORIGIN: LOCAL.indexer,
        OIP_INDEXER_HOST: local,
        OIP_INDEXER_PORT: "0",
        OIP_INDEXER_DATABASE: join(directory, "indexer.db"),
        OIP_INDEXER_BUNDLE_FILE: files.bundle,
        OIP_INDEXER_KEY_FILE: files.key,
        OIP_INDEXER_RESOLVERS: LOCAL.resolver,
        OIP_INDEXER_QUERY_BURST: GENEROUS.BURST,
        OIP_INDEXER_QUERY_PER_MINUTE: GENEROUS.PER_MINUTE,
        OIP_INDEXER_SUBMIT_BURST: GENEROUS.BURST,
        OIP_INDEXER_SUBMIT_PER_MINUTE: GENEROUS.PER_MINUTE,
      },
      { ...edges, get, post },
    );
    stops.push(() => indexer.stop("the network is stopping"));
    routes[LOCAL.indexer] = `http://${local}:${String(indexer.port)}`;
  } catch (error) {
    await stop();
    throw error;
  }
  return { ...LOCAL, routes, stop };
}
