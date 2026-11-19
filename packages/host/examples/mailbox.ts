// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { formatTimestamp, MEDIA_TYPE, mindId, type SyncSigner, utf8 } from "@oip/core";
import { signRequest } from "@oip/net";
import {
  type Clock,
  Database,
  Log,
  LogArchive,
  Metrics,
  RateLimiter,
  Shutdown,
  StoredNonces,
} from "@oip/server";

import { Host, HOST_MIGRATIONS, hostApp } from "@oip/host";

const ORIGIN = "https://host.example";

/** A mind, as far as signing a request for it needs: its address, a key reference and the key. */
export interface Owner {
  readonly address: string;
  readonly keyRef: string;
  readonly signer: SyncSigner;
}

/**
 * A host in memory, asked as its clients would ask one over HTTP. A mind
 * brings its bundle and is taken on. A sender delivers a packet to its
 * inbox, twice. The mind drains its mailbox and removes what it has.
 *
 * @param bundle - The owner's `Bundle`.
 * @param sender - The sender's `Bundle`, which the host is given here as a resolver would give it.
 * @param packet - A `Packet` from the sender to the owner.
 */
export async function example(
  owner: Owner,
  bundle: unknown,
  sender: unknown,
  packet: unknown,
  clock: Clock & { at: bigint },
): Promise<string[]> {
  const db = Database.open({ path: ":memory:" }, HOST_MIGRATIONS, clock);
  const log = new Log({ service: "host", clock, sink: () => undefined });
  const archive = new LogArchive({ db, clock });
  const limiter = (): RateLimiter => new RateLimiter({ burst: 100, perMinute: 600 }, clock);
  const app = hostApp({
    host: new Host({ db, archive }),
    archive,
    clock,
    log,
    metrics: new Metrics(),
    origin: ORIGIN,
    nonces: new StoredNonces(db),
    // This host takes on one mind.
    admits: (mind) => mind === owner.address,
    limits: { read: limiter(), deliver: limiter(), owner: limiter() },
    shutdown: new Shutdown({ log }),
    ready: {},
  });
  const ask = (path: string, init?: RequestInit): Promise<Response> =>
    Promise.resolve(app.fetch(new Request(`${ORIGIN}${path}`, init), {}));
  let nonces = 0;
  /** A request the owner signs (Layer 1, 13.3). */
  const signed = async (method: string, path: string, record?: unknown): Promise<RequestInit> => {
    const body = record === undefined ? undefined : utf8(JSON.stringify(record));
    const headers: [string, string][] = body === undefined ? [] : [["Content-Type", MEDIA_TYPE]];
    const added = await signRequest(
      { method, url: `${ORIGIN}${path}`, headers, ...(body === undefined ? {} : { body }) },
      { keyRef: owner.keyRef, created: clock.now(), nonce: `example-nonce-${++nonces}` },
      owner.signer,
    );
    return { method, ...(body === undefined ? {} : { body }), headers: [...headers, ...added] };
  };

  const endpoint = `/oip/v1/minds/${mindId(owner.address) ?? ""}`;
  const lines: string[] = [];
  const brought = await ask(endpoint, await signed("PUT", endpoint, bundle));
  lines.push(`the mind brings its bundle at ${formatTimestamp(clock.now())}: ${brought.status}`);

  const { mind: from } = sender as { mind: string };
  archive.publish(mindId(from) ?? "", sender as never);
  for (const time of ["first", "again"]) {
    const delivered = await ask(`${endpoint}/inbox`, {
      method: "POST",
      headers: { "content-type": MEDIA_TYPE },
      body: JSON.stringify(packet),
    });
    lines.push(`the packet is delivered, ${time}: ${delivered.status} ${await delivered.text()}`);
  }

  const mailbox = `${endpoint}/mailbox`;
  const unsigned = await ask(mailbox);
  lines.push(`anyone asks for the mind's mail: ${unsigned.status}`);
  const drained = (await (await ask(mailbox, await signed("GET", mailbox))).json()) as {
    items: { cursor: string; record: unknown }[];
  };
  lines.push(
    `the mind drains its mailbox: ${drained.items.length} item, the packet: ${String(
      JSON.stringify(drained.items[0]?.record) === JSON.stringify(packet),
    )}`,
  );
  const item = `${mailbox}/${drained.items[0]?.cursor ?? ""}`;
  lines.push(`the mind removes it: ${(await ask(item, await signed("DELETE", item))).status}`);
  const after = (await (await ask(mailbox, await signed("GET", mailbox))).json()) as {
    items: unknown[];
  };
  lines.push(`left in the mailbox: ${after.items.length}`);
  db.close();
  return lines;
}
