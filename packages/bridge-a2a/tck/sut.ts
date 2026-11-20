// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * The system the A2A TCK is run against (BUILD.md, M9): a mind served as
 * an A2A agent by a gateway (Layer 0, 3.2), with everything behind it real.
 *
 * This starts a network on this machine (a resolver, a host and an
 * indexer), makes a gateway's mind and a mind for it to serve, serves that
 * mind on a port, and prints the URL the TCK is given as `--sut-host`:
 *
 *     SUT http://127.0.0.1:<port>/a2a/<the mind's ID>
 *
 * The TCK says what it wants of an agent in the ID of each message
 * (`scenarios/*.feature` in the TCK). The mind that is served here is an
 * ordinary OIP mind that plays those scenarios: it reads its mailbox,
 * finds the A2A message a packet stands for in the packet's references,
 * and answers with the packet the scenario asks for. It knows nothing of
 * A2A beyond that name.
 *
 * It runs until it is stopped, and then clears up what it made.
 *
 *     node --conditions=@oip/source packages/bridge-a2a/tck/sut.ts
 */

import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { type AddressInfo, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { LOCAL, startNetwork } from "@oip/cli";
import { type Message, Mind, systemClock } from "@oip/client";
import { sha256Digest } from "@oip/core";
import { Keystore, SCRYPT_MIN_N } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";
import {
  type Config,
  Home,
  lockOf,
  type Machine,
  NETWORK_FILE,
  openMind,
  optionsOf,
  type Where,
} from "@oip/local";

import { A2aServer, Front, listen } from "../src/index.ts";

/** How long the mind and the gateway rest between two readings of their mailboxes, in milliseconds. */
const EVERY_MS = 25;

const root = mkdtempSync(join(tmpdir(), "oip-a2a-tck-"));
const directory = join(root, "network");
const network = await startNetwork({ directory });
writeFileSync(join(directory, NETWORK_FILE), JSON.stringify({ ...LOCAL, routes: network.routes }));
const config: Config = {
  resolvers: [LOCAL.resolver],
  indexers: [LOCAL.indexer],
  lock: "passphrase",
  network: directory,
};
const machine: Machine = {
  // Made for this run, for minds that live as long as it does. It is never shown.
  env: { OIP_PASSPHRASE: randomBytes(24).toString("base64url") },
  home: root,
  keychain: () => Promise.reject(new Error("this run keeps its keys under a passphrase")),
  scryptN: SCRYPT_MIN_N,
};
const where = (name: string): Where => ({ edges: machine, dir: join(root, name) });

/** Makes a mind in a directory, as `oip init` does. */
async function make(name: string, kind: string): Promise<Mind> {
  const at = where(name);
  const home = new Home(at.dir);
  const lock = await lockOf(at, config.lock, true);
  const keystore = await Keystore.create({ storage: fileStorage(home.keys), locks: lock });
  home.write(config);
  const mind = await Mind.create(optionsOf(at, home, config, keystore, lock), {
    kind,
    homes: [LOCAL.host],
  });
  await mind.publishLocation();
  return mind;
}

(await make("gateway", "service")).close();
const agent = await make("agent", "agent");
const id = agent.address.slice("did:oip:".length);

const gateway = await openMind(where("gateway"));

/** A file the mind delivers by its URL: what the scenarios call `output.txt`. */
const file = (url: string): Message["content"] => ({
  mediaType: "text/plain",
  ref: url,
  digest: sha256Digest(new TextEncoder().encode("The output of a TCK scenario.\n")),
});
const text = (body: string): Message["content"] => ({ mediaType: "text/plain", body });

/**
 * The scenarios of the TCK (`scenarios/core_operations.feature`), by the
 * prefix of the message's ID, the longest first. What has no scenario is
 * completed: that is the TCK's default.
 */
const SCENARIOS: readonly (readonly [string, Pick<Message, "verb" | "content">])[] = [
  ["tck-artifact-text", { verb: "deliver", content: text("Generated text content") }],
  ["tck-artifact-file-url", { verb: "deliver", content: file("https://example.com/output.txt") }],
  // The mind has no bytes to give but by a URL: the scenario takes a file either way.
  ["tck-artifact-file", { verb: "deliver", content: file("https://example.com/files/output.txt") }],
  [
    "tck-artifact-data",
    {
      verb: "deliver",
      content: { mediaType: "application/json", body: { key: "value", count: 42 } },
    },
  ],
  ["tck-message-response", { verb: "inform", content: text("Direct message response") }],
  ["tck-input-required", { verb: "request", content: text("More is needed to go on.") }],
  ["tck-reject-task", { verb: "decline", content: text("rejected") }],
];
const COMPLETE: Pick<Message, "verb" | "content"> = {
  verb: "deliver",
  content: text("Hello from TCK"),
};

let stopping = false;

/** The mind's side: it answers each request that reaches it as its scenario says. */
async function play(): Promise<void> {
  while (!stopping) {
    const { received } = await agent.receive();
    for (const { id: packet, from, packet: got } of received) {
      if (got.purpose.verb !== "request") continue;
      const named = (got.context?.refs ?? [])
        .filter((ref) => ref.startsWith("a2a:message/"))
        .map((ref) => decodeURIComponent(ref.slice("a2a:message/".length)));
      const [, answer = COMPLETE] =
        SCENARIOS.find(([prefix]) => named.some((message) => message.startsWith(prefix))) ?? [];
      await agent.send({
        ...answer,
        to: [from],
        replyTo: packet,
        ...(got.session === undefined ? {} : { session: got.session }),
      });
    }
    if (received.length === 0) await new Promise((resolve) => setTimeout(resolve, EVERY_MS));
  }
}

const failed = (error: unknown): void => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
};

// A card names the URL it is served at: the port is chosen before anything is served on it.
const port = await new Promise<number>((resolve, reject) => {
  const probe = createServer();
  probe.once("error", reject);
  probe.listen(0, "127.0.0.1", () => {
    const { port: free } = probe.address() as AddressInfo;
    probe.close(() => {
      resolve(free);
    });
  });
});
const base = `http://127.0.0.1:${String(port)}/a2a`;
const serving = new Front({ opened: gateway, base, version: "0.0.0", clock: systemClock });
// The mind asks to be served: its profile lists the card this gateway serves for it.
await agent.publishProfile({
  name: "The TCK's agent",
  summary: "An OIP mind that plays the scenarios of the A2A TCK.",
  capabilities: [{ id: "scenarios", summary: "Plays a scenario of the A2A TCK" }],
  interfaces: { a2a: `${base}/${id}/.well-known/agent-card.json` },
});
const served = await listen(new A2aServer(serving, "/a2a", failed), serving, {
  port,
  everyMs: EVERY_MS,
  failed,
});
const playing = play().catch(failed);

process.stdout.write(`SUT ${base}/${id}\n`);

const stop = (): void => {
  if (stopping) return;
  stopping = true;
  void (async (): Promise<void> => {
    await served.close();
    await playing;
    agent.close();
    gateway.mind.close();
    await network.stop();
    rmSync(root, { recursive: true, force: true });
  })().catch(failed);
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
