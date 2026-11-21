// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The Host profile over the wire, run against the reference host on a socket of this machine. */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bytesToBase64url, contentId, formatTimestamp } from "@oip/core";
import { type Running, start } from "@oip/host";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  type HostSetup,
  hostProfile,
  referenceHostSetup,
  type WireClient,
  type WireMind,
  type WireReport,
} from "../src/index.ts";
import {
  answered,
  type Fault,
  failed,
  faulty,
  faultySocket,
  notPassed,
  rewritten,
  type SocketFault,
  FAULT_TIMEOUT_MS,
} from "./wire-faults.ts";

const ORIGIN = "https://host.example";

let directory: string;
let running: Running[];
let open: string;

beforeAll(async () => {
  directory = mkdtempSync(join(tmpdir(), "oip-wire-host-"));
  const service = await start(
    {
      OIP_HOST_ORIGIN: ORIGIN,
      OIP_HOST_HOST: "127.0.0.1",
      OIP_HOST_PORT: "0",
      OIP_HOST_DATABASE: join(directory, "host.db"),
      OIP_HOST_OPEN: "true",
      // Every run of the suite is one address: the limits are not what is tested here.
      OIP_HOST_READ_BURST: "100000",
      OIP_HOST_DELIVER_BURST: "100000",
      OIP_HOST_OWNER_BURST: "100000",
    },
    { sink: () => undefined },
  );
  running = [service];
  open = `http://127.0.0.1:${service.port}`;
});
afterAll(async () => {
  for (const service of running) await service.stop("test over");
  rmSync(directory, { recursive: true, force: true });
});

/** The minds a run of the suite had the host take on: the one it serves, and the one that sends to it. */
interface Minds {
  owner?: WireMind;
  sender?: WireMind;
}

/** The reference host's own interface, which also tells a test of the minds a run makes. */
const watching =
  (minds: Minds, more: (setup: HostSetup) => Partial<HostSetup> = () => ({})) =>
  (client: WireClient): HostSetup => {
    const setup = referenceHostSetup(client);
    const told: HostSetup = {
      ...setup,
      adopt: async (mind, bundle) => {
        if (minds.owner === undefined) minds.owner = mind;
        else minds.sender = mind;
        await setup.adopt(mind, bundle);
      },
    };
    return { ...told, ...more(told) };
  };

/** The profile run against the host with a fault in the way. */
const against = (
  fault: Fault,
  socket: SocketFault = {},
  setup?: (client: WireClient) => HostSetup,
): Promise<WireReport> =>
  hostProfile({
    target: open,
    origin: ORIGIN,
    fetch: faulty(fault),
    webSocket: faultySocket(socket),
    timeoutMs: FAULT_TIMEOUT_MS,
    ...(setup === undefined ? {} : { setup }),
  });

const outcome = (report: WireReport, id: string): string | undefined =>
  report.checks.find((check) => check.id === `host/${id}`)?.outcome;

const isBundle = (path: string): boolean => /^\/\.well-known\/oip\/mind\/[^/]+$/u.test(path);
const isInbox = (path: string): boolean => path.endsWith("/inbox");
const isMailbox = (path: string): boolean => /\/mailbox(\?|$)/u.test(path);
/** A query without one of its parameters. */
const without = (path: string, name: string): string => {
  const url = new URL(path, "https://host.example");
  url.searchParams.delete(name);
  return `${url.pathname}${url.search}`;
};
/** The type of a message, or `undefined` if it is not a JSON object with one. */
const typeOf = (text: string): unknown => {
  try {
    return (JSON.parse(text) as { type?: unknown }).type;
  } catch {
    return undefined;
  }
};

describe("the Host profile over the wire", () => {
  it(`passes against the reference host ${clause("L1 13.1", "L1 13.2", "L1 13.4", "L1 13.5")}`, async () => {
    const report = await hostProfile({ target: open, origin: ORIGIN });
    expect(notPassed(report)).toEqual([]);
    expect(report.conforms).toBe(true);
    expect(report.profile).toBe("host");
    expect(report.checks.length).toBeGreaterThan(30);
    expect(new Set(report.checks.map((check) => check.id)).size).toBe(report.checks.length);
  });

  it(`passes a host that keeps no mailboxes, which a host need not ${clause("L1 13.5")}`, async () => {
    const report = await against(
      {},
      {},
      watching({}, () => ({ mailbox: () => undefined })),
    );
    expect(report.conforms).toBe(true);
    expect(notPassed(report).map((line) => line.split(": ").slice(0, 2).join(": "))).toEqual(
      expect.arrayContaining([
        "host/mailbox-post: not-applicable",
        "host/socket-mail: not-applicable",
      ]),
    );
    expect(failed(report)).toEqual([]);
    expect(outcome(report, "mailbox-drain")).toBe("not-applicable");
    expect(outcome(report, "mailbox-unsigned")).toBe("not-applicable");
    expect(outcome(report, "inbox")).toBe("pass");
    expect(outcome(report, "socket-welcome")).toBe("pass");
  });

  it("says that nothing was checked of a host that takes none of its minds on", async () => {
    const report = await against(
      {},
      {},
      watching({}, () => ({ adopt: () => Promise.reject(new Error("this host is closed")) })),
    );
    expect(report.conforms).toBe(false);
    expect(notPassed(report)[0]).toMatch(/^host\/bundle: skipped: .*this host is closed/u);
    expect(failed(report)).toEqual([]);
    expect(outcome(report, "unknown-mind")).toBe("pass");
    expect(outcome(report, "inbox")).toBe("skipped");
    expect(outcome(report, "socket-welcome")).toBe("skipped");
  });

  it("skips what it cannot ask of an endpoint at another origin", async () => {
    const report = await against(
      {},
      {},
      watching({}, () => ({ endpoint: () => "https://elsewhere.example/oip" })),
    );
    expect(report.conforms).toBe(false);
    expect(outcome(report, "inbox")).toBe("skipped");
    expect(outcome(report, "bundle")).toBe("pass");
  });

  it(`verifies the Ack of a host that signs for the mind ${clause("L1 13.2")}`, async () => {
    /** An `Ack` by `signer` in the name of the mind a run's host serves. */
    const ack = (minds: Minds, signer: WireMind | undefined, packet: string): unknown => {
      const at = formatTimestamp(BigInt(Date.now()) * 1_000_000n);
      return signer?.sign({
        oip: "1",
        type: "Ack",
        author: minds.owner?.address,
        packet,
        received: at,
        created: at,
      });
    };
    /**
     * A run against a host that answers each packet delivered with what `answer` gives.
     * The host keeps the answer it gave, unless `keeps` is false.
     */
    const custodial = (
      answer: (minds: Minds, packet: string) => unknown,
      keeps = true,
    ): Promise<WireReport> => {
      const minds: Minds = {};
      const given = new Map<string, unknown>();
      return against(
        {
          answer: (asked, response) => {
            if (!isInbox(asked.path) || response.status !== 202) return undefined;
            if (!asked.body.includes('"type":"Packet"')) return undefined;
            const made = () => answer(minds, contentId(JSON.parse(asked.body) as object));
            if (!keeps) return answered(202, made(), "application/oip+json");
            if (!given.has(asked.body)) given.set(asked.body, made());
            return answered(202, given.get(asked.body), "application/oip+json");
          },
        },
        {},
        watching(minds),
      );
    };

    const signing = await custodial((minds, packet) => ack(minds, minds.owner, packet));
    expect(notPassed(signing)).toEqual([]);
    expect(signing.conforms).toBe(true);

    // One that signs a new Ack each time does not answer a duplicate as it answered the packet.
    const again = await custodial((minds, packet) => ack(minds, minds.owner, packet), false);
    expect(failed(again)).toEqual(["inbox-duplicate"]);

    // An Ack for another packet, and one that another mind signed.
    const other = await custodial((minds) => ack(minds, minds.owner, minds.owner?.id ?? ""));
    expect(failed(other)).toEqual(["inbox"]);
    const forged = await custodial((minds, packet) => ack(minds, minds.sender, packet));
    expect(failed(forged)).toEqual(["inbox"]);
  });
});

describe.concurrent("a host with a fault fails the checks that the fault breaks", () => {
  it(`one that serves every mind ${clause("L1 13.1")}`, async () => {
    const report = await against({
      answer: (asked, response) =>
        isBundle(asked.path) && response.status === 404
          ? answered(200, { oip: "1", type: "Bundle", log: [] }, "application/oip+json")
          : undefined,
    });
    expect(failed(report)).toEqual(["unknown-mind"]);
  });

  it(`one that serves a log without its proofs ${clause("L1 13.1")}`, async () => {
    const report = await against({
      answer: (asked, response) =>
        isBundle(asked.path) && response.status === 200
          ? rewritten(response, (bundle) => ({
              ...bundle,
              log: (bundle["log"] as Record<string, unknown>[]).map(
                ({ proof: _, ...event }) => event,
              ),
            }))
          : undefined,
    });
    expect(failed(report)).toEqual(["bundle"]);
    expect(outcome(report, "inbox")).toBe("skipped");
  });

  it(`one that serves a record as plain JSON ${clause("core 10.1")}`, async () => {
    const report = await against({
      answer: async (asked, response) =>
        isBundle(asked.path) && response.status === 200
          ? answered(200, await response.json())
          : undefined,
    });
    expect(failed(report)).toEqual(["bundle"]);
  });

  it(`one whose pages start from the first whatever after says ${clause("L1 13.1")}`, async () => {
    const report = await against({
      ask: (asked) =>
        asked.path.includes("/.well-known/") ? { path: without(asked.path, "after") } : undefined,
    });
    expect(failed(report)).toEqual(["log-page", "feed-page"]);
    expect(outcome(report, "object")).toBe("skipped");
  });

  it(`one whose pages never give next ${clause("L1 13.1")}`, async () => {
    const report = await against({
      answer: (asked, response) =>
        /\/(log|feed)(\?|$)/u.test(asked.path) && response.status === 200
          ? rewritten(response, ({ next: _, ...page }) => page)
          : undefined,
    });
    expect(failed(report)).toEqual(["log-page", "feed-page"]);
  });

  it(`one that serves no record a feed lists ${clause("L1 10.2")}`, async () => {
    const report = await against({
      answer: (asked, response) =>
        asked.method === "GET" && asked.path.includes("/obj/") && response.status === 200
          ? answered(
              404,
              { type: "urn:oip:error:not-found", status: 404 },
              "application/problem+json",
            )
          : undefined,
    });
    expect(failed(report)).toEqual(["object"]);
  });

  it(`one that serves a record for every content ID ${clause("L1 13.1")}`, async () => {
    const report = await against({
      answer: (asked, response) =>
        asked.method === "GET" && asked.path.includes("/obj/") && response.status === 404
          ? answered(200, { oip: "1", type: "Participant" }, "application/oip+json")
          : undefined,
    });
    expect(failed(report)).toEqual(["object"]);
  });

  it(`one that answers a delivery 200 ${clause("L1 13.2")}`, async () => {
    const report = await against({
      answer: (asked, response) =>
        isInbox(asked.path) && response.status === 202
          ? answered(200, { stored: true })
          : undefined,
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["inbox", "inbox-sealed"]));
    expect(outcome(report, "inbox-duplicate")).toBe("skipped");
  });

  it(`one that answers a delivery with nothing that says it was taken ${clause("L1 13.2")}`, async () => {
    const report = await against({
      answer: (asked, response) =>
        isInbox(asked.path) && response.status === 202
          ? answered(202, { stored: false })
          : undefined,
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["inbox", "inbox-sealed"]));
  });

  it(`one that answers a duplicate otherwise ${clause("L1 13.2")}`, async () => {
    const seen = new Set<string>();
    const report = await against({
      answer: (asked, response) => {
        if (!isInbox(asked.path) || response.status !== 202) return undefined;
        if (seen.has(asked.body)) return answered(202, { stored: true, duplicate: true });
        seen.add(asked.body);
        return undefined;
      },
    });
    expect(failed(report)).toEqual(["inbox-duplicate"]);
  });

  it(`one that takes whatever is delivered ${clause("L1 12.4", "core 10.2")}`, async () => {
    const report = await against({
      answer: (asked, response) =>
        isInbox(asked.path) && response.status >= 400 ? answered(202, { stored: true }) : undefined,
    });
    expect(failed(report)).toEqual([
      "inbox-unsigned",
      "inbox-of-another",
      "inbox-expired",
      "inbox-dates",
      "inbox-malformed",
    ]);
  });

  it(`one that takes no Sealed record ${clause("L1 13.2", "L1 12.6")}`, async () => {
    const report = await against({
      answer: (asked) =>
        isInbox(asked.path) && asked.body.includes('"type":"Sealed"')
          ? answered(
              400,
              { type: "urn:oip:error:invalid-record", status: 400 },
              "application/problem+json",
            )
          : undefined,
    });
    expect(failed(report)).toEqual(["inbox-sealed"]);
  });

  it(`one whose mailbox judges what it is sent ${clause("L1 13.5")}`, async () => {
    const report = await against({
      ask: (asked) =>
        asked.method === "POST" && isMailbox(asked.path)
          ? { path: asked.path.replace(/\/mailbox$/u, "/inbox") }
          : undefined,
    });
    expect(failed(report)).toEqual(["mailbox-unjudged"]);
    // What is recommended and not required does not decide whether a host conforms.
    expect(report.conforms).toBe(true);
  });

  it(`one whose mailbox does not say that it stored a record ${clause("L1 13.5")}`, async () => {
    const report = await against({
      answer: (asked, response) =>
        asked.method === "POST" && isMailbox(asked.path) && response.status === 202
          ? answered(202, {})
          : undefined,
    });
    expect(failed(report)).toEqual(["mailbox-post"]);
    expect(outcome(report, "mailbox-drain")).toBe("skipped");
  });

  it(`one that drains a mailbox latest first ${clause("L1 13.5")}`, async () => {
    const report = await against({
      answer: (asked, response) =>
        asked.method === "GET" && isMailbox(asked.path) && response.status === 200
          ? rewritten(response, (page) => ({
              ...page,
              items: (page["items"] as unknown[]).toReversed(),
            }))
          : undefined,
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["mailbox-drain"]));
  });

  it(`one that drains a mailbox from its start whatever after says ${clause("L1 13.5")}`, async () => {
    const report = await against({
      answer: async (asked, response) => {
        if (asked.method !== "GET" || !isMailbox(asked.path) || !asked.path.includes("after=")) {
          return undefined;
        }
        // What the request without `after` would have been answered: it is signed, so it
        // cannot be asked again here. The item at the cursor is put back before the others.
        const after = new URL(asked.path, ORIGIN).searchParams.get("after");
        return rewritten(response, (page) => ({
          ...page,
          items: [
            { cursor: after, record: { oip: "1", type: "Packet" } },
            ...(page["items"] as unknown[]),
          ],
        }));
      },
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["mailbox-after"]));
  });

  it(`one that drains a mailbox for anyone ${clause("L1 13.3", "L1 13.5")}`, async () => {
    const drained = new Map<string, string>();
    const report = await against({
      answer: async (asked, response) => {
        if (asked.method !== "GET" || !isMailbox(asked.path)) return undefined;
        if (response.status === 200) {
          drained.set(asked.path, await response.clone().text());
          return undefined;
        }
        const last = drained.get(asked.path);
        return last === undefined ? undefined : answered(200, JSON.parse(last));
      },
    });
    expect(failed(report)).toEqual([
      "mailbox-unsigned",
      "mailbox-replayed",
      "mailbox-expired",
      "mailbox-ahead",
      "mailbox-unknown-key",
      "mailbox-of-another",
    ]);
  });

  it(`one that removes an item for anyone, and one that removes none ${clause("L1 13.5")}`, async () => {
    const anyone = await against({
      answer: (asked, response) =>
        asked.method === "DELETE" && response.status >= 400
          ? new Response(null, { status: 204 })
          : undefined,
    });
    expect(failed(anyone)).toEqual(["mailbox-remove"]);
    const minds: Minds = {};
    const none = await against(
      {
        ask: (asked) =>
          asked.method === "DELETE" &&
          (asked.headers.get("signature-input") ?? "").includes(minds.owner?.address ?? "?")
            ? { method: "GET", path: "/healthz", headers: new Headers() }
            : undefined,
        answer: (asked, response) =>
          asked.path === "/healthz" && response.status === 200
            ? new Response(null, { status: 204 })
            : undefined,
      },
      {},
      watching(minds),
    );
    expect(failed(none)).toEqual(["mailbox-remove"]);
  });

  it(`one whose challenge is short, names another origin, or comes with no subprotocol ${clause("L1 13.4")}`, async () => {
    const challenge = (change: (challenge: Record<string, unknown>) => unknown): SocketFault => ({
      incoming: (text) =>
        typeOf(text) === "Challenge"
          ? JSON.stringify(change(JSON.parse(text) as Record<string, unknown>))
          : text,
    });
    const short = await against(
      {},
      challenge((sent) => ({ ...sent, nonce: bytesToBase64url(new Uint8Array(8).fill(7)) })),
    );
    expect(failed(short)).toEqual(expect.arrayContaining(["socket-challenge"]));
    const elsewhere = await against(
      {},
      challenge((sent) => ({ ...sent, domain: "https://elsewhere.example" })),
    );
    expect(failed(elsewhere)).toEqual(["socket-challenge"]);
    const unnamed = await against({}, { protocol: "" });
    expect(failed(unnamed)).toEqual(["socket-challenge"]);
    const silent = await against(
      {},
      challenge(() => ({ type: "Welcome" })),
    );
    expect(failed(silent)).toEqual(
      expect.arrayContaining(["socket-challenge", "socket-welcome", "socket-deliver"]),
    );
  });

  it(`one that welcomes whoever says hello ${clause("L1 13.3", "L1 13.4")}`, async () => {
    const report = await against(
      {},
      {
        outgoing: (text, reply) => {
          if (typeOf(text) !== "Hello") return text;
          reply(
            JSON.stringify({
              type: "Welcome",
              mind: (JSON.parse(text) as { author: string }).author,
            }),
          );
          return undefined;
        },
      },
    );
    expect(failed(report)).toEqual(
      expect.arrayContaining([
        "socket-wrong-challenge",
        "socket-wrong-domain",
        "socket-challenge-once",
      ]),
    );
    expect(failed(report)).not.toContain("socket-welcome");
  });

  it(`one that welcomes a mind by another address ${clause("L1 13.4")}`, async () => {
    const report = await against(
      {},
      {
        incoming: (text) =>
          typeOf(text) === "Welcome"
            ? JSON.stringify({ type: "Welcome", mind: "did:oip:another" })
            : text,
      },
    );
    expect(failed(report)).toEqual(
      expect.arrayContaining(["socket-welcome", "socket-deliver", "socket-refused", "socket-mail"]),
    );
  });

  it(`one that closes with other codes ${clause("L1 13.4")}`, async () => {
    const policy = await against(
      {},
      { closed: (code, reason) => ({ code: code === 4401 ? 1008 : code, reason }) },
    );
    expect(failed(policy)).toEqual([
      "socket-wrong-challenge",
      "socket-wrong-domain",
      "socket-challenge-once",
      "socket-no-hello",
    ]);
    const normal = await against(
      {},
      { closed: (code, reason) => ({ code: code === 1008 ? 1000 : code, reason }) },
    );
    expect(failed(normal)).toEqual(["socket-refused"]);
    expect(outcome(normal, "socket-refused-reason")).toBe("skipped");
    const unexplained = await against({}, { closed: (code) => ({ code, reason: "" }) });
    expect(failed(unexplained)).toEqual(["socket-refused-reason"]);
    expect(unexplained.conforms).toBe(true);
  });

  it(`one that refuses a packet sent over the socket, or answers it for another ${clause("L1 13.4", "L1 13.2")}`, async () => {
    const refusing = await against(
      {},
      {
        // The packet arrives with another nonce than the one that was signed.
        outgoing: (text) =>
          typeOf(text) === "Packet" && !text.includes('"proofValue":"zz')
            ? text.replace(/"nonce":"[0-9a-f]{2}/u, '"nonce":"zz')
            : text,
      },
    );
    expect(failed(refusing)).toEqual(expect.arrayContaining(["socket-deliver"]));
    const answering = await against(
      {},
      {
        outgoing: (text, reply) => {
          if (typeOf(text) === "Packet") reply(JSON.stringify({ type: "Ack", packet: "another" }));
          return text;
        },
      },
    );
    expect(failed(answering)).toEqual(expect.arrayContaining(["socket-deliver"]));
  });

  it(`one that sends a mind none of its mail, and one that forgets what it sent ${clause("L1 13.4", "L1 13.5")}`, async () => {
    const none = await against(
      {},
      { incoming: (text) => (typeOf(text) === "Packet" ? undefined : text) },
    );
    expect(failed(none)).toEqual(["socket-mail"]);
    // What was sent over a socket is gone from the mailbox, acknowledged or not.
    const sent = new Set<string>();
    const forgetful = await against(
      {
        answer: (asked, response) =>
          asked.method === "GET" && isMailbox(asked.path) && response.status === 200
            ? rewritten(response, (page) => ({
                ...page,
                items: (page["items"] as { record: object }[]).filter(
                  (item) => !sent.has(contentId(item.record)),
                ),
              }))
            : undefined,
      },
      {
        incoming: (text) => {
          if (typeOf(text) === "Packet") sent.add(contentId(JSON.parse(text) as object));
          return text;
        },
      },
    );
    expect(failed(forgetful)).toEqual(expect.arrayContaining(["socket-mail"]));
  });
});
