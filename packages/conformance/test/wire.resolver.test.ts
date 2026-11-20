// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The Resolver profile over the wire, run against the reference resolver on a socket of this machine. */

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { formatTimestamp, proofDigest } from "@oip/core";
import { type Running, start } from "@oip/resolver";
import { clause, repoRoot } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { report } from "../examples/run-wire.ts";
import { resolverProfile, type WireReport } from "../src/index.ts";
import {
  answered,
  type Fault,
  failed,
  faulty,
  notPassed,
  restreamed,
  rewritten,
  FAULT_TIMEOUT_MS,
} from "./wire-faults.ts";

const ORIGIN = "https://resolver.example";

let directory: string;
let running: Running[];
/** A resolver that takes unsigned bundles, and one that requires signed publication. */
let open: string;
let closed: string;

/** Starts a resolver on a port of its own and gives where it is reached. */
async function started(name: string, more: Record<string, string> = {}): Promise<string> {
  const service = await start(
    {
      OIP_RESOLVER_ORIGIN: ORIGIN,
      OIP_RESOLVER_HOST: "127.0.0.1",
      OIP_RESOLVER_PORT: "0",
      OIP_RESOLVER_DATABASE: join(directory, `${name}.db`),
      // Every run of the suite is one address: the limits are not what is tested here.
      OIP_RESOLVER_READ_BURST: "100000",
      OIP_RESOLVER_PUBLISH_BURST: "100000",
      ...more,
    },
    { sink: () => undefined },
  );
  running.push(service);
  return `http://127.0.0.1:${service.port}`;
}

beforeAll(async () => {
  directory = mkdtempSync(join(tmpdir(), "oip-wire-resolver-"));
  running = [];
  open = await started("open");
  closed = await started("closed", { OIP_RESOLVER_AUTHENTICATED_PUBLICATION: "true" });
});
afterAll(async () => {
  for (const service of running) await service.stop("test over");
  rmSync(directory, { recursive: true, force: true });
});

/** The profile run against a resolver with a fault in the way. */
const against = (target: string, fault: Fault): Promise<WireReport> =>
  resolverProfile({ target, origin: ORIGIN, fetch: faulty(fault), timeoutMs: FAULT_TIMEOUT_MS });

const isResolve = (path: string): boolean => path.startsWith("/oip/v1/resolve/");

describe("the Resolver profile over the wire", () => {
  it(`passes against the reference resolver ${clause("L1 17.1", "L1 17.2")}`, async () => {
    const report = await resolverProfile({ target: open, origin: ORIGIN });
    expect(notPassed(report)).toEqual([
      expect.stringMatching(/^resolver\/publication-unsigned: not-applicable: /u),
    ]);
    expect(report.conforms).toBe(true);
    expect(report.profile).toBe("resolver");
    expect(report.target).toBe(open);
    expect(report.summary.pass).toBe(report.checks.length - 1);
    // Each check names itself, its clauses and what it holds the resolver to.
    for (const check of report.checks) {
      expect(check.id).toMatch(/^resolver\/[a-z-]+$/u);
      expect(check.clauses.length).toBeGreaterThan(0);
      expect(check.title).not.toBe("");
    }
    expect(new Set(report.checks.map((check) => check.id)).size).toBe(report.checks.length);
  });

  it(`passes against a resolver that requires signed publication ${clause("L1 17.3", "L1 13.3")}`, async () => {
    const report = await resolverProfile({ target: closed, origin: ORIGIN });
    expect(notPassed(report)).toEqual([]);
    expect(report.conforms).toBe(true);
    expect(report.checks.map((check) => check.id)).toEqual(
      expect.arrayContaining([
        "resolver/publication-unsigned",
        "resolver/publication-signed",
        "resolver/publication-replayed",
        "resolver/publication-expired",
        "resolver/publication-ahead",
        "resolver/publication-unknown-key",
        "resolver/publication-digest",
      ]),
    );
  });
});

describe("the README", () => {
  const packageRoot = join(repoRoot, "packages", "conformance");
  const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

  it("shows examples/run-wire.ts unchanged", () => {
    const example = readFileSync(join(packageRoot, "examples", "run-wire.ts"), "utf8");
    // The file's licence header is not part of what the README shows.
    const code = example.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
    expect(readme).toContain(`\`\`\`ts\n${code}\`\`\``);
  });

  it("shows the output the example really gives against the reference resolver", async () => {
    const output = await report("resolver", { target: open, origin: ORIGIN });
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
    expect(output).toHaveLength(1);
  });

  it("reports each check that failed, with its clauses", async () => {
    const output = await report("resolver", { target: "http://127.0.0.1:9", timeoutMs: 500 });
    expect(output[0]).toMatch(
      /^the resolver at http:\/\/127\.0\.0\.1:9: 0 passed, \d+ failed, \d+ skipped, 0 not applicable: not shown to conform$/u,
    );
    expect(output[1]).toMatch(
      /^FAIL resolver\/unknown-mind \[L1 17\.1\]: the check could not be completed: /u,
    );
  });
});

describe.concurrent("a resolver with a fault fails the checks that the fault breaks", () => {
  it(`one that knows every mind ${clause("L1 17.1")}`, async () => {
    const report = await against(open, {
      answer: (asked, response) =>
        asked.method === "GET" && isResolve(asked.path) && response.status === 404
          ? answered(200, { oip: "1", type: "Bundle", log: [] }, "application/oip+json")
          : undefined,
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["unknown-mind", "not-a-mind"]));
    expect(report.conforms).toBe(false);
  });

  it(`one that answers a publication 200 ${clause("L1 17.1")}`, async () => {
    const report = await against(open, {
      answer: (asked, response) =>
        asked.method === "PUT" && response.status === 202 ? answered(200, { added: 0 }) : undefined,
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["publish", "duplicity"]));
    // What builds on a check that failed is not said to pass.
    expect(report.checks.find((check) => check.id === "resolver/resolve")?.outcome).toBe("skipped");
    expect(report.conforms).toBe(false);
  });

  it(`one that serves no first-seen times ${clause("L1 17.1", "L1 13.1")}`, async () => {
    const report = await against(open, {
      answer: (asked, response) =>
        asked.method === "GET" && isResolve(asked.path) && response.status === 200
          ? rewritten(response, ({ firstSeen: _, ...bundle }) => bundle)
          : undefined,
    });
    expect(failed(report)).toEqual(["first-seen", "location"]);
    expect(report.checks.find((check) => check.id === "resolver/first-seen-kept")?.outcome).toBe(
      "skipped",
    );
  });

  it(`one that gives the time of asking as the time first seen ${clause("L1 17.2")}`, async () => {
    const report = await against(open, {
      answer: (asked, response) =>
        asked.method === "GET" && isResolve(asked.path) && response.status === 200
          ? rewritten(response, (bundle) => ({
              ...bundle,
              firstSeen: Object.fromEntries(
                Object.keys(bundle["firstSeen"] as object).map((key) => [
                  key,
                  formatTimestamp(BigInt(Date.now()) * 1_000_000n + BigInt(performance.now() | 0)),
                ]),
              ),
            }))
          : undefined,
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["first-seen-kept", "update"]));
    expect(failed(report)).not.toContain("first-seen");
  });

  it(`one that serves an event without its proof ${clause("L1 17.1")}`, async () => {
    const report = await against(open, {
      answer: (asked, response) =>
        asked.method === "GET" && isResolve(asked.path) && response.status === 200
          ? rewritten(response, (bundle) => ({
              ...bundle,
              log: (bundle["log"] as Record<string, unknown>[]).map(
                ({ proof: _, ...event }) => event,
              ),
            }))
          : undefined,
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["resolve", "invalid-event"]));
  });

  it(`one that serves no location record ${clause("L1 17.1")}`, async () => {
    const report = await against(open, {
      answer: (asked, response) =>
        asked.method === "GET" && isResolve(asked.path) && response.status === 200
          ? rewritten(response, ({ location: _, ...bundle }) => bundle)
          : undefined,
    });
    expect(failed(report)).toEqual(["location"]);
  });

  it(`one that serves whatever it was last shown ${clause("L1 17.2")}`, async () => {
    // What was last published for each mind, verified or not.
    const shown = new Map<string, Record<string, unknown>>();
    const report = await against(open, {
      answer: async (asked, response) => {
        if (!isResolve(asked.path)) return undefined;
        if (asked.method === "PUT") {
          try {
            shown.set(asked.path, JSON.parse(asked.body) as Record<string, unknown>);
          } catch {
            // Not JSON: nothing was shown.
          }
          return undefined;
        }
        const last = shown.get(asked.path);
        if (response.status !== 200 || last === undefined) return undefined;
        return rewritten(response, (bundle) => {
          const location = last["location"] as { proof: unknown[] } | undefined;
          return {
            ...bundle,
            log: last["log"],
            ...(location === undefined ? {} : { location }),
            firstSeen: {
              ...(bundle["firstSeen"] as object),
              ...(location === undefined
                ? {}
                : { [proofDigest(location.proof[0])]: "2026-11-20T00:00:00Z" }),
            },
          };
        });
      },
    });
    expect(failed(report)).toEqual(
      expect.arrayContaining([
        "location-of-another",
        "invalid-event",
        "critical-extension",
        "counting-proofs",
        "first-seen-wins",
      ]),
    );
  });

  it(`one that takes everything it is sent ${clause("L1 17.1", "L1 17.2", "core 10.2")}`, async () => {
    const report = await against(open, {
      answer: (asked, response) =>
        asked.method === "PUT" && response.status >= 400 ? answered(202, { added: 0 }) : undefined,
    });
    expect(failed(report)).toEqual(
      expect.arrayContaining([
        "invalid-event",
        "critical-extension",
        "another-minds-bundle",
        "duplicity",
        "malformed-json",
        "not-a-bundle",
        "fraction",
        "duplicate-names",
        "too-deep",
        "too-large",
      ]),
    );
  });

  it(`one that serves no evidence of duplicity ${clause("L1 17.1")}`, async () => {
    const report = await against(open, {
      answer: (asked, response) =>
        asked.path.startsWith("/oip/v1/duplicity/") && response.status === 200
          ? rewritten(response, (evidence) => ({ ...evidence, pairs: [] }))
          : undefined,
    });
    expect(failed(report)).toEqual(["duplicity-evidence"]);
  });

  it(`one that serves a problem as plain JSON ${clause("core 10.2")}`, async () => {
    const report = await against(open, {
      answer: async (_asked, response) =>
        response.status >= 400 ? answered(response.status, await response.json()) : undefined,
    });
    expect(failed(report)).toEqual(
      expect.arrayContaining(["unknown-mind", "invalid-event", "duplicity", "malformed-json"]),
    );
  });

  it(`one whose stream gives its events no id ${clause("L1 17.1")}`, async () => {
    const report = await against(open, {
      answer: (asked, response) =>
        asked.path.startsWith("/oip/v1/stream")
          ? restreamed(response, (text) => text.replace(/^id: .*\n/gmu, ""))
          : undefined,
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["stream"]));
  });

  it(`one whose stream always starts from the first event ${clause("L1 17.1")}`, async () => {
    const report = await against(open, {
      ask: (asked) => {
        if (!asked.path.startsWith("/oip/v1/stream")) return undefined;
        const headers = new Headers(asked.headers);
        headers.delete("last-event-id");
        return { path: "/oip/v1/stream", headers };
      },
    });
    expect(failed(report)).toEqual(["stream-since", "stream-last-event-id"]);
  });

  it(`one whose stream ends when it has told what it holds ${clause("L1 17.1", "L1 17.2")}`, async () => {
    const report = await against(open, {
      answer: async (asked, response) => {
        if (!asked.path.startsWith("/oip/v1/stream")) return undefined;
        // What comes within a moment, and then the end.
        const reader = response.body?.getReader();
        const chunks: Uint8Array[] = [];
        for (;;) {
          const chunk = await Promise.race([
            reader?.read(),
            new Promise<undefined>((resolve) => {
              setTimeout(() => {
                resolve(undefined);
              }, 150);
            }),
          ]);
          if (chunk === undefined || chunk.done) break;
          chunks.push(chunk.value as Uint8Array);
        }
        void reader?.cancel();
        return new Response(Buffer.concat(chunks), { status: 200, headers: response.headers });
      },
    });
    expect(failed(report)).toEqual(["stream-live"]);
  });

  it(`one that asks for a signature and takes any ${clause("L1 13.3", "L1 17.3")}`, async () => {
    const report = await against(closed, {
      answer: (asked, response) =>
        asked.method === "PUT" && response.status === 401 && asked.headers.has("signature")
          ? answered(202, { added: 0 })
          : undefined,
    });
    expect(failed(report)).toEqual(
      expect.arrayContaining([
        "publication-replayed",
        "publication-expired",
        "publication-ahead",
        "publication-unknown-key",
        "publication-digest",
      ]),
    );
    expect(failed(report)).not.toContain("publication-signed");
  });

  it(`one that refuses an unsigned bundle as forbidden ${clause("L1 13.3", "core 10.2")}`, async () => {
    const report = await against(closed, {
      answer: async (asked, response) =>
        response.status === 401 && !asked.headers.has("signature")
          ? answered(
              403,
              {
                ...((await response.json()) as object),
                type: "urn:oip:error:forbidden",
                status: 403,
              },
              "application/problem+json",
            )
          : undefined,
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["publication-unsigned"]));
  });

  it(`one that refuses every signature ${clause("L1 13.3", "L1 17.3")}`, async () => {
    const report = await against(closed, {
      ask: (asked) => {
        if (asked.method !== "PUT") return undefined;
        const headers = new Headers(asked.headers);
        headers.delete("signature");
        return { headers };
      },
    });
    expect(failed(report)).toEqual(expect.arrayContaining(["publish", "publication-signed"]));
  });
});
