// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** `oip-mcp` as a program, with what it would serve given to the test in place of a host. */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { McpServerFactory } from "@modelcontextprotocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { type Host, main, POLICY_FILE, type Serve, VERSION } from "../src/index.ts";

let root: string;
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "oip-mcp-main-"));
});
afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

/** A process, as the program sees one, with what was written to it and what it listens for. */
function host(env: Record<string, string> = {}) {
  const written = { out: "", err: "" };
  const heard = new Map<string, () => void>();
  const of: Host = {
    env,
    stdout: { write: (text) => (written.out += text) },
    stderr: { write: (text) => (written.err += text) },
    once: (signal, stop) => heard.set(signal, stop),
  };
  return { of, written, heard };
}

/** What would serve, as the test sees it. */
function serving() {
  const seen: { factory?: McpServerFactory; onerror?: (error: Error) => void; closed: number } = {
    closed: 0,
  };
  const serve: Serve = (factory, options) => {
    seen.factory = factory;
    seen.onerror = options.onerror;
    return {
      close: () => {
        seen.closed++;
        return Promise.resolve();
      },
    };
  };
  return { serve, seen };
}

describe("oip-mcp", () => {
  it("says its version, or what it takes, and serves nothing then", () => {
    const { serve, seen } = serving();
    const version = host();
    expect(main(["--version"], version.of, serve)).toBe(0);
    expect(version.written).toStrictEqual({ out: `${VERSION}\n`, err: "" });
    const help = host();
    expect(main(["--help"], help.of, serve)).toBe(0);
    expect(help.written.err).toBe("");
    expect(help.written.out).toMatch(/^oip-mcp: gives an MCP host a mind/u);
    expect(help.written.out).toContain("--dir <path>");
    expect(seen.factory).toBeUndefined();
  });

  it("ends with 2 for arguments it does not have, with nothing on its output", () => {
    const { serve, seen } = serving();
    for (const argv of [["--passphrase", "secret words"], ["extra"], ["--dir"]]) {
      const wrong = host();
      expect(main(argv, wrong.of, serve)).toBe(2);
      expect(wrong.written.out).toBe("");
      expect(wrong.written.err).toMatch(/^oip-mcp: .*`oip-mcp --help` shows what it takes\n$/u);
    }
    expect(seen.factory).toBeUndefined();
  });

  it("serves the mind of the directory it is given, of OIP_DIR, or of the home", () => {
    for (const [argv, env, dir] of [
      [["--dir", join(root, "named")], { OIP_DIR: join(root, "by-env") }, join(root, "named")],
      [[], { OIP_DIR: join(root, "by-env") }, join(root, "by-env")],
    ] as const) {
      const { serve, seen } = serving();
      const started = host(env);
      expect(main(argv, started.of, serve)).toBeUndefined();
      expect(seen.factory).toBeTypeOf("function");
      expect(started.written.out).toBe("");
      expect(started.written.err).toBe(
        `oip-mcp ${VERSION}: serving the mind of ${dir}. Every Commitment and every Receipt is confirmed by the person.\n`,
      );
    }
    const { serve } = serving();
    const home = host();
    expect(main([], home.of, serve)).toBeUndefined();
    expect(home.written.err).toMatch(/serving the mind of .*\.oip\. /u);
  });

  it("says where a policy lets something be signed unasked, and does not start with one it cannot read", () => {
    const dir = join(root, "with-policy");
    mkdirSync(dir);
    writeFileSync(
      join(dir, POLICY_FILE),
      JSON.stringify({ receipt: [["==", ".outcome", "progress"]] }),
    );
    const { serve, seen } = serving();
    const started = host();
    expect(main(["--dir", dir], started.of, serve)).toBeUndefined();
    expect(started.written.err).toContain(
      "A Commitment or a Receipt is confirmed by the person unless policy.json permits it.",
    );
    expect(seen.factory).toBeTypeOf("function");

    writeFileSync(join(dir, POLICY_FILE), "{ not json");
    const refusing = serving();
    const wrong = host();
    expect(main(["--dir", dir], wrong.of, refusing.serve)).toBe(2);
    expect(wrong.written.out).toBe("");
    expect(wrong.written.err).toMatch(/^oip-mcp: .*policy\.json is no policy/u);
    expect(refusing.seen.factory).toBeUndefined();
  });

  it("closes what it serves when the process is asked to stop, and logs what goes wrong beside a call", () => {
    const { serve, seen } = serving();
    const started = host({ OIP_DIR: join(root, "stopping") });
    expect(main([], started.of, serve)).toBeUndefined();
    expect([...started.heard.keys()].sort()).toStrictEqual(["SIGINT", "SIGTERM"]);
    started.heard.get("SIGTERM")?.();
    expect(seen.closed).toBe(1);
    started.heard.get("SIGINT")?.();
    expect(seen.closed).toBe(2);
    seen.onerror?.(new RangeError("a message too long to read"));
    expect(started.written.err).toContain("oip-mcp: RangeError: a message too long to read\n");
    expect(started.written.out).toBe("");
  });

  it("makes servers that list the tools, for a host that asks", async () => {
    const { serve, seen } = serving();
    const started = host({ OIP_DIR: join(root, "listing") });
    main([], started.of, serve);
    const server = await seen.factory?.({ era: "modern" });
    expect(server).toBeDefined();
    await server?.close();
  });

  it("lets what it did not expect be seen: it is thrown on", () => {
    const { serve } = serving();
    const broken = host();
    expect(() =>
      main(
        [],
        {
          ...broken.of,
          stderr: {
            write: () => {
              throw new Error("the log is gone");
            },
          },
        },
        serve,
      ),
    ).toThrow("the log is gone");
  });
});
