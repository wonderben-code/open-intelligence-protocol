// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The command `oip-indexer`, run as a process of its own from the source. */

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bytesToBase64url } from "@oip/core";
import { repoRoot } from "@oip/testkit";
import { KeyMind } from "@oip/testkit/minds";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const bin = join(repoRoot, "packages", "indexer", "src", "bin.ts");

let directory: string;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-indexer-bin-"));
});
afterEach(() => {
  rmSync(directory, { recursive: true, force: true });
});

/** Runs the command with an environment of its own, and gives what it wrote and how it ended. */
function run(environment: Record<string, string>, whenListening?: (port: number) => Promise<void>) {
  return new Promise<{ code: number | null; out: string; err: string }>((resolve, reject) => {
    const child = spawn(process.execPath, ["--conditions=@oip/source", bin], {
      // Nothing of this process's environment is the service's.
      env: { PATH: process.env["PATH"] ?? "", ...environment },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    let told = false;
    child.stdout.on("data", (chunk: Buffer) => {
      out += chunk.toString("utf8");
      const listening = /"event":"listening".*?"port":(\d+)/u.exec(out);
      if (listening !== null && !told && whenListening !== undefined) {
        told = true;
        whenListening(Number(listening[1])).then(() => child.kill("SIGTERM"), reject);
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      err += chunk.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({ code, out, err });
    });
  });
}

describe("the command oip-indexer", () => {
  it("says everything that is wrong with its configuration, and ends with 1", async () => {
    const ended = await run({
      OIP_INDEXER_PORT: "http",
      OIP_INDEXER_DATABASE: join(directory, "x.db"),
    });
    expect(ended.code).toBe(1);
    expect(ended.out).toBe("");
    const said = ended.err.split("\n");
    expect(said[0]).toBe("the configuration is wrong:");
    expect(said).toContain('- OIP_INDEXER_PORT: "http" is not a whole number from 0 to 65535');
    for (const setting of ["ORIGIN", "BUNDLE_FILE", "KEY_FILE"]) {
      expect(said.some((line) => line.startsWith(`- OIP_INDEXER_${setting} is not set: `))).toBe(
        true,
      );
    }
  });

  it("listens, answers, and stops in order when it is told to, ending with 0", async () => {
    // The indexer's own mind and key: fixtures the test kit makes from a name.
    const ian = new KeyMind("ian");
    const bundleFile = join(directory, "bundle.json");
    writeFileSync(
      bundleFile,
      JSON.stringify({ oip: "1", type: "Bundle", mind: ian.address, log: ian.events }),
    );
    const keyFile = join(directory, "key");
    writeFileSync(
      keyFile,
      bytesToBase64url(createHash("sha256").update("ian/operational/0").digest()),
      { mode: 0o600 },
    );
    let health = 0;
    const ended = await run(
      {
        OIP_INDEXER_ORIGIN: "https://indexer.example",
        OIP_INDEXER_HOST: "127.0.0.1",
        OIP_INDEXER_PORT: "0",
        OIP_INDEXER_DATABASE: join(directory, "indexer.db"),
        OIP_INDEXER_BUNDLE_FILE: bundleFile,
        OIP_INDEXER_KEY_FILE: keyFile,
      },
      async (port) => {
        health = (await fetch(`http://127.0.0.1:${port}/healthz`)).status;
      },
    );
    expect(health).toBe(200);
    expect(ended.err).toBe("");
    expect(ended.code).toBe(0);
    const events = ended.out
      .trim()
      .split("\n")
      .map((line) => (JSON.parse(line) as { event: string }).event);
    expect(events).toStrictEqual(["starting", "listening", "stopping", "stopped"]);
    expect(ended.out).toContain('"reason":"SIGTERM"');
    expect(ended.out).toContain('"clean":true');
  });
});
