// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The command `oip-host`, run as a process of its own from the source. */

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const bin = join(repoRoot, "packages", "host", "src", "bin.ts");

let directory: string;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-host-bin-"));
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

describe("the command oip-host", () => {
  it("says everything that is wrong with its configuration, and ends with 1", async () => {
    const ended = await run({ OIP_HOST_PORT: "http", OIP_HOST_DATABASE: join(directory, "x.db") });
    expect(ended.code).toBe(1);
    expect(ended.out).toBe("");
    expect(ended.err.split("\n").slice(0, 3)).toStrictEqual([
      "the configuration is wrong:",
      expect.stringMatching(/^- OIP_HOST_ORIGIN is not set: /u),
      '- OIP_HOST_PORT: "http" is not a whole number from 0 to 65535',
    ]);
  });

  it("listens, answers, and stops in order when it is told to, ending with 0", async () => {
    let health = 0;
    const ended = await run(
      {
        OIP_HOST_ORIGIN: "https://host.example",
        OIP_HOST_HOST: "127.0.0.1",
        OIP_HOST_PORT: "0",
        OIP_HOST_DATABASE: join(directory, "host.db"),
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
