// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The indexer's own mind, made by `oip-indexer init`. */

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  base64urlToBytes,
  keyHash,
  mindId,
  OipError,
  sha256,
  signerFromPrivateKey,
  utf8,
} from "@oip/core";
import { FirstSeen, judgeRecord, LogBook, ownSignedTime, witnessRecord } from "@oip/identity";
import { ConfigError, type Randomness } from "@oip/server";
import { clause, repoRoot } from "@oip/testkit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  init,
  INIT_FILES,
  INIT_USAGE,
  initCommand,
  readKey,
  type Running,
  start,
} from "../src/index.ts";

const CREATED = "2026-11-20T04:00:00Z";
const NOW = 1_795_147_200_000_000_000n;

let directory: string;
let running: Running[];

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "oip-indexer-init-"));
  running = [];
});
afterEach(async () => {
  for (const service of running) await service.stop("test over");
  rmSync(directory, { recursive: true, force: true });
});

/** Randomness that is the same in every run: hashes of a counter. */
function counting(): Randomness & { given: Uint8Array[] } {
  const given: Uint8Array[] = [];
  return {
    given,
    bytes: (length) => {
      const bytes = sha256(utf8(`init/${given.length}`)).subarray(0, length);
      given.push(bytes);
      return bytes;
    },
  };
}

/** The public key of the private key a file holds. */
const publicKeyIn = (path: string): string =>
  signerFromPrivateKey(base64urlToBytes(readFileSync(path, "utf8").trim()) ?? new Uint8Array(0))
    .publicKey;

interface Genesis {
  kind: string;
  controller: { keys: string[]; next: string[] };
  keys: { key: string }[];
  homes?: string[];
}

describe(`${clause("L1 3.6", "L1 3.11")} the mind an indexer is made with`, () => {
  it("is a key-controlled mind whose log verifies, with its keys in files of their owner", () => {
    const home = join(directory, "mind");
    const made = init({ directory: home, created: CREATED, randomness: counting() });
    expect(made).toEqual({
      address: made.address,
      bundleFile: join(home, "bundle.json"),
      keyFile: join(home, "operational.key"),
      nextControlKeyFile: join(home, "next-control.key"),
    });
    expect(readdirSync(home).toSorted()).toEqual(Object.values(INIT_FILES).toSorted());
    expect(statSync(home).mode & 0o777).toBe(0o700);
    expect(statSync(made.keyFile).mode & 0o777).toBe(0o600);
    expect(statSync(made.nextControlKeyFile).mode & 0o777).toBe(0o600);
    expect(statSync(made.bundleFile).mode & 0o777).toBe(0o644);

    const bundle = JSON.parse(readFileSync(made.bundleFile, "utf8")) as {
      oip: string;
      type: string;
      mind: string;
      log: Genesis[];
    };
    expect([bundle.oip, bundle.type, bundle.mind, bundle.log.length]).toEqual([
      "1",
      "Bundle",
      made.address,
      1,
    ]);
    const seen = new FirstSeen();
    const book = new LogBook(seen);
    expect(book.witness(bundle.log, NOW, seen)).toEqual({ ok: true, value: made.address });
    const log = book.log(made.address);
    expect(log.ok && log.value.entries.length).toBe(1);

    const [genesis] = bundle.log as [Genesis];
    expect(genesis.kind).toBe("service");
    expect(genesis.homes).toBeUndefined();
    // The indexer's key is the mind's operational key, as the indexer reads it.
    expect(genesis.keys).toEqual([{ key: readKey(made.keyFile).publicKey }]);
    // The genesis commits to the control key that was kept, and reveals one that was not.
    expect(genesis.controller.next).toEqual([keyHash(publicKeyIn(made.nextControlKeyFile))]);
    const kept = [publicKeyIn(made.keyFile), publicKeyIn(made.nextControlKeyFile)];
    expect(kept).not.toContain(genesis.controller.keys[0]);
    expect(new Set([...kept, genesis.controller.keys[0]]).size).toBe(3);
  });

  it("names the homes it is given, and makes nothing with one that is no HTTPS origin", () => {
    const made = init({
      directory,
      created: CREATED,
      randomness: counting(),
      homes: ["https://indexer.example"],
    });
    const bundle = JSON.parse(readFileSync(made.bundleFile, "utf8")) as { log: [Genesis] };
    expect(bundle.log[0].homes).toEqual(["https://indexer.example"]);
    const other = join(directory, "other");
    expect(() =>
      init({
        directory: other,
        created: CREATED,
        randomness: counting(),
        homes: ["http://indexer.example/path"],
      }),
    ).toThrow(OipError);
    expect(existsSync(other)).toBe(false);
  });

  it("is made once: nothing is written over", () => {
    const first = init({ directory, created: CREATED, randomness: counting() });
    const before = Object.values(INIT_FILES).map((name) =>
      readFileSync(join(directory, name), "utf8"),
    );
    const again = counting();
    expect(() => init({ directory, created: "2026-11-21T00:00:00Z", randomness: again })).toThrow(
      new ConfigError([
        `${join(directory, INIT_FILES.bundle)} is there already: a mind is made once, and its keys are not written over`,
      ]),
    );
    // No key was drawn for a mind that was not made.
    expect(again.given).toHaveLength(0);
    expect(
      Object.values(INIT_FILES).map((name) => readFileSync(join(directory, name), "utf8")),
    ).toEqual(before);
    // One file is enough to stop it.
    rmSync(first.bundleFile);
    rmSync(first.keyFile);
    expect(() => init({ directory, created: CREATED, randomness: counting() })).toThrow(
      ConfigError,
    );
    expect(existsSync(first.bundleFile)).toBe(false);
  });
});

describe("the command oip-indexer init", () => {
  /** Runs the command and keeps what it wrote. */
  const run = (args: string[]) => {
    const text = { out: "", err: "" };
    const code = initCommand(args, {
      created: CREATED,
      randomness: counting(),
      out: (more) => {
        text.out += more;
      },
      err: (more) => {
        text.err += more;
      },
    });
    return { code, ...text };
  };

  it("makes the mind and says where its files are, and nothing of a key", () => {
    const home = join(directory, "mind");
    const { code, out, err } = run([home, "--home", "https://indexer.example"]);
    expect([code, err]).toEqual([0, ""]);
    const address = /^Made the mind (did:oip:[a-z0-9]+)$/mu.exec(out)?.[1];
    expect(mindId(address)).toBeDefined();
    expect(out).toContain(`  OIP_INDEXER_BUNDLE_FILE=${join(home, "bundle.json")}\n`);
    expect(out).toContain(`  OIP_INDEXER_KEY_FILE=${join(home, "operational.key")}\n`);
    expect(out).toContain(join(home, "next-control.key"));
    for (const name of [INIT_FILES.key, INIT_FILES.nextControlKey]) {
      expect(out).not.toContain(readFileSync(join(home, name), "utf8").trim());
    }
  });

  it("makes the mind only if it is missing, where it is asked to", () => {
    const first = run([directory, "--if-missing"]);
    expect([first.code, first.err]).toEqual([0, ""]);
    expect(first.out).toMatch(/^Made the mind did:oip:/u);
    const before = Object.values(INIT_FILES).map((name) =>
      readFileSync(join(directory, name), "utf8"),
    );
    expect(run(["--if-missing", directory])).toEqual({
      code: 0,
      out: `The mind in ${directory} is there already: nothing was made.\n`,
      err: "",
    });
    expect(
      Object.values(INIT_FILES).map((name) => readFileSync(join(directory, name), "utf8")),
    ).toEqual(before);
    // Half a mind is not a mind that is there: it is not completed, and not written over.
    rmSync(join(directory, INIT_FILES.bundle));
    const half = run([directory, "--if-missing"]);
    expect([half.code, half.out]).toEqual([1, ""]);
    expect(half.err).toContain("is there already");
    expect(readFileSync(join(directory, INIT_FILES.key), "utf8")).toBe(before[1]);
  });

  it("says how it is used, and what is wrong with how it was", () => {
    expect(run(["--help"])).toEqual({ code: 0, out: INIT_USAGE, err: "" });
    expect(run(["-h"])).toEqual({ code: 0, out: INIT_USAGE, err: "" });
    const wrong: [string[], string][] = [
      [[], "give one directory"],
      [[directory, "another"], "give one directory"],
      [[directory, "--home"], "--home takes an HTTPS origin"],
      [[directory, "--force"], "--force is no option of this command"],
    ];
    for (const [args, why] of wrong) {
      expect(run(args)).toEqual({
        code: 2,
        out: "",
        err: `oip-indexer init: ${why}\n\n${INIT_USAGE}`,
      });
    }
    expect(readdirSync(directory)).toEqual([]);
    // What cannot be made is said, and the command ends with 1.
    expect(run([directory]).code).toBe(0);
    const again = run([directory]);
    expect([again.code, again.out]).toEqual([1, ""]);
    expect(again.err.startsWith("oip-indexer init: ")).toBe(true);
    expect(again.err).toContain("is there already");
    const home = run([join(directory, "other"), "--home", "ftp://indexer.example"]);
    expect([home.code, home.out]).toEqual([1, ""]);
    expect(home.err).toMatch(/^oip-indexer init: /u);
  });

  it(`makes a mind that the indexer starts with and signs as ${clause("L1 18.3")}`, async () => {
    const bin = join(repoRoot, "packages", "indexer", "src", "bin.ts");
    const home = join(directory, "mind");
    const made = spawnSync(process.execPath, ["--conditions=@oip/source", bin, "init", home], {
      encoding: "utf8",
      env: { PATH: process.env["PATH"] ?? "" },
    });
    expect([made.status, made.stderr]).toEqual([0, ""]);
    const address = /^Made the mind (did:oip:[a-z0-9]+)$/mu.exec(made.stdout)?.[1] ?? "";
    const service = await start(
      {
        OIP_INDEXER_ORIGIN: "https://indexer.example",
        OIP_INDEXER_HOST: "127.0.0.1",
        OIP_INDEXER_PORT: "0",
        OIP_INDEXER_DATABASE: join(directory, "indexer.db"),
        OIP_INDEXER_BUNDLE_FILE: join(home, INIT_FILES.bundle),
        OIP_INDEXER_KEY_FILE: join(home, INIT_FILES.key),
      },
      { sink: () => undefined },
    );
    running.push(service);
    expect(service.address).toBe(address);
    const http = `http://127.0.0.1:${service.port}`;
    const bundle = (await (
      await fetch(`${http}/.well-known/oip/mind/${mindId(address) ?? ""}`)
    ).json()) as { log: unknown };
    const answered = await fetch(`${http}/oip/v1/query`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ want: "anything" }),
    });
    const result = (await answered.json()) as { author: string };
    expect(result.author).toBe(address);
    // The result is signed by the mind that was made, as its own log shows.
    const now = BigInt(Date.now()) * 1_000_000n;
    const seen = new FirstSeen();
    const book = new LogBook(seen);
    expect(book.witness(bundle.log, now, seen).ok).toBe(true);
    const judged = judgeRecord(result);
    expect(judged.ok).toBe(true);
    if (judged.ok) {
      witnessRecord(judged.value, now, seen);
      expect(ownSignedTime(judged.value, address, book)).toBeDefined();
    }
  });
});
