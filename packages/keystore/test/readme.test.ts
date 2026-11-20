// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { FirstSeen, witnessLog } from "@oip/identity";
import { repoRoot } from "@oip/testkit";
import { at, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { example } from "../examples/new-mind.ts";
import * as keystore from "../src/index.ts";
import * as node from "../src/node.ts";
import { quick } from "./helpers.ts";

const packageRoot = join(repoRoot, "packages", "keystore");
const readme = readFileSync(join(packageRoot, "README.md"), "utf8");

describe("the README", () => {
  it("shows examples/new-mind.ts unchanged", () => {
    const source = readFileSync(join(packageRoot, "examples", "new-mind.ts"), "utf8");
    // The file's licence header is not part of what the README shows.
    const code = source.replace(/^(\/\/ SPDX[^\n]*\n)+\n/, "");
    expect(readme).toContain(`\`\`\`ts\n${code}\`\`\``);
  });

  it("shows the output the example really gives, for a genesis that verifies", async () => {
    const published: object[] = [];
    const output = await example(keystore.memoryStorage(), quick(), T(0), (genesis) => {
      published.push(genesis);
      return Promise.resolve();
    });
    expect(output).toStrictEqual([
      "signed: 1 event awaits publication",
      "published: 1 control key destroyed",
      "kept for the next event: 1 control key",
      "a signature of 64 bytes",
      "a backup is due for: control, operational, agreement",
    ]);
    expect(readme).toContain(`\`\`\`\n${output.join("\n")}\n\`\`\``);
    expect(witnessLog(published, at(100), new FirstSeen()).log?.entries).toHaveLength(1);
  });

  it("names only things the package exports, and every value it exports", () => {
    const table = readme.slice(
      readme.indexOf("## What it exports"),
      readme.indexOf("## What to know"),
    );
    const named = table
      .split("\n")
      .filter((line) => line.startsWith("| `"))
      .flatMap((line) => [...(line.split("|")[1] ?? "").matchAll(/`([A-Za-z_0-9]+)`/g)])
      .map((match) => match[1] ?? "");
    expect(new Set(named).size).toBe(named.length);
    const values = [...Object.keys(keystore), ...Object.keys(node)];
    expect(values.length).toBeGreaterThan(30);
    // Every value the package exports is named, and what is named besides is a type.
    for (const value of values) expect(named, value).toContain(value);
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      [
        "AllKeys",
        "Backup",
        "ControlKeyInfo",
        "CreateOptions",
        "FileStorageOptions",
        "GenerateOptions",
        "IdbDatabase",
        "IdbFactory",
        "IdbObjectStore",
        "IdbOpenRequest",
        "IdbRequest",
        "IdbTransaction",
        "KeyInfo",
        "KeyRole",
        "KeyStorage",
        "Keychain",
        "KeychainHeader",
        "KeystoreErrorCode",
        "KeystoreOptions",
        "Lock",
        "LockContext",
        "LockHeader",
        "Locks",
        "MemberSigning",
        "PassphraseOptions",
        "Randomness",
        "RestoreOptions",
        "ScryptHeader",
        "SealedHeader",
        "SealedKind",
        "SealedToKey",
        "Stored",
      ].sort(),
    );
  });

  it("gives the numbers the code has", () => {
    const row = (...cells: string[]) =>
      new RegExp(
        `\\| ${cells.map((cell) => cell.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("\\s+\\| ")}`,
      );
    expect(readme).toMatch(row("Work factor of scrypt for a new passphrase lock", "2^17"));
    expect(keystore.SCRYPT_N).toBe(2 ** 17);
    expect(readme).toMatch(row("Work factor accepted", "2^14 to 2^20"));
    expect([keystore.SCRYPT_MIN_N, keystore.SCRYPT_MAX_N]).toStrictEqual([2 ** 14, 2 ** 20]);
    expect(readme).toMatch(row("Characters in a passphrase, at least", "8"));
    expect(keystore.MIN_PASSPHRASE_LENGTH).toBe(8);
    expect(readme).toMatch(row("Keys in one role", "256"));
    expect(keystore.MAX_KEYS).toBe(256);
    expect(readme).toMatch(row("Positions an invocation key remembers", "10,000"));
    expect(keystore.MAX_POSITIONS).toBe(10_000);
    expect(readme).toMatch(row("Bytes of a sealed document", "4 MiB"));
    expect(keystore.MAX_DOCUMENT_BYTES).toBe(4 * 2 ** 20);
  });
});
