// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The README says what is so: its tables name what there is, and its example is a result. */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import * as driver from "../src/index.ts";
import { Place } from "./harness.ts";

const directory = join(repoRoot, "packages", "did-resolver");
const readme = readFileSync(join(directory, "README.md"), "utf8");
const manifest = JSON.parse(readFileSync(join(directory, "package.json"), "utf8")) as {
  bin: Record<string, string>;
  dependencies: Record<string, string>;
};

/** The rows of the table under a heading, each as its cells. */
function table(heading: string): string[][] {
  const [, rest = ""] = readme.split(`\n${heading}\n`);
  const [section = ""] = rest.split("\n## ");
  const [first = ""] = section.split("\n### ");
  return first
    .split("\n")
    .filter((line) => line.startsWith("| ") && !line.startsWith("| -"))
    .slice(1)
    .map((line) =>
      line
        .split("|")
        .slice(1, -1)
        .map((cell) => cell.trim()),
    );
}

let place: Place;
let ada: string;
beforeAll(async () => {
  place = await new Place().start();
  ada = await place.make("ada");
});
afterAll(async () => {
  await place.close();
});

describe("the README", () => {
  it("shows a result with the members a result has", async () => {
    const [, example = ""] =
      /## What a result holds[\s\S]*?```json\n([\s\S]*?)\n```/u.exec(readme) ?? [];
    const shown = JSON.parse(example) as Record<string, Record<string, unknown>>;
    const result = await driver.resolveDid(ada, place.options());
    expect(Object.keys(shown)).toStrictEqual(Object.keys(result));
    expect(shown["didResolutionMetadata"]).toStrictEqual(result.didResolutionMetadata);
    // The same members, in the same order, for a mind that has a home and no location to show.
    const members = (value: unknown): string[] => Object.keys(value as object);
    expect(members(shown["didDocument"])).toStrictEqual(members(result.didDocument));
    expect(members(shown["didDocumentMetadata"])).toStrictEqual(
      members(result.didDocumentMetadata),
    );
    const [method] = shown["didDocument"]?.["verificationMethod"] as object[];
    expect(members(method)).toStrictEqual(members(result.didDocument?.verificationMethod[0]));
  });

  it("says what the program takes, as the program's own help does", async () => {
    expect(manifest.bin).toStrictEqual({ "oip-did-resolver": "./dist/bin.js" });
    const written = { out: "" };
    await driver.main(["--help"], {
      env: {},
      stdout: { write: (text) => (written.out += text) },
      stderr: { write: () => undefined },
      once: () => undefined,
    });
    const rows = table("### What the program takes");
    const settings = rows.map(([name = ""]) => name.replace(/`/gu, ""));
    expect(settings).toStrictEqual(["OIP_DID_RESOLVERS", "OIP_DID_HOST", "OIP_DID_PORT", "--help"]);
    for (const setting of settings) expect(written.out, setting).toContain(setting);
    for (const [name = "", says = ""] of rows) {
      const [, given] = /Default: (`?[^`\s,]+`?)/u.exec(says) ?? [];
      if (given === undefined) continue;
      const line = written.out
        .split("\n")
        .find((one) => one.trimStart().startsWith(name.replace(/`/gu, "")));
      expect(line, name).toContain(`Default: ${given.replace(/`/gu, "")}`);
    }
  });

  it("gives each error the status the interface answers with", async () => {
    // The section has two tables: the second gives a status in each row.
    const statuses = Object.fromEntries(
      table("### What it answers")
        .filter(([status = ""]) => /^\d{3}$/u.test(status))
        .map(([status = "", when = ""]) => [status, when]),
    );
    expect(Object.keys(statuses)).toStrictEqual(["200", "400", "404", "406", "410", "500", "501"]);
    const asked = async (did: string, accept?: string): Promise<string> =>
      String(
        (
          await driver.handle(
            { method: "GET", path: `/1.0/identifiers/${did}`, ...(accept ? { accept } : {}) },
            place.options(),
          )
        ).status,
      );
    expect(await asked(ada)).toBe("200");
    expect(await asked("did:oip:tooshort")).toBe("400");
    expect(await asked(`${ada.slice(0, -4)}aaaa`)).toBe("404");
    expect(await asked(ada, "application/did+ld+json")).toBe("406");
    expect(await asked("did:key:z6Mk")).toBe("501");
    expect(readme).toContain(`as \`${driver.RESOLUTION_RESULT}\``);
    expect(readme).toContain(`\`Accept: ${driver.DID_JSON}\``);
  });

  it("names only things the package exports, and every one of them", () => {
    const named = table("## What it exports").flatMap(([names = ""]) =>
      [...names.matchAll(/`([A-Za-z_]+)`/gu)].map(([, name = ""]) => name),
    );
    const values = Object.keys(driver);
    for (const value of values) expect(named, value).toContain(value);
    // What is named besides is a type, which leaves nothing in the module to see.
    expect(named.filter((name) => !values.includes(name)).sort()).toStrictEqual(
      [
        "Answer",
        "Asking",
        "DidResolutionError",
        "DidResolutionMetadata",
        "DidResolutionResult",
        "DidResolver",
        "Host",
        "ParsedDid",
        "Serving",
        "Writable",
      ].sort(),
    );
    expect(new Set(named).size).toBe(named.length);
  });

  it("shows a program that imports what the package has, and has no need of the DIF library to run", () => {
    expect(readme).toContain('import { getResolver } from "@oip/did-resolver";');
    expect(typeof driver.getResolver).toBe("function");
    expect(
      Object.keys(manifest.dependencies).filter((name) => !name.startsWith("@oip/")),
    ).toStrictEqual([]);
  });
});
