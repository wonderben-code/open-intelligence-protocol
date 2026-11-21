// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Running a profile by its name, the report as text, and the command `oip-conformance`. */

import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { repoRoot } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  command,
  formatReport,
  readArguments,
  runWire,
  USAGE,
  WIRE_PROFILES,
  type WireReport,
} from "../src/index.ts";

/** A report with a check of each outcome. */
const report: WireReport = {
  suite: "oip-conformance-wire",
  oip: "1",
  profile: "resolver",
  target: "https://resolver.example",
  started: "2026-11-20T00:00:00Z",
  finished: "2026-11-20T00:00:05Z",
  checks: [
    {
      id: "resolver/publish",
      clauses: ["L1 17.1"],
      level: "MUST",
      title: "It is published",
      outcome: "pass",
    },
    {
      id: "resolver/resolve",
      clauses: ["L1 17.1", "L1 13.1"],
      level: "MUST",
      title: "It resolves",
      outcome: "fail",
      detail: "required 200; got 500",
    },
    {
      id: "resolver/duplicate-names",
      clauses: ["core 1.1"],
      level: "SHOULD",
      title: "Twice is refused",
      outcome: "skipped",
      detail: "it builds on a bundle",
    },
    {
      id: "resolver/publication-unsigned",
      clauses: ["L1 17.3"],
      level: "MUST",
      title: "Unsigned is refused",
      outcome: "not-applicable",
      detail: "it takes unsigned bundles",
    },
  ],
  summary: { pass: 1, fail: 1, "not-applicable": 1, skipped: 1 },
  conforms: false,
};

/** What a run of the command wrote. */
function written() {
  const text = { out: "", err: "" };
  return {
    text,
    write: {
      out: (more: string) => {
        text.out += more;
      },
      err: (more: string) => {
        text.err += more;
      },
    },
  };
}

describe("a report as text", () => {
  it("has a line for each check, what went wrong under it, and the sum", () => {
    expect(formatReport(report).split("\n")).toEqual([
      "OIP conformance over the wire: the resolver at https://resolver.example",
      "",
      "pass  resolver/publish  [L1 17.1]",
      "      It is published",
      "FAIL  resolver/resolve  [L1 17.1, L1 13.1]",
      "      It resolves",
      "      -> required 200; got 500",
      "skip  resolver/duplicate-names  [core 1.1] (recommended)",
      "      Twice is refused",
      "      -> it builds on a bundle",
      "n/a   resolver/publication-unsigned  [L1 17.3]",
      "      Unsigned is refused",
      "      -> it takes unsigned bundles",
      "",
      "1 passed, 1 failed, 1 not applicable, 1 skipped.",
      "This run does not show that the implementation conforms to the resolver profile.",
      "",
    ]);
    expect(formatReport({ ...report, conforms: true })).toContain(
      "Every check that the resolver profile requires passed or did not apply.",
    );
  });
});

describe("the arguments of the command", () => {
  it("are a profile and a URL, and options", () => {
    expect(readArguments(["resolver", "https://resolver.example"])).toEqual({
      profile: "resolver",
      options: { target: "https://resolver.example" },
      json: false,
      allowSkipped: false,
    });
    expect(
      readArguments([
        "--json",
        "host",
        "--origin",
        "https://host.example",
        "http://127.0.0.1:8080",
        "--timeout",
        "2500",
      ]),
    ).toEqual({
      profile: "host",
      options: { target: "http://127.0.0.1:8080", origin: "https://host.example", timeoutMs: 2500 },
      json: true,
      allowSkipped: false,
    });
    expect(readArguments(["indexer", "https://indexer.example", "--allow-skipped"])).toMatchObject({
      allowSkipped: true,
    });
  });

  it("are refused with a sentence that says why", () => {
    const refused: [string[], string][] = [
      [[], "give a profile and a URL"],
      [["resolver"], "give a profile and a URL"],
      [["resolver", "https://a.example", "https://b.example"], "give a profile and a URL"],
      [
        ["gateway", "https://a.example"],
        "gateway is no profile: give one of resolver, host, indexer",
      ],
      [["resolver", "a.example"], "the URL is an http or https URL; got a.example"],
      [["resolver", "ftp://a.example"], "the URL is an http or https URL; got ftp://a.example"],
      [["resolver", "https://"], "the URL is an http or https URL; got https://"],
      [
        ["resolver", "https://a.example", "--origin", "a.example"],
        "--origin is an http or https URL; got a.example",
      ],
      [["resolver", "https://a.example", "--origin"], "--origin takes a value"],
      [["resolver", "https://a.example", "--timeout"], "--timeout takes a value"],
      [
        ["resolver", "https://a.example", "--timeout", "soon"],
        "--timeout is a number of milliseconds",
      ],
      [
        ["resolver", "https://a.example", "--timeout", "0"],
        "--timeout is a number of milliseconds",
      ],
      [
        ["resolver", "https://a.example", "--timeout", "1.5"],
        "--timeout is a number of milliseconds",
      ],
      [["resolver", "https://a.example", "--verbose"], "--verbose is no option of this command"],
    ];
    for (const [args, why] of refused) expect(readArguments(args)).toBe(why);
  });
});

describe("the command oip-conformance", () => {
  it("runs the profile, writes the report and ends with 0 or 1 by whether it conforms", async () => {
    const asked: unknown[] = [];
    const run =
      (conforms: boolean): typeof runWire =>
      (profile, options) => {
        asked.push([profile, options]);
        return Promise.resolve({ ...report, conforms });
      };
    const failing = written();
    expect(await command(["resolver", "https://resolver.example"], failing.write, run(false))).toBe(
      1,
    );
    expect(failing.text).toEqual({ out: formatReport(report), err: "" });
    const passing = written();
    expect(
      await command(["resolver", "https://resolver.example", "--json"], passing.write, run(true)),
    ).toBe(0);
    expect(JSON.parse(passing.text.out)).toEqual({ ...report, conforms: true });
    expect(passing.text.out.endsWith("}\n")).toBe(true);
    expect(asked).toEqual([
      ["resolver", { target: "https://resolver.example" }],
      ["resolver", { target: "https://resolver.example" }],
    ]);
  });

  it("ends with 0 for a run with skipped checks only where it is told that it may", async () => {
    const check = (
      outcome: WireReport["checks"][number]["outcome"],
      level: "MUST" | "SHOULD" = "MUST",
    ): WireReport["checks"][number] => ({
      id: `resolver/${outcome}`,
      clauses: ["L1 17.1"],
      level,
      title: "A check",
      outcome,
    });
    const ending = (checks: WireReport["checks"], args: string[] = []): Promise<number> =>
      command(["resolver", "https://resolver.example", ...args], written().write, () =>
        Promise.resolve({ ...report, checks, conforms: false }),
      );
    const skipped = [check("pass"), check("skipped")];
    expect(await ending(skipped)).toBe(1);
    expect(await ending(skipped, ["--allow-skipped"])).toBe(0);
    // What failed has failed, whatever was skipped.
    expect(await ending([...skipped, check("fail")], ["--allow-skipped"])).toBe(1);
    // A recommended check that failed does not decide.
    expect(await ending([...skipped, check("fail", "SHOULD")], ["--allow-skipped"])).toBe(0);
  });

  it("says how it is used when asked, and when it is used wrongly", async () => {
    const run: typeof runWire = () => Promise.reject(new Error("nothing is run"));
    for (const flag of ["--help", "-h"]) {
      const help = written();
      expect(await command([flag], help.write, run)).toBe(0);
      expect(help.text).toEqual({ out: USAGE, err: "" });
    }
    const wrong = written();
    expect(await command(["gateway", "https://a.example"], wrong.write, run)).toBe(2);
    expect(wrong.text).toEqual({
      out: "",
      err: `oip-conformance: gateway is no profile: give one of resolver, host, indexer\n\n${USAGE}`,
    });
    for (const profile of WIRE_PROFILES) expect(USAGE).toContain(profile);
  });

  it("runs as a process from the source", () => {
    const bin = join(repoRoot, "packages", "conformance", "src", "bin.ts");
    const run = (args: string[]) =>
      spawnSync(process.execPath, ["--conditions=@oip/source", bin, ...args], {
        encoding: "utf8",
        env: { PATH: process.env["PATH"] ?? "" },
      });
    const help = run(["--help"]);
    expect([help.status, help.stdout, help.stderr]).toEqual([0, USAGE, ""]);
    const wrong = run([]);
    expect(wrong.status).toBe(2);
    expect(wrong.stderr).toContain("oip-conformance: give a profile and a URL");
    // Nothing listens there: every check fails or is skipped, and the command says so.
    const nobody = run(["resolver", "http://127.0.0.1:9", "--timeout", "500", "--json"]);
    expect(nobody.status).toBe(1);
    const told = JSON.parse(nobody.stdout) as WireReport;
    expect(told.profile).toBe("resolver");
    expect(told.conforms).toBe(false);
    expect(told.summary.pass).toBe(0);
  });
});

describe("a profile run by its name", () => {
  it("reports each profile, and every check as failed or skipped where nothing answers", async () => {
    for (const profile of WIRE_PROFILES) {
      const told = await runWire(profile, { target: "http://127.0.0.1:9/", timeoutMs: 500 });
      expect(told.profile).toBe(profile);
      expect(told.suite).toBe("oip-conformance-wire");
      expect(told.oip).toBe("1");
      // The slash at the end of a URL is not part of where it is.
      expect(told.target).toBe("http://127.0.0.1:9");
      expect(told.conforms).toBe(false);
      expect(told.summary.pass).toBe(0);
      expect(told.summary.fail + told.summary.skipped).toBe(told.checks.length);
      expect(Date.parse(told.finished)).toBeGreaterThanOrEqual(Date.parse(told.started));
      const first = told.checks.find((check) => check.outcome === "fail");
      expect(first?.detail).toMatch(/^the check could not be completed: /u);
    }
  });
});
