// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Place } from "./harness.ts";

let place: Place;
const dirs = { ada: "", bo: "", cy: "" };
const minds = { ada: "", bo: "", cy: "" };
type Who = keyof typeof dirs;

async function as<T = Record<string, unknown>>(who: Who, ...argv: string[]): Promise<T> {
  const ran = await place.oip([...argv, "--dir", dirs[who], "--json"]);
  expect(ran.err, argv.join(" ")).toBe("");
  expect(ran.code, `${argv.join(" ")}: ${ran.out}`).toBe(0);
  return ran.json() as T;
}

beforeAll(async () => {
  place = new Place();
  await place.network();
  for (const who of ["ada", "bo", "cy"] as const) {
    dirs[who] = place.dir(who);
    const made = await place.oip([
      "init",
      "--local",
      "--kind",
      "human",
      "--dir",
      dirs[who],
      "--json",
    ]);
    expect(made.code).toBe(0);
    minds[who] = (made.json() as { mind: string }).mind;
  }
});
afterAll(async () => {
  await place.close();
});

describe("a collective, through the command", () => {
  let event = "";
  let club = "";

  it(`${clause("L1 9.2")} is founded by its members, each of whom signs its first event`, async () => {
    const out = join(place.home, "genesis.json");
    const founded = await place.oip([
      "collective",
      "create",
      "--member",
      minds.bo,
      "--member",
      minds.cy,
      "--threshold",
      "2",
      "--out",
      out,
      "--send-to",
      minds.bo,
      "--send-to",
      minds.cy,
      "--dir",
      dirs.ada,
    ]);
    expect(founded.err).toBe("");
    expect(founded.code).toBe(0);
    expect(place.plain(founded.out)).toMatchSnapshot();
    [, event = ""] = /event {6}(bciq[a-z2-7]{52})/u.exec(founded.out) ?? [];
    [, club = ""] = /will be (did:oip:[a-z2-7]+)/u.exec(founded.out) ?? [];
    expect(club).toBe(`did:oip:${event}`);
    expect(JSON.parse(readFileSync(out, "utf8"))).toMatchObject({
      type: "Genesis",
      kind: "collective",
      controller: { members: [minds.ada, minds.bo, minds.cy], threshold: 2 },
    });
    // It does not exist yet: one founder of three has signed.
    const early = await place.oip(["collective", "sign", event, "--publish", "--dir", dirs.ada]);
    expect(early.code).toBe(1);
    expect(early.err).toContain("the log does not verify");
    expect((await place.oip(["resolve", club, "--local"])).code).toBe(1);
  });

  it(`${clause("L1 9.4")} each member signs with a key of its own, and the last publishes the log`, async () => {
    // Bo reads his mailbox, signs, and sends his copy on to Cy.
    expect((await as<{ new: number }>("bo", "inbox")).new).toBe(1);
    const second = await as<{ signed: string[]; waiting: string[] }>(
      "bo",
      "collective",
      "sign",
      event,
      "--send-to",
      minds.cy,
    );
    expect(second).toMatchObject({ signed: [minds.ada, minds.bo], waiting: [minds.cy] });
    // Cy has two copies by now, Ada's and Bo's: their proofs are put together with hers.
    expect((await as<{ new: number }>("cy", "inbox")).new).toBe(2);
    const last = await place.oip(["collective", "sign", event, "--publish", "--dir", dirs.cy]);
    expect(last.err).toBe("");
    expect(last.code).toBe(0);
    expect(place.plain(last.out)).toMatchSnapshot();
    expect(last.out).toContain(`The collective is ${club}\n`);
    // Anyone resolves it now.
    const resolved = await place.oip(["resolve", club, "--local", "--json"]);
    expect(resolved.json()).toMatchObject({ mind: club, kind: "collective", seq: 0 });
  });

  it(`${clause("L1 9.5")} a record in its name is the collective's once enough of its members have signed`, async () => {
    const intent = await as<{ id: string; record: object }>(
      "ada",
      "intent",
      "--want",
      "A hall for the spring meeting.",
      "--for",
      club,
      "--send-to",
      minds.bo,
    );
    expect(intent.record).toMatchObject({ type: "Intent", author: club });
    // One member's signature is one member's.
    expect(await as("ada", "status", intent.id)).toMatchObject({
      parties: [{ mind: club, role: "author", counts: false }],
    });
    await as("bo", "inbox");
    const out = join(place.home, "intent.json");
    const both = await place.oip(["collective", "sign", intent.id, "--out", out, "--dir", dirs.bo]);
    expect(both.err).toBe("");
    expect(place.plain(both.out)).toMatchSnapshot();
    expect(both.out).toContain("  counts     yes: enough of its members have signed\n");
    const signed = JSON.parse(readFileSync(out, "utf8")) as { proof: unknown[] };
    expect(signed.proof).toHaveLength(2);
    // From the file, anyone sees the same.
    expect(await as("cy", "status", out)).toMatchObject({
      id: intent.id,
      status: "open",
      parties: [{ mind: club, role: "author", counts: true }],
    });
  });

  it("says what is wrong with what it was given, and signs nothing", async () => {
    const nobody = `bciq${"a".repeat(52)}`;
    for (const [argv, said] of [
      [["collective", "create"], "a collective has members besides this mind"],
      [
        ["collective", "create", "--member", minds.bo],
        "a collective acts by a number of its members",
      ],
      [
        ["collective", "create", "--member", minds.bo, "--threshold", "two"],
        "a collective acts by a number",
      ],
      [
        ["collective", "create", "more", "--member", minds.bo, "--threshold", "2"],
        "collective create takes options alone",
      ],
      [
        [
          "collective",
          "create",
          "--member",
          minds.bo,
          "--threshold",
          "2",
          "--host",
          "http://plain.example",
        ],
        "is no HTTPS origin",
      ],
      [["collective", "sign"], "collective sign takes one event or record"],
      [["collective", "sign", nobody, nobody], "collective sign takes one event or record"],
      [["collective", "sign", nobody], `the mind holds no record ${nobody}`],
    ] as const) {
      const refused = await place.oip([...argv, "--dir", dirs.ada]);
      expect(refused.code, argv.join(" ")).toBe(2);
      expect(refused.err, argv.join(" ")).toContain(said);
    }
    // A threshold that is no majority makes no collective: the client refuses it, and nothing is written.
    const out = join(place.home, "never.json");
    const minority = await place.oip([
      "collective",
      "create",
      "--member",
      minds.bo,
      "--member",
      minds.cy,
      "--threshold",
      "1",
      "--out",
      out,
      "--dir",
      dirs.ada,
    ]);
    expect(minority.code).toBe(1);
    expect(existsSync(out)).toBe(false);
    // What is no record is not signed.
    writeFileSync(out, JSON.stringify({ type: "Genesis", kind: "collective" }));
    expect((await place.oip(["collective", "sign", out, "--dir", dirs.ada])).code).toBe(1);
  });
});
