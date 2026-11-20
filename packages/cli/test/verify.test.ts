// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Place } from "./harness.ts";

let place: Place;
const dirs = { amina: "", lexis: "", agent: "" };
const minds = { amina: "", lexis: "", agent: "" };
type Who = keyof typeof dirs;

async function as<T = Record<string, unknown>>(who: Who, ...argv: string[]): Promise<T> {
  const ran = await place.oip([...argv, "--dir", dirs[who], "--json"]);
  expect(ran.err, argv.join(" ")).toBe("");
  expect(ran.code, `${argv.join(" ")}: ${ran.out}`).toBe(0);
  return ran.json() as T;
}
interface Signed {
  readonly id: string;
  readonly record: Record<string, unknown>;
}
/** What `oip verify --json` says. */
interface Verified {
  readonly subject: string;
  readonly verified: boolean;
  readonly failed: boolean;
  readonly verdicts: { verdict: string; what: string; clause: string }[];
}
/** Verifies something, and gives what was said for a program, with how the run ended. */
async function verify(...argv: string[]): Promise<Verified & { code: number }> {
  const ran = await place.oip(["verify", ...argv, "--json"]);
  expect(ran.err, argv.join(" ")).toBe("");
  return { ...(ran.json() as Verified), code: ran.code };
}
/** Writes a value to a file of this place, and gives the file's path. */
function file(name: string, value: unknown): string {
  const path = join(place.home, name);
  writeFileSync(path, JSON.stringify(value));
  return path;
}

let intent: Signed;
let mandate: Signed;
let deal: Signed;

beforeAll(async () => {
  place = new Place();
  await place.network();
  for (const [who, kind] of [
    ["amina", "human"],
    ["lexis", "institution"],
    ["agent", "agent"],
  ] as const) {
    dirs[who] = place.dir(who);
    const made = await place.oip(["init", "--local", "--kind", kind, "--dir", dirs[who], "--json"]);
    expect(made.code).toBe(0);
    minds[who] = (made.json() as { mind: string }).mind;
  }
  await as("amina", "publish", "profile", "--name", "Amina");
  intent = await as<Signed>("amina", "intent", "--want", "A lease translated into English.");
  mandate = await as<Signed>(
    "lexis",
    "delegate",
    minds.agent,
    "--command",
    "/oip/sign/Commitment",
    "--days",
    "30",
    "--send-to",
    minds.agent,
  );
  await as("agent", "inbox");
  deal = await as<Signed>(
    "agent",
    "commit",
    "--debtor",
    minds.lexis,
    "--creditor",
    minds.amina,
    "--promise",
    "Lexis Ltd will deliver the translation.",
    "--authority",
    mandate.id,
    "--send-to",
    minds.amina,
  );
  await as("amina", "inbox");
}, 60_000);
afterAll(async () => {
  await place.close();
});

describe("oip verify, given a record", () => {
  it(`${clause("core 5.4", "L1 6.1")} says of each proof whose key made it, and that the key was that mind's then`, async () => {
    const path = file("intent.json", intent.record);
    const said = await place.oip(["verify", path, "--local"]);
    expect(said.err).toBe("");
    expect(said.code).toBe(0);
    expect(place.plain(said.out)).toMatchSnapshot();
    expect(said.out).toContain(`Intent ${intent.id}\n`);
    expect(said.out.endsWith("It verifies.\n")).toBe(true);
    const asJson = await verify(path, "--local");
    expect(asJson).toMatchObject({
      subject: `Intent ${intent.id}`,
      verified: true,
      failed: false,
      code: 0,
    });
    expect(asJson.verdicts.map(({ verdict, clause: rests }) => [verdict, rests])).toStrictEqual([
      ["ok", "core 2.1"],
      ["ok", "core 5.4"],
      ["ok", "L1 6.1"],
      ["ok", "L2 7.1"],
    ]);
    // A record the mind of the directory holds is named by its ID, and judged the same.
    expect(await verify(intent.id, "--dir", dirs.amina)).toMatchObject({
      subject: `Intent ${intent.id}`,
      verified: true,
    });
  });

  it(`${clause("core 5.5")} says which proof does not verify, and ends with 1`, async () => {
    const path = file("changed.json", { ...intent.record, want: "A castle." });
    const said = await place.oip(["verify", path, "--local"]);
    expect(said.code).toBe(1);
    expect(said.err).toBe("");
    expect(said.out).toContain("  FAILS      proof 0 does not verify: ");
    expect(said.out.endsWith("It does not verify.\n")).toBe(true);
    const asJson = await verify(path, "--local");
    expect(asJson).toMatchObject({ verified: false, failed: true, code: 1 });
    // What is no record is said to be none, with the clause that says what one is.
    const { type: _type, ...typeless } = intent.record;
    const none = await verify(file("none.json", typeless), "--local");
    expect(none).toMatchObject({ failed: true, code: 1 });
    expect(none.verdicts[0]?.what).toContain("it is no well-formed record");
    expect(none.verdicts.every(({ clause: rests }) => rests !== "")).toBe(true);
  });

  it(`${clause("L1 11.4", "L2 7.1")} says for whom a record counts, and through which delegations`, async () => {
    const said = await place.oip(["verify", deal.id, "--dir", dirs.amina]);
    expect(said.err).toBe("");
    expect(place.plain(said.out)).toMatchSnapshot();
    expect(said.out).toContain(
      `  ok         proof 0 counts for ${minds.lexis} through the delegations it names (L1 11.4)\n`,
    );
    expect(said.out).toContain(`  ok         it counts for ${minds.lexis} (L2 7.1)\n`);
    // Amina has not signed it: that is an answer of no, and nothing is wrong with the record.
    expect(said.out).toContain(`  no         it does not count for ${minds.amina}: `);
    expect(said.code).toBe(0);
    expect(said.out.endsWith("It verifies.\n")).toBe(true);
  });

  it(`${clause("L1 11.5")} says that a delegation was taken back, of what was signed after`, async () => {
    await as("lexis", "revoke", mandate.id, "--send-to", minds.amina);
    await as("amina", "inbox");
    const later = await as<Signed>(
      "agent",
      "commit",
      "--debtor",
      minds.lexis,
      "--creditor",
      minds.amina,
      "--promise",
      "Lexis Ltd will deliver a second translation.",
      "--authority",
      mandate.id,
      "--send-to",
      minds.amina,
    );
    await as("amina", "inbox");
    const after = await verify(later.id, "--dir", dirs.amina);
    expect(after).toMatchObject({ failed: true, code: 1 });
    const refused = after.verdicts.find(({ verdict }) => verdict === "fails");
    expect(refused?.what).toContain(
      `proof 0 does not count for ${minds.lexis} through a delegation`,
    );
    expect(refused?.clause).toBe("L1 11.5");
    // What it signed before still counts, for a mind that held it before the revocation came.
    expect(await verify(deal.id, "--dir", dirs.amina)).toMatchObject({ failed: false, code: 0 });
    // A stranger, who holds no revocation, is told what the record itself shows.
    expect(await verify(file("later.json", later.record), "--local")).toMatchObject({
      failed: false,
    });
  });

  it("asks nobody when told not to, and says what it then could not judge", async () => {
    const path = file("intent.json", intent.record);
    const said = await place.oip(["verify", path, "--offline"]);
    expect(said.code).toBe(0);
    expect(said.out).toContain(
      "  unknown    whose keys those are was not asked: there is no resolver to ask (L1 6.1)\n",
    );
    expect(said.out.endsWith("Nothing fails. Not everything could be judged.\n")).toBe(true);
    // With no mind in the directory and no network named, there is nobody to ask either.
    const nowhere = await verify(path, "--dir", place.dir("nobody"));
    expect(nowhere).toMatchObject({ verified: false, failed: false, code: 0 });
    // A signer nobody serves is said to be unknown, and its proof is not counted.
    const { verdicts } = await verify(path, "--dir", dirs.amina, "--offline");
    expect(verdicts.map(({ verdict }) => verdict)).toStrictEqual(["ok", "ok", "unknown"]);
  });
});

describe("oip verify, given a log, a bundle or a mind", () => {
  let bundle: { log: Record<string, unknown>[]; location: object; participant: object };
  let path = "";

  it(`${clause("L1 4.1")} verifies a bundle a resolver served: its log, and what it carries`, async () => {
    path = join(place.home, "bundle.json");
    await as("amina", "rotate");
    const resolved = await place.oip(["resolve", minds.amina, "--local", "--out", path]);
    expect(resolved.code).toBe(0);
    bundle = JSON.parse(readFileSync(path, "utf8")) as typeof bundle;
    expect(bundle).toMatchObject({ type: "Bundle", mind: minds.amina });
    expect(bundle.log).toHaveLength(2);
    const said = await place.oip(["verify", path, "--local"]);
    expect(said.err).toBe("");
    expect(said.code).toBe(0);
    expect(place.plain(said.out)).toMatchSnapshot();
    expect(said.out).toContain(
      `  ok         the log verifies: 2 events of ${minds.amina} (L1 4.1)\n`,
    );
    expect(said.out).toContain("  ok         the resolvers hold the same log (L1 17.1)\n");
    expect(said.out).toContain("  ok         its participant: it is a well-formed Participant");
  });

  it(`${clause("L1 7.1")} verifies a log as an array of its events, and says how it stands to what the resolvers hold`, async () => {
    expect(await verify(file("log.json", bundle.log), "--local")).toMatchObject({
      subject: minds.amina,
      verified: true,
    });
    // A copy that is behind is no failure: it is the beginning of the same log.
    const behind = await verify(file("behind.json", bundle.log.slice(0, 1)), "--local");
    expect(behind).toMatchObject({ verified: false, failed: false, code: 0 });
    expect(behind.verdicts.at(-1)).toMatchObject({
      verdict: "unknown",
      what: "the resolvers hold 1 event more: this copy is behind",
    });
    // Asked of nobody, the log stands by its own signatures.
    const alone = await verify(file("log.json", bundle.log), "--offline");
    expect(alone.verdicts.map(({ verdict }) => verdict)).toStrictEqual(["ok", "unknown"]);
    // An event that was changed breaks the log, and the clause says where the rule is.
    const [genesis, update] = bundle.log;
    const broken = await verify(file("broken.json", [genesis, { ...update, seq: 5 }]), "--local");
    expect(broken).toMatchObject({ failed: true, code: 1 });
    expect(broken.verdicts[0]?.what).toContain("the log does not verify");
    // One event by itself is judged in its log, and not alone.
    const single = await verify(file("event.json", genesis), "--local");
    expect(single.verdicts.at(-1)).toMatchObject({ verdict: "unknown", clause: "L1 4.1" });
  });

  it(`${clause("L1 17.1")} verifies a mind by its address: each event of its log, as the resolvers serve it`, async () => {
    const said = await place.oip(["verify", minds.amina, "--local"]);
    expect(said.err).toBe("");
    expect(said.code).toBe(0);
    expect(place.plain(said.out)).toMatchSnapshot();
    expect(said.out.endsWith("It verifies.\n")).toBe(true);
    // A mind nobody serves is not found, as it is for `oip resolve`.
    const nobody = await place.oip(["verify", `did:oip:bciq${"a".repeat(52)}`, "--local"]);
    expect(nobody.code).toBe(1);
    expect(nobody.err).toMatch(/^oip: /u);
    // And with nobody to ask, there is nothing to verify it by.
    const offline = await place.oip(["verify", minds.amina, "--offline"]);
    expect(offline.code).toBe(2);
    expect(offline.err).toContain("a mind is verified by what its resolvers serve");
  });

  it("says what is wrong with what it was given", async () => {
    const id = `bciq${"a".repeat(52)}`;
    for (const [argv, said] of [
      [[], "verify takes one thing: a file, the ID of a record, or an address"],
      [["one.json", "two.json"], "verify takes one thing"],
      [[join(place.home, "missing.json")], "there is no such file to read"],
      [[id, "--dir", dirs.amina], `the mind holds no record ${id}`],
      [[id, "--local", "--network", place.dir("no-network")], "no network is running from"],
    ] as const) {
      const refused = await place.oip(["verify", ...argv]);
      expect(refused.code, argv.join(" ")).toBe(2);
      expect(refused.err).toContain(said);
    }
  });
});
