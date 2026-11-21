// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Place } from "./harness.ts";

let place: Place;
/** The cast of the papers' scenario: Amina, Lexis Ltd, and the firm's agent. */
const dirs = { amina: "", lexis: "", agent: "" };
const minds = { amina: "", lexis: "", agent: "" };
type Who = keyof typeof dirs;

/** Runs a command as one of them, and gives what it said for a program. It must not fail. */
async function as<T = Record<string, unknown>>(who: Who, ...argv: string[]): Promise<T> {
  const ran = await place.oip([...argv, "--dir", dirs[who], "--json"]);
  expect(ran.err, argv.join(" ")).toBe("");
  expect(ran.code, `${argv.join(" ")}: ${ran.out}`).toBe(0);
  return ran.json() as T;
}
/** The same, for a person. */
async function shown(who: Who, ...argv: string[]): Promise<string> {
  const ran = await place.oip([...argv, "--dir", dirs[who]]);
  expect(ran.err, argv.join(" ")).toBe("");
  expect(ran.code).toBe(0);
  return ran.out;
}
interface Signed {
  readonly id: string;
  readonly status?: string;
  readonly record: Record<string, unknown>;
  readonly parties?: { mind: string; role: string; counts: boolean }[];
}
const statusOf = async (who: Who, id: string): Promise<string | undefined> =>
  (await as<Signed>(who, "status", id)).status;

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
});
afterAll(async () => {
  await place.close();
});

describe("the scenario of the papers, through the command", () => {
  let mandate = "";
  let wanted = "";
  let deal = "";

  it(`${clause("L1 11.1")} a firm lets its agent commit it, within limits, and gives it the delegation`, async () => {
    const policy = join(place.home, "policy.json");
    writeFileSync(
      policy,
      JSON.stringify([
        ["==", ".terms.price.currency", "USD"],
        ["<=", ".terms.price.amount", "500"],
        ["==", ".terms.price.payee", minds.lexis],
        ["all", ".parties", ["!=", ".mind", minds.agent]],
      ]),
    );
    const said = await place.oip([
      "delegate",
      minds.agent,
      "--command",
      "/oip/sign/Commitment",
      "--days",
      "30",
      "--policy",
      policy,
      "--send-to",
      minds.agent,
      "--dir",
      dirs.lexis,
    ]);
    expect(said.err).toBe("");
    expect(place.plain(said.out)).toMatchSnapshot();
    [mandate = ""] = /bciq[a-z2-7]{52}/u.exec(said.out) ?? [];
    // The agent reads its mailbox, and holds it from then on.
    const arrived = await shown("agent", "inbox");
    expect(arrived).toContain(`  record     Delegation ${mandate}\n`);
    expect(readdirSync(join(dirs.agent, "records"))).toStrictEqual([`${mandate}.json`]);
    expect(await as("agent", "status", mandate)).toMatchObject({
      type: "Delegation",
      parties: [{ mind: minds.lexis, role: "author", counts: true }],
    });
  });

  it(`${clause("L2 4.1")} someone says what she wants`, async () => {
    const said = await place.oip([
      "intent",
      "--want",
      "A Swahili commercial lease translated into English.",
      "--budget",
      "150",
      "--currency",
      "USD",
      "--publish",
      "--send-to",
      minds.agent,
      "--dir",
      dirs.amina,
    ]);
    expect(said.err).toBe("");
    expect(place.plain(said.out)).toMatchSnapshot();
    [wanted = ""] = /bciq[a-z2-7]{52}/u.exec(said.out) ?? [];
    expect(await statusOf("amina", wanted)).toBe("open");
    // Published, it is on her feed and with her indexer, where anyone finds it.
    const found = await as<{ found: { id: string }[] }>("lexis", "find", "--kind", "intent");
    expect(found.found.map(({ id }) => id)).toStrictEqual([wanted]);
  });

  it(`${clause("L2 5.1", "L1 11.4")} the agent writes a Commitment and signs it for the firm, which it binds`, async () => {
    expect(await shown("agent", "inbox")).toContain(`  record     Intent ${wanted}\n`);
    const said = await place.oip([
      "commit",
      "--debtor",
      minds.lexis,
      "--creditor",
      minds.amina,
      "--promise",
      "Lexis Ltd will deliver the translation; Amina will pay 120 USD on delivery.",
      "--price",
      "120",
      "--currency",
      "USD",
      "--resolves",
      wanted,
      "--closes-intent",
      "--authority",
      mandate,
      "--send-to",
      minds.amina,
      "--dir",
      dirs.agent,
    ]);
    expect(said.err).toBe("");
    expect(place.plain(said.out)).toMatchSnapshot();
    [deal = ""] = /bciq[a-z2-7]{52}/u.exec(said.out) ?? [];
    expect(said.out).toContain("  status     proposed\n");
    expect(said.out).toContain(`  debtor     ${minds.lexis}: bound\n`);
    expect(said.out).toContain(`  creditor   ${minds.amina}: not bound\n`);
  });

  it(`${clause("L2 7.3")} she reads it and signs: it is accepted, and her Intent is satisfied`, async () => {
    await shown("amina", "inbox");
    const before = await as<Signed>("amina", "status", deal);
    expect(before).toMatchObject({
      type: "Commitment",
      status: "proposed",
      parties: [
        { mind: minds.lexis, role: "debtor", counts: true },
        { mind: minds.amina, role: "creditor", counts: false },
      ],
    });
    const signed = await as<Signed>(
      "amina",
      "commit",
      deal,
      "--send-to",
      minds.lexis,
      "--send-to",
      minds.agent,
    );
    expect(signed).toMatchObject({
      id: deal,
      status: "accepted",
      parties: [{ counts: true }, { counts: true }],
    });
    expect(await statusOf("amina", wanted)).toBe("satisfied");
    // The record is the same record: only its proofs are more.
    expect((signed.record["proof"] as unknown[]).length).toBe(2);
  });

  it(`${clause("L2 6.1", "L2 8.3")} the firm says it delivered, and she, who is owed it, confirms`, async () => {
    expect(await shown("lexis", "inbox")).toContain(`  record     Commitment ${deal}\n`);
    expect(await statusOf("lexis", deal)).toBe("accepted");
    const delivered = await place.oip([
      "receipt",
      deal,
      "--outcome",
      "fulfilled",
      "--statement",
      "Delivered by packet, on the day.",
      "--send-to",
      minds.amina,
      "--dir",
      dirs.lexis,
    ]);
    expect(delivered.err).toBe("");
    expect(place.plain(delivered.out)).toMatchSnapshot();
    await shown("amina", "inbox");
    const confirmed = await as<Signed>(
      "amina",
      "receipt",
      deal,
      "--outcome",
      "fulfilled",
      "--score",
      "1",
    );
    expect(confirmed.record).toMatchObject({ type: "Receipt", outcome: "fulfilled" });
    expect(await statusOf("amina", deal)).toBe("fulfilled");
    expect(await shown("amina", "status", deal)).toContain("  status     fulfilled\n");
  });

  it(`${clause("L1 11.5", "core 9.4")} the firm takes the delegation back: what its agent signed before stands, and what it signs after does not bind`, async () => {
    const revoked = await place.oip([
      "revoke",
      mandate,
      "--send-to",
      minds.amina,
      "--dir",
      dirs.lexis,
    ]);
    expect(revoked.err).toBe("");
    expect(place.plain(revoked.out)).toMatchSnapshot();
    await shown("amina", "inbox");
    const later = await as<Signed>(
      "agent",
      "commit",
      "--debtor",
      minds.lexis,
      "--creditor",
      minds.amina,
      "--promise",
      "Lexis Ltd will deliver a second translation; Amina will pay 130 USD.",
      "--price",
      "130",
      "--currency",
      "USD",
      "--authority",
      mandate,
      "--send-to",
      minds.amina,
    );
    await shown("amina", "inbox");
    expect(await as<Signed>("amina", "status", later.id)).toMatchObject({
      status: "proposed",
      parties: [
        { mind: minds.lexis, role: "debtor", counts: false },
        { mind: minds.amina, role: "creditor", counts: false },
      ],
    });
    // Each command is a run of its own, and holds its records again: the first Commitment is
    // judged by when it came, before the revocation, in every one of them.
    for (let run = 0; run < 3; run++) {
      expect(await as<Signed>("amina", "status", deal)).toMatchObject({
        status: "fulfilled",
        parties: [{ counts: true }, { counts: true }],
      });
    }
  });

  it(`${clause("L2 4.2")} an Offer is published, found, and taken up`, async () => {
    const offered = await as<Signed>(
      "lexis",
      "offer",
      "--provides",
      "An English translation of a commercial lease.",
      "--summary",
      "Within two days, by a sworn translator.",
      "--price",
      "120",
      "--currency",
      "USD",
      "--quantity",
      "5",
      "--publish",
    );
    expect(offered.status).toBe("open");
    const found = await shown("amina", "find", "--kind", "offer");
    expect(
      place.plain(found).replace(/ranked {5}[0-9.]+ by/gu, "ranked     <score> by"),
    ).toMatchSnapshot();
    expect(found).toContain(`  record     ${offered.id}\n`);
    // What was found is kept, and taken up by its ID: the firm owes, she is owed, on its terms.
    const taken = await as<Signed>(
      "amina",
      "commit",
      "--offer",
      offered.id,
      "--send-to",
      minds.lexis,
    );
    expect(taken.record).toMatchObject({
      type: "Commitment",
      parties: [
        { mind: minds.lexis, role: "debtor", required: true },
        { mind: minds.amina, role: "creditor", required: true },
      ],
      promise: "An English translation of a commercial lease.",
      terms: {
        price: { amount: "120", currency: "USD", payer: minds.amina, payee: minds.lexis },
      },
      resolves: [`${minds.lexis}/${offered.id}`],
    });
    expect(taken.status).toBe("proposed");
    await shown("lexis", "inbox");
    expect(await as<Signed>("lexis", "commit", taken.id)).toMatchObject({ status: "accepted" });
  });
});

describe("the commands of the Mind Web, given what they cannot use", () => {
  it("say what is wrong, and sign nothing", async () => {
    const nobody = `bciq${"a".repeat(52)}`;
    for (const [argv, said] of [
      [["intent"], "an Intent says what is wanted: --want"],
      [["intent", "--want", "x", "--deadline", "soon"], "soon is no time"],
      [["intent", "--want", "x", "--budget", "a lot"], "a lot is no amount"],
      [
        ["intent", "--want", "x", "--currency", "USD"],
        "--currency is what a --budget is counted in",
      ],
      [
        ["intent", "--want", "x", "--audience", "public", "--audience", "did:oip:x"],
        "--audience is public, or the minds it names",
      ],
      [["offer"], "an Offer says what is provided: --provides"],
      [
        ["offer", "--provides", "x", "--price", "5"],
        "a price is an amount and what it is counted in",
      ],
      [["offer", "--provides", "x", "--quantity", "0"], "0 is no number of times"],
      [["offer", "--provides", "x", "--answers", nobody], `the mind holds no record ${nobody}`],
      [["commit"], "a Commitment names who owes, who is owed, and what"],
      [["commit", nobody, nobody], "commit takes one Commitment to sign, or none"],
      [["commit", nobody, "--promise", "x"], "the options that write one do not go with it"],
      [["commit", nobody], `the mind holds no record ${nobody}`],
      [
        ["commit", "--debtor", "me", "--creditor", "me", "--promise", "x", "--price", "5"],
        "a price is an amount and what it is counted in",
      ],
      [["receipt"], "receipt takes one record it is about"],
      [["receipt", nobody], "a Receipt says what became of the record: --outcome"],
      [["receipt", nobody, "--outcome", "fulfilled", "--score", "5"], "5 is no rating"],
      [["status"], "status takes one record"],
      [["status", nobody], `the mind holds no record ${nobody}`],
      [["delegate"], "delegate takes the address of the one mind it grants"],
      [["delegate", "did:oip:x"], "a delegation says what the delegate may do: --command"],
      [
        ["delegate", "did:oip:x", "--command", "/oip/send"],
        "a delegation ends: say when with --days, or with --expires",
      ],
      [
        [
          "delegate",
          "did:oip:x",
          "--command",
          "/oip/send",
          "--days",
          "30",
          "--expires",
          "2031-01-01T00:00:00Z",
        ],
        "a delegation ends",
      ],
      [
        ["delegate", "did:oip:x", "--command", "/oip/send", "--days", "99999"],
        "99999 is no number of days",
      ],
      [["revoke"], "revoke takes one delegation"],
      [["revoke", nobody], `the mind holds no record ${nobody}`],
    ] as const) {
      const refused = await place.oip([...argv, "--dir", dirs.amina]);
      expect(refused.code, argv.join(" ")).toBe(2);
      expect(refused.err, argv.join(" ")).toContain(said);
      expect(refused.out).toBe("");
    }
  });

  it("leave to the client what makes no record, with the code of the problem", async () => {
    for (const argv of [
      ["offer", "--provides", "x", "--capability", "x".repeat(200)],
      ["commit", "--debtor", "did:oip:nobody", "--creditor", "me", "--promise", "x"],
      ["delegate", "did:oip:nobody", "--command", "/oip/send", "--days", "1"],
      ["delegate", minds.agent, "--command", "not a command", "--days", "1"],
    ]) {
      const refused = await place.oip([...argv, "--dir", dirs.amina, "--json"]);
      expect(refused.code, argv.join(" ")).toBe(1);
      expect(refused.json()).toMatchObject({ error: { code: "invalid-record" } });
    }
  });

  it("take a record from a file as well as by its ID, and a wrong one for neither", async () => {
    const intent = await as<Signed>("amina", "intent", "--want", "A hall for the spring meeting.");
    const file = join(place.home, "intent.json");
    writeFileSync(file, JSON.stringify(intent.record));
    expect(await as<Signed>("lexis", "status", file)).toMatchObject({
      id: intent.id,
      type: "Intent",
      status: "open",
      parties: [{ mind: minds.amina, role: "author", counts: true }],
    });
    // An Intent is no Commitment to sign, no delegation to act by or to revoke, and no Offer to take up.
    for (const [argv, said] of [
      [["commit", file], "is no Commitment"],
      [["commit", "--offer", file], "is no Offer"],
      [["intent", "--want", "x", "--authority", file], "is no delegation"],
      [["intent", "--want", "x", "--charter", file], "is no charter"],
      [["revoke", file], "is no delegation"],
    ] as const) {
      const refused = await place.oip([...argv, "--dir", dirs.lexis]);
      expect(refused.code, argv.join(" ")).toBe(2);
      expect(refused.err).toContain(said);
    }
  });
});
