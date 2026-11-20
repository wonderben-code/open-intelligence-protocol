// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** What seldom happens to a mind, and what the commands say when it does. */

import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { Finding } from "@oip/client";
import { Home } from "@oip/local";
import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { findingLines } from "../src/commands/find.ts";
import { makeMind } from "../src/commands/init.ts";
import { LOCAL, startNetwork } from "../src/index.ts";
import { PASSPHRASE, Place } from "./harness.ts";

const BACKUP_PASSPHRASE = "kept apart, in another place";
const env = { OIP_PASSPHRASE: PASSPHRASE, OIP_BACKUP_PASSPHRASE: BACKUP_PASSPHRASE };

let place: Place;
beforeAll(async () => {
  place = new Place();
  await place.network();
});
afterAll(async () => {
  await place.close();
});

/** Makes a mind on the local network, and gives its directory and its address. */
async function made(name: string, ...more: string[]): Promise<{ dir: string; mind: string }> {
  const dir = place.dir(name);
  const ran = await place.oip(["init", "--local", "--dir", dir, "--json", ...more]);
  expect(ran.code, ran.out + ran.err).toBe(0);
  return { dir, mind: (ran.json() as { mind: string }).mind };
}
async function as<T = Record<string, unknown>>(dir: string, ...argv: string[]): Promise<T> {
  const ran = await place.oip([...argv, "--dir", dir, "--json"]);
  expect(ran.code, `${argv.join(" ")}: ${ran.out}${ran.err}`).toBe(0);
  return ran.json() as T;
}
interface Looked {
  readonly failed: boolean;
  readonly checks: { state: string; what: string; advice?: string }[];
}
const whats = (looked: Looked, state: string): string[] =>
  looked.checks.filter((check) => check.state === state).map(({ what }) => what);
/** A configuration, changed where it is kept. */
function reconfigure(dir: string, change: (config: Record<string, unknown>) => object): void {
  const file = join(dir, "config.json");
  const config = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
  writeFileSync(file, JSON.stringify(change(config)));
}
const file = (name: string, value: unknown): string => {
  const path = join(place.home, name);
  writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value));
  return path;
};

describe("a mind that names no host", () => {
  it("signs and reads, takes no packets, and has no feed", async () => {
    const dir = place.dir("hostless");
    const said = await place.oip(["init", "--local", "--no-host", "--dir", dir]);
    expect(said.code).toBe(0);
    expect(said.out).toContain("It names no host yet, so it takes no packets.\n");
    const both = await place.oip(["init", "--local", "--no-host", "--host", LOCAL.host]);
    expect(both.code).toBe(2);
    expect(both.err).toContain("--no-host and --host say opposite things");
    const looked = await as<Looked>(dir, "doctor");
    expect(whats(looked, "warn")).toContain(
      "the mind names no host: it takes no packets, and has no feed",
    );
    // It delegates and revokes all the same: the revocation is its own to give out.
    const other = await made("delegate-of-hostless");
    const mandate = await as<{ id: string }>(
      dir,
      "delegate",
      other.mind,
      "--command",
      "/oip/sign/Offer",
      "--days",
      "1",
      "--not-before",
      "2026-01-01T00:00:00Z",
    );
    const revoked = await place.oip(["revoke", mandate.id, "--dir", dir]);
    expect(revoked.code).toBe(0);
    expect(revoked.out).toContain(
      "  feed       the mind has no host: give the revocation out yourself\n",
    );
    const feedless = await place.oip(["publish", "record", file("m.json", {}), "--dir", dir]);
    expect(feedless.code).toBe(1);
  });
});

describe("oip doctor, where something is amiss", () => {
  it("says that a mind was never published, or that its keys cannot be read", async () => {
    const dir = place.dir("unpublished");
    await place.oip(["init", "--dir", dir, "--resolver", "https://resolver.invalid"]);
    const unpublished = await place.oip(["doctor", "--dir", dir, "--json"]);
    expect(unpublished.code).toBe(1);
    expect(whats(unpublished.json() as Looked, "fails")).toStrictEqual([
      "the mind was never published",
    ]);
    // Its keys are backed up and restored like any other's: they are of no mind yet.
    const backup = join(place.home, "unpublished.backup");
    expect((await place.oip(["keys", "backup", backup, "--dir", dir], { env })).code).toBe(0);
    const restored = await place.oip(
      ["keys", "restore", backup, "--local", "--dir", place.dir("unpublished-too")],
      { env },
    );
    expect(restored.out).toContain("They are of a mind that was never published");
    // Keys that are not what a keystore wrote are not read.
    const broken = place.dir("broken");
    mkdirSync(join(broken, "keys"), { recursive: true });
    writeFileSync(join(broken, "config.json"), readFileSync(join(dir, "config.json")));
    writeFileSync(join(broken, "keys", "meta"), "not a keystore");
    const unread = await place.oip(["doctor", "--dir", broken, "--json"]);
    expect(unread.code).toBe(1);
    expect(whats(unread.json() as Looked, "fails")[0]).toContain("cannot be read");
  });

  it("says which services do not answer, and what waits for them", async () => {
    const { dir } = await made("doc");
    // A packet for a mind nobody knows waits to be sent again.
    await as(dir, "send", `did:oip:bciq${"a".repeat(52)}`, "--text", "Are you there?");
    // An indexer that is not there, besides the one that is.
    reconfigure(dir, (config) => ({
      ...config,
      indexers: [...(config["indexers"] as string[]), "https://indexer.invalid"],
    }));
    const looked = await as<Looked>(dir, "doctor");
    expect(whats(looked, "warn")).toStrictEqual([
      "no backup holds the keys as they are now (control, operational, invocation, agreement)",
      "the mind has no profile: nobody finds it by what it can do",
      "https://indexer.invalid, an indexer, does not answer",
      "1 packet sent from here did not arrive yet: each is kept, to be sent again",
    ]);
    const wanted = await as<{ record: object }>(dir, "intent", "--want", "A hall.");
    // With no indexer at all there is nobody for `oip find` to ask.
    reconfigure(dir, (config) => ({ ...config, indexers: [] }));
    expect((await place.oip(["show", "--dir", dir])).out).toContain("  indexers   none\n");
    expect(whats(await as<Looked>(dir, "doctor"), "warn")).toContain(
      "the mind names no indexer: `oip find` has nobody to ask",
    );
    // Its services reached as themselves, and not on this machine: nobody is there.
    reconfigure(dir, ({ network: _network, ...config }) => config);
    const alone = await place.oip(["doctor", "--dir", dir, "--json"]);
    expect(alone.code).toBe(1);
    const said = alone.json() as Looked;
    expect(whats(said, "warn")).toContain(
      "the mind trusts one resolver: a single resolver that serves a forked log is not found out",
    );
    expect(whats(said, "fails")[0]).toMatch(/^no resolver serves the mind's log \(/u);
    // A record is then verified as far as it can be: nobody answers for its signer's log.
    const intent = await place.oip([
      "verify",
      file("unreached.json", wanted.record),
      "--dir",
      dir,
      "--json",
    ]);
    const { verdicts } = intent.json() as { verdicts: { verdict: string; what: string }[] };
    expect(verdicts[2]).toMatchObject({ verdict: "unknown" });
    expect(verdicts[2]?.what).toMatch(
      /could not be had from the resolvers \((unreachable|timeout)\)$/u,
    );
  });

  it("finds nothing to see to where all is well, whatever seals the keys", async () => {
    const well = await made("well");
    await as(well.dir, "publish", "profile", "--name", "Well");
    expect(
      (
        await place.oip(["keys", "backup", join(place.home, "well.backup"), "--dir", well.dir], {
          env,
        })
      ).code,
    ).toBe(0);
    const said = await place.oip(["doctor", "--dir", well.dir]);
    expect(said.code).toBe(0);
    expect(said.out.endsWith("All is well.\n")).toBe(true);
    expect(said.out).toContain("  ok         its profile is published: Well\n");
    expect(await as(well.dir, "doctor")).toMatchObject({ well: true, failed: false });
    // A mind whose keys the machine's keychain seals, at a host that is not there besides the
    // one that is, with a second resolver that does not answer.
    const dir = place.dir("keychained");
    const init = await place.oip(
      [
        "init",
        "--local",
        "--keychain",
        "--host",
        LOCAL.host,
        "--host",
        "https://host.invalid",
        "--dir",
        dir,
      ],
      { env: {} },
    );
    expect(init.code, init.err).toBe(0);
    expect(init.out).toContain("sealed with a key in this machine's keychain.\n");
    reconfigure(dir, (config) => ({
      ...config,
      resolvers: [...(config["resolvers"] as string[]), "https://resolver.invalid"],
    }));
    const looked = await place.oip(["doctor", "--dir", dir], { env: {} });
    expect(looked.code).toBe(0);
    expect(place.plain(looked.out)).toContain(
      "  ok         the keys are in <home>/keychained/keys, sealed with a key in this machine's keychain\n",
    );
    expect(looked.out).toMatch(
      / {2}warn {7}https:\/\/resolver\.invalid did not serve the mind's log \(/u,
    );
    expect(looked.out).toContain(
      "  warn       https://host.invalid, a host of the mind, does not answer\n",
    );
    // It signs with no passphrase asked for: the keychain opens its keys.
    expect((await place.oip(["rotate", "--dir", dir], { env: {} })).code).toBe(0);
  });

  it(`${clause("L1 3.10", "L1 15.1")} says that a mind is retired, and that what it published is out of date`, async () => {
    const { dir } = await made("old");
    const hours = 3n * 3_600_000_000_000n;
    const late = await place.oip(["doctor", "--dir", dir, "--json"], {
      clock: { now: () => BigInt(Date.now()) * 1_000_000n + hours },
    });
    expect(whats(late.json() as Looked, "warn")).toContain(
      "the mind's location record is out of date: senders may not rely on it",
    );
    // No command retires a mind: it is done here as a program would, with the client.
    const opened = await place.mind(dir);
    await opened.mind.retire({ control: opened.lock, reason: "Replaced." });
    opened.mind.close();
    expect(whats(await as<Looked>(dir, "doctor"), "warn")).toContain(
      "the mind is retired: it signs nothing more",
    );
    expect((await place.oip(["show", "--dir", dir])).out).toContain(
      "  log        2 events, and retired\n",
    );
    const verified = await place.oip([
      "verify",
      (await as<{ mind: string }>(dir, "show")).mind,
      "--local",
    ]);
    expect(verified.out).toContain(
      "the mind is retired: its keys sign nothing from then on (L1 3.10)",
    );
    const bundle = join(place.home, "old.json");
    await place.oip(["resolve", verified.out.split("\n")[0] ?? "", "--local", "--out", bundle]);
    expect((await place.oip(["verify", bundle, "--local"])).out).toMatch(
      /the log verifies: 2 events of did:oip:[a-z2-7]+, which is retired \(L1 4\.1\)/u,
    );
    // Its backup holds no key it signs with now, and no key that could change it.
    const backup = join(place.home, "old.backup");
    expect((await place.oip(["keys", "backup", backup, "--dir", dir], { env })).code).toBe(0);
    const restored = await place.oip(
      ["keys", "restore", backup, "--local", "--dir", place.dir("old-restored"), "--json"],
      { env },
    );
    expect(restored.json()).toMatchObject({ signs: false, identity: false });
  });
});

describe("oip verify, of what another network holds", () => {
  it(`${clause("core 9.4")} says that a signer's log could not be had, and counts nothing by it`, async () => {
    const elsewhere = new Place();
    await elsewhere.network();
    const dir = elsewhere.dir("eve");
    expect((await elsewhere.oip(["init", "--local", "--dir", dir])).code).toBe(0);
    const intent = await elsewhere.oip(["intent", "--want", "A castle.", "--dir", dir, "--json"]);
    const { record } = intent.json() as { record: { author: string } };
    const bundle = join(place.home, "eve.json");
    await elsewhere.oip(["resolve", record.author, "--local", "--out", bundle]);
    // A mind of this place, asked about at that network: its resolver answers, and knows nothing of it.
    const stray = await made("stray");
    const before = readFileSync(join(stray.dir, "config.json"), "utf8");
    reconfigure(stray.dir, (config) => ({ ...config, network: join(elsewhere.home, ".oip-demo") }));
    const lost = await place.oip(["doctor", "--dir", stray.dir, "--json"]);
    expect(lost.code).toBe(1);
    expect(whats(lost.json() as Looked, "fails")).toStrictEqual([
      "no resolver serves the mind's log (not-found)",
    ]);
    writeFileSync(join(stray.dir, "config.json"), before);
    await elsewhere.close();
    // Here, no resolver knows her.
    const said = await place.oip(["verify", file("castle.json", record), "--local", "--json"]);
    const { verdicts, failed } = said.json() as {
      failed: boolean;
      verdicts: { verdict: string; what: string }[];
    };
    // Nothing is known against the record: there is nobody here to say whose key signed it.
    expect(failed).toBe(false);
    expect(said.code).toBe(0);
    expect(verdicts.map(({ verdict }) => verdict)).toStrictEqual([
      "ok",
      "ok",
      "unknown",
      "unknown",
      "unknown",
    ]);
    expect(verdicts[2]?.what).toBe(
      `the log of ${record.author} could not be had from the resolvers (not-found)`,
    );
    expect(verdicts[3]?.what).toBe(
      `proof 0 cannot be judged: it names a key of ${record.author}, whose log was not had`,
    );
    // Her log verifies by itself, and the resolvers here do not serve it.
    const log = await place.oip(["verify", bundle, "--local", "--json"]);
    const judged = log.json() as { failed: boolean; verdicts: { verdict: string; what: string }[] };
    expect(judged.failed).toBe(false);
    expect(judged.verdicts[0]?.verdict).toBe("ok");
    expect(judged.verdicts[1]).toMatchObject({
      verdict: "unknown",
      what: "the resolvers do not serve the mind (not-found)",
    });
  });
});

describe("the records of the Mind Web, in their less usual forms", () => {
  it(`${clause("L1 11.4")} a delegation is passed on, and what is signed by the chain counts for its root`, async () => {
    const firm = await made("firm");
    const agent = await made("agent");
    const junior = await made("junior");
    const mandate = await as<{ id: string }>(
      firm.dir,
      "delegate",
      agent.mind,
      "--command",
      "/oip/sign/Offer",
      "--days",
      "30",
      "--send-to",
      agent.mind,
    );
    await as(agent.dir, "inbox");
    const policy = file("junior-policy.json", [["<=", ".terms.price.amount", "100"]]);
    const passed = await as<{ id: string; record: { subject: string } }>(
      agent.dir,
      "delegate",
      junior.mind,
      "--command",
      "/oip/sign/Offer",
      "--days",
      "7",
      "--policy",
      policy,
      "--authority",
      mandate.id,
      "--send-to",
      junior.mind,
    );
    expect(passed.record.subject).toBe(firm.mind);
    await as(junior.dir, "inbox");
    // The junior holds the last link. The first came to the agent, and is given by a file.
    const kept = JSON.parse(
      readFileSync(join(firm.dir, "records", `${mandate.id}.json`), "utf8"),
    ) as { record: object };
    const root = file("root.json", kept.record);
    const offer = await as<{ id: string; record: { author: string } }>(
      junior.dir,
      "offer",
      "--provides",
      "A translation.",
      "--price",
      "80",
      "--currency",
      "USD",
      "--delivery-by",
      "2031-01-31T12:00:00Z",
      "--condition",
      "Paid on delivery.",
      "--capability",
      "translate",
      "--audience",
      "public",
      "--expires",
      "2031-06-30T00:00:00Z",
      "--authority",
      root,
      "--authority",
      passed.id,
    );
    // It is written in the firm's name, and counts for the firm.
    expect(offer.record.author).toBe(firm.mind);
    const judged = await place.oip(["verify", offer.id, "--dir", junior.dir]);
    expect(judged.code).toBe(0);
    expect(judged.out).toContain(`  ok         it counts for ${firm.mind} (L2 7.1)\n`);
    // What makes no policy, and what names two authorities, is said before anything is signed.
    for (const [argv, said] of [
      [
        [
          "delegate",
          junior.mind,
          "--command",
          "/oip/send",
          "--days",
          "1",
          "--policy",
          file("p.json", { a: 1 }),
        ],
        "holds no JSON array: a policy is one",
      ],
      [
        [
          "delegate",
          junior.mind,
          "--command",
          "/oip/send",
          "--days",
          "1",
          "--policy",
          file("q.json", [["maybe", ".a", 1]]),
        ],
        "is no policy: ",
      ],
      [["offer", "--provides", "x", "--authority", root, "--charter", root], "is no charter"],
      [
        [
          "intent",
          "--want",
          "x",
          "--audience",
          junior.mind,
          "--audience",
          firm.mind,
          "--require",
          "sworn",
          "--deadline",
          "soon",
        ],
        "soon is no time",
      ],
    ] as const) {
      const refused = await place.oip([...argv, "--dir", agent.dir]);
      expect(refused.code, argv.join(" ")).toBe(2);
      expect(refused.err).toContain(said);
    }
    // An Intent for two minds, with what an answer must meet.
    const wanted = await as<{ record: object }>(
      agent.dir,
      "intent",
      "--want",
      "A sworn translation.",
      "--audience",
      junior.mind,
      "--audience",
      firm.mind,
      "--require",
      "sworn",
      "--deadline",
      "2031-01-31T12:00:00Z",
      "--expires",
      "2031-02-28T00:00:00Z",
    );
    expect(wanted.record).toMatchObject({
      audience: [junior.mind, firm.mind],
      constraints: { requires: ["sworn"], deadline: "2031-01-31T12:00:00Z" },
    });
    // A Commitment with a witness, who is no party that must sign.
    const witnessed = await as<{ record: { parties: object[] }; status: string }>(
      agent.dir,
      "commit",
      "--debtor",
      "me",
      "--creditor",
      junior.mind,
      "--witness",
      firm.mind,
      "--promise",
      "The agent will train the junior.",
      "--deadline",
      "2031-01-31T12:00:00Z",
    );
    expect(witnessed.record.parties).toStrictEqual([
      { mind: agent.mind, role: "debtor", required: true },
      { mind: junior.mind, role: "creditor", required: true },
      { mind: firm.mind, role: "witness" },
    ]);
  });

  it(`${clause("L1 9.3")} a collective's log is extended by its members, and published with the event`, async () => {
    const ada = await made("c-ada");
    const bo = await made("c-bo");
    const founded = await as<{ id: string; collective: string }>(
      ada.dir,
      "collective",
      "create",
      "--member",
      bo.mind,
      "--threshold",
      "2",
      "--host",
      LOCAL.host,
      "--send-to",
      bo.mind,
    );
    await as(bo.dir, "inbox");
    await as(bo.dir, "collective", "sign", founded.id, "--publish");
    // What one member signs in its name is not yet the collective's, however often she signs.
    const alone = await as<{ id: string }>(
      ada.dir,
      "intent",
      "--want",
      "A hall.",
      "--for",
      founded.collective,
    );
    const still = await place.oip(["collective", "sign", alone.id, "--dir", ada.dir]);
    expect(still.out).toContain("  counts     not yet: more of its members must sign\n");
    // Its log is verified with its members' logs, which the resolvers serve.
    const club = join(place.home, "club.json");
    await place.oip(["resolve", founded.collective, "--local", "--out", club]);
    const verified = await place.oip(["verify", club, "--local"]);
    expect(verified.code).toBe(0);
    expect(verified.out).toContain(`the log verifies: 1 event of ${founded.collective} (L1 4.1)`);
    // Asked of nobody, a collective's log cannot be judged: its members' logs are not at hand.
    expect((await place.oip(["verify", club, "--offline"])).code).toBe(1);
    // No command drafts a change to a collective: a member does, as a program would.
    const opened = await place.mind(ada.dir);
    const update = await opened.mind.changeCollective(
      founded.collective,
      { alsoKnownAs: ["https://club.example"] },
      { invocation: opened.lock },
    );
    opened.mind.close();
    const drafted = file("update.json", update);
    const signed = await place.oip(["collective", "sign", drafted, "--publish", "--dir", bo.dir]);
    expect(signed.err).toBe("");
    expect(signed.code).toBe(0);
    expect(signed.out).toContain(
      `The collective is ${founded.collective}\n  log        2 events\n`,
    );
    // Its other name is listed, and not shown to be its own: nothing there points back.
    const named = await place.oip(["resolve", founded.collective, "--aliases", "--local"]);
    expect(named.out).toContain("  names      https://club.example\n");
    expect(named.out).toMatch(/ {2}name {7}https:\/\/club\.example: not shown to be \(/u);
  });

  it(`${clause("L1 18.5")} a packet for whoever can do a thing is forwarded by the indexer of the network`, async () => {
    const ada = await made("b-ada");
    const bob = await made("b-bob");
    await as(
      bob.dir,
      "publish",
      "profile",
      "--name",
      "Bob",
      "--capability",
      "bake=Bakes bread",
      "--tag",
      "domain:baking",
    );
    const opened = await place.mind(ada.dir);
    const sent = await opened.mind.send({
      to: { query: { tags: ["domain:baking"] } },
      verb: "request",
      content: { mediaType: "text/plain", body: "Forty loaves by Friday?" },
    });
    opened.mind.close();
    expect(sent.deliveries).toMatchObject([{ to: LOCAL.indexer, stored: true }]);
    const arrived = await place.oip(["inbox", "--dir", bob.dir]);
    expect(arrived.out).toContain("    Forty loaves by Friday?\n");
    expect(arrived.out).toMatch(/ {2}through {4}did:oip:/u);
  });
});

describe("what a mind's log says of its own past", () => {
  it(`${clause("L1 8.2")} a parent nobody can resolve is a parent by the child's word alone`, async () => {
    const dir = place.dir("orphan");
    const context = place.context(dir);
    const config = {
      resolvers: [LOCAL.resolver],
      indexers: [],
      lock: "passphrase" as const,
      network: join(place.home, ".oip-demo"),
    };
    const id = `bciqa${"b".repeat(50)}a`;
    const parent = `did:oip:${id}`;
    const { mind } = await makeMind(context, new Home(dir), config, {
      kind: "agent",
      homes: [],
      parents: [{ mind: parent, at: `0-${id}` }],
    });
    mind.close();
    const shown = await place.oip(["show", "--dir", dir]);
    expect(shown.code).toBe(0);
    expect(shown.out).toContain(`  parent     ${parent} (by its own word alone)\n`);
  });

  it(`${clause("L1 6.2")} a key that was stolen signs nothing that counts from the time it was`, async () => {
    const { dir, mind } = await made("robbed");
    const intent = await as<{ record: object }>(dir, "intent", "--want", "A castle.");
    const path = file("robbed.json", intent.record);
    expect((await place.oip(["verify", path, "--local"])).code).toBe(0);
    const { keys } = await as<{ keys: string[] }>(dir, "show");
    await as(dir, "add-key");
    await as(dir, "revoke-key", keys[0] ?? "", "--compromised-since", "2026-01-01T00:00:00Z");
    const said = await place.oip(["verify", path, "--local", "--json"]);
    expect(said.code).toBe(1);
    const { verdicts } = said.json() as {
      verdicts: { verdict: string; what: string; clause: string }[];
    };
    const refused = verdicts.find(({ verdict }) => verdict === "fails");
    expect(refused?.what).toContain(`proof 0 is not by a valid key of ${mind}`);
    expect(refused?.clause).toMatch(/^(L1 6\.[0-9]|core 9\.[0-9])$/u);
    expect(verdicts.at(-1)).toMatchObject({ verdict: "no" });
  });
});

describe("what a query found, as it is shown", () => {
  it("says what was named and refused, and which indexers did not answer", () => {
    const finding: Finding = {
      found: [
        {
          mind: "did:oip:x",
          id: "bciqone",
          record: { type: "Intent", want: "A hall." } as never,
          current: false,
          by: [{ indexer: "https://i.example", score: "0.5", why: "it matches" }],
        },
        {
          mind: "did:oip:y",
          id: "bciqtwo",
          record: { type: "Participant", name: "Ada" } as never,
          current: true,
          by: [],
        },
        {
          mind: "did:oip:z",
          id: "bciqthree",
          record: { type: "Offer", provides: "Bread.", terms: { summary: "Daily." } } as never,
          current: true,
          by: [],
        },
      ],
      refused: [
        {
          indexer: "https://i.example",
          mind: "did:oip:w",
          record: "bciqfour",
          failure: "invalid-proof",
        },
      ],
      sources: [
        { indexer: "https://i.example", results: 4 },
        { indexer: "https://j.example", results: undefined, failure: "unreachable" },
        { indexer: "https://k.example", results: undefined },
      ],
    };
    expect(findingLines(finding)).toStrictEqual([
      "3 found. Indexers that answered: 1 of 3.",
      "1. did:oip:x",
      "  intent     A hall. (replaced since)",
      "  record     bciqone",
      "  ranked     0.5 by https://i.example: it matches",
      "2. did:oip:y",
      "  profile    Ada",
      "  record     bciqtwo",
      "3. did:oip:z",
      "  offer      Bread.",
      "  record     bciqthree",
      "  refused    bciqfour of did:oip:w, named by https://i.example (invalid-proof)",
      "  no answer  https://j.example (unreachable)",
      "  no answer  https://k.example (it did not say why)",
    ]);
  });
});

describe("the network of this machine", () => {
  it("stops what it started where it cannot start the rest, and starts whole the next time", async () => {
    const directory = join(place.home, "bad-network");
    mkdirSync(join(directory, "indexer"), { recursive: true });
    // An indexer's mind that is none: the resolver will not take its log.
    writeFileSync(
      join(directory, "indexer", "bundle.json"),
      JSON.stringify({ mind: "did:oip:nobody" }),
    );
    await expect(startNetwork({ directory })).rejects.toThrow(
      "the resolver did not take the indexer's log",
    );
    rmSync(join(directory, "indexer"), { recursive: true });
    const network = await startNetwork({ directory });
    expect(Object.keys(network.routes).sort()).toStrictEqual(Object.values(LOCAL).sort());
    await network.stop();
  });
});
