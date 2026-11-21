// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * What every command prints for a person, held by one snapshot, with a
 * check that no command is left out (BUILD.md, M7: "snapshot tests cover the
 * help and output of every command"). The help of each is held in
 * `run.test.ts`, and what each does in the tests of its own.
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { COMMANDS } from "../src/index.ts";
import { PASSPHRASE, Place } from "./harness.ts";

const env = { OIP_PASSPHRASE: PASSPHRASE, OIP_BACKUP_PASSPHRASE: "kept apart, in another place" };

let place: Place;
beforeAll(async () => {
  place = new Place();
  await place.network();
});
afterAll(async () => {
  await place.close();
});

describe("what every command prints", () => {
  it("is held, for every command there is", async () => {
    const printed: Record<string, string> = {};
    const ada = place.dir("ada");
    const bob = place.dir("bob");
    /** Runs a command, keeps what it printed under the command's name, and gives it back. */
    const oip = async (name: string, argv: readonly string[], dir = ada): Promise<string> => {
      const ran = await place.oip([...name.split(" "), ...argv, "--dir", dir], { env });
      expect(ran.err, `${name} ${argv.join(" ")}`).toBe("");
      expect(ran.code, name).toBe(0);
      printed[name] = place
        .plain(ran.out)
        .replace(/ranked {5}[0-9.]+ by/gu, "ranked     <score> by")
        .replace(/[0-9]+ bytes/gu, "<bytes> bytes");
      return ran.out;
    };
    /** What a command answers for a program, without keeping what it printed. */
    const json = async <T>(argv: readonly string[], dir = ada): Promise<T> =>
      (await place.oip([...argv, "--dir", dir, "--json"], { env })).json() as T;
    const idIn = (text: string): string => /bciq[a-z2-7]{52}/u.exec(text)?.[0] ?? "";
    const file = (name: string, value: unknown): string => {
      const path = join(place.home, name);
      writeFileSync(path, JSON.stringify(value));
      return path;
    };

    await oip("init", ["--local"]);
    await place.oip(["init", "--local", "--kind", "human", "--dir", bob], { env });
    const adaMind = (await json<{ mind: string }>(["show"])).mind;
    const bobMind = (await json<{ mind: string }>(["show"], bob)).mind;

    await oip("rotate", []);
    await oip("add-key", ["--label", "laptop"]);
    const [first = ""] = (await json<{ keys: string[] }>(["show"])).keys;
    await oip("revoke-key", [first]);
    await oip("fork", [place.dir("child")]);

    const profile = await json<{ record: object }>([
      "publish",
      "profile",
      "--name",
      "Ada",
      "--capability",
      "translate=Translates legal texts",
      "--tag",
      "domain:legal",
    ]);
    await oip("publish profile", [
      "--name",
      "Ada",
      "--summary",
      "Translates.",
      "--capability",
      "translate=Translates legal texts",
      "--tag",
      "domain:legal",
    ]);
    await oip("publish location", ["--ttl", "600"]);
    await oip("publish record", [file("profile.json", profile.record)]);
    await oip("show", []);
    await oip("resolve", [adaMind, "--aliases"], bob);
    await oip("find", ["--tag", "domain:legal"], bob);

    await oip("send", [
      bobMind,
      "--verb",
      "request",
      "--goal",
      "A translation",
      "--text",
      "By Friday?",
    ]);
    await oip("inbox", [], bob);

    const wanted = idIn(
      await oip(
        "intent",
        ["--want", "A lease translated.", "--budget", "150", "--currency", "USD"],
        bob,
      ),
    );
    await place.oip(["send", adaMind, "--record", wanted, "--dir", bob], { env });
    await place.oip(["inbox", "--dir", ada], { env });
    await oip("offer", [
      "--provides",
      "A translation of a lease.",
      "--price",
      "120",
      "--currency",
      "USD",
      "--answers",
      wanted,
    ]);
    const deal = idIn(
      await oip("commit", [
        "--debtor",
        "me",
        "--creditor",
        bobMind,
        "--promise",
        "Ada will translate the lease.",
        "--send-to",
        bobMind,
      ]),
    );
    await place.oip(["inbox", "--dir", bob], { env });
    await place.oip(["commit", deal, "--send-to", adaMind, "--dir", bob], { env });
    await place.oip(["inbox", "--dir", ada], { env });
    await oip("receipt", [deal, "--outcome", "fulfilled", "--statement", "Delivered."]);
    await oip("status", [deal]);
    await oip("verify", [deal]);

    const mandate = idIn(
      await oip("delegate", [
        bobMind,
        "--command",
        "/oip/sign/Offer",
        "--expires",
        "2031-01-31T12:00:00Z",
      ]),
    );
    await oip("revoke", [mandate]);

    const event = /event {6}(bciq[a-z2-7]{52})/u.exec(
      await oip("collective create", [
        "--member",
        bobMind,
        "--threshold",
        "2",
        "--send-to",
        bobMind,
      ]),
    )?.[1];
    await place.oip(["inbox", "--dir", bob], { env });
    await oip("collective sign", [event ?? "", "--publish"], bob);

    const backup = join(place.home, "ada.backup");
    await oip("keys backup", [backup]);
    await oip("keys restore", [backup, "--local"], place.dir("restored"));
    await oip("doctor", []);
    await oip("completions", ["bash"]);

    // The network says where it is when it starts, and that it has stopped when it has.
    const other = new Place();
    const ran = await other.oip(["demo"]);
    expect(ran.code).toBe(0);
    printed["demo"] = other.plain(ran.out);
    await other.close();

    expect(Object.keys(printed).sort()).toStrictEqual(COMMANDS.map(({ name }) => name).sort());
    expect(printed).toMatchSnapshot();
  });
});
