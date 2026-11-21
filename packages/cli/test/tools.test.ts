// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { COMMANDS, GLOBAL_FLAGS } from "../src/index.ts";
import { PASSPHRASE, Place } from "./harness.ts";

const BACKUP_PASSPHRASE = "kept apart, in another place";
/** The environment of a run that makes or opens a backup. */
const env = { OIP_PASSPHRASE: PASSPHRASE, OIP_BACKUP_PASSPHRASE: BACKUP_PASSPHRASE };

let place: Place;
let ada: string;
let mind: string;
beforeAll(async () => {
  place = new Place();
  await place.network();
  ada = place.dir("ada");
  const made = await place.oip(["init", "--local", "--dir", ada, "--json"]);
  expect(made.code).toBe(0);
  mind = (made.json() as { mind: string }).mind;
});
afterAll(async () => {
  await place.close();
});

/** What `oip doctor --json` says. */
interface Looked {
  readonly well: boolean;
  readonly failed: boolean;
  readonly checks: { state: string; what: string; advice?: string }[];
}
const doctor = async (dir: string, more = {}): Promise<Looked & { code: number }> => {
  const ran = await place.oip(["doctor", "--dir", dir, "--json"], more);
  return { ...(ran.json() as Looked), code: ran.code };
};

describe("oip doctor", () => {
  it("says what is well with a mind and what should be seen to, and asks for no passphrase", async () => {
    const said = await place.oip(["doctor", "--dir", ada], { env: {} });
    expect(said.err).toBe("");
    expect(said.code).toBe(0);
    expect(place.plain(said.out)).toMatchSnapshot();
    expect(said.out.endsWith("The mind works. 2 things should be seen to.\n")).toBe(true);
    const looked = await doctor(ada);
    expect(looked).toMatchObject({ well: false, failed: false, code: 0 });
    expect(looked.checks.filter(({ state }) => state === "warn")).toStrictEqual([
      {
        state: "warn",
        what: "no backup holds the keys as they are now (control, operational, invocation, agreement)",
        advice: "oip keys backup <file>",
      },
      {
        state: "warn",
        what: "the mind has no profile: nobody finds it by what it can do",
        advice: "oip publish profile --name <name>",
      },
    ]);
  });

  it("says where there is no mind, or no network for it, and ends with 1", async () => {
    const nobody = await place.oip(["doctor", "--dir", place.dir("nobody")]);
    expect(nobody.code).toBe(1);
    expect(place.plain(nobody.out)).toMatchSnapshot();
    // A mind whose services are a network on this machine needs that network to be running.
    const other = new Place();
    await other.network();
    const dir = other.dir("eve");
    expect((await other.oip(["init", "--local", "--dir", dir])).code).toBe(0);
    await other.close();
    // The directory is gone with its place: one like it, whose network is not there.
    const lone = place.dir("lone");
    expect((await place.oip(["init", "--local", "--dir", lone])).code).toBe(0);
    const config = join(lone, "config.json");
    const told = JSON.parse(readFileSync(config, "utf8")) as { network: string };
    writeFileSync(config, JSON.stringify({ ...told, network: place.dir("no-network") }));
    const stopped = await doctor(lone);
    expect(stopped).toMatchObject({ failed: true, code: 1 });
    expect(stopped.checks.at(-1)).toMatchObject({
      state: "fails",
      advice: "start it in another terminal: oip demo",
    });
    expect((await place.oip(["doctor", "more", "--dir", ada])).code).toBe(2);
  });

  it(`${clause("core 9.1")} finds a clock that is off, and a directory that is open to others`, async () => {
    const hour = 3_600_000_000_000n;
    const late = await doctor(ada, {
      clock: { now: () => BigInt(Date.now()) * 1_000_000n + hour },
    });
    expect(late).toMatchObject({ failed: true, code: 1 });
    const off = late.checks.find(({ state }) => state === "fails");
    expect(off?.what).toMatch(/this machine's clock differs from .* by 3[0-9]{3} seconds/u);
    expect(off?.advice).toBe("set the clock");
    chmodSync(ada, 0o755);
    const open = await doctor(ada);
    expect(open.checks[1]).toStrictEqual({
      state: "warn",
      what: "the directory can be read by other users of this machine",
      advice: `chmod 700 ${ada}`,
    });
    chmodSync(ada, 0o700);
  });
});

describe("oip keys backup and oip keys restore", () => {
  const file = (name: string): string => join(place.home, name);

  it("writes the keys to a file, sealed with a passphrase of its own, and nothing of them in the clear", async () => {
    const backup = file("first.backup");
    const made = await place.oip(["keys", "backup", backup, "--dir", ada], { env });
    expect(made.err).toBe("");
    expect(made.code).toBe(0);
    expect(place.plain(made.out)).toMatchSnapshot();
    expect(statSync(backup).mode & 0o077).toBe(0);
    const kept = readFileSync(backup, "latin1");
    expect(kept).not.toContain(PASSPHRASE);
    expect(kept).not.toContain(BACKUP_PASSPHRASE);
    expect(made.out + made.err).not.toContain(BACKUP_PASSPHRASE);
    // The keystore knows a backup holds its keys now.
    const looked = await doctor(ada);
    expect(looked.checks.map(({ what }) => what)).toContain("a backup holds every key");
    // A file that is there is not written over, unless that is asked for.
    const again = await place.oip(["keys", "backup", backup, "--dir", ada], { env });
    expect(again.code).toBe(2);
    expect(again.err).toContain("is there already: name another, or write over it with --replace");
    const replaced = await place.oip(
      ["keys", "backup", backup, "--replace", "--dir", ada, "--json"],
      {
        env,
      },
    );
    // One key of each role: to change its identity, to sign, to sign as a member, to be sealed to.
    expect(replaced.json()).toMatchObject({ file: backup, mind, keys: 4 });
  });

  it("asks for each passphrase where one is typed, the backup's twice, and shows neither", async () => {
    const asked: string[] = [];
    const answers = [PASSPHRASE, BACKUP_PASSPHRASE, BACKUP_PASSPHRASE];
    const typed = await place.oip(["keys", "backup", file("typed.backup"), "--dir", ada], {
      env: {},
      secret: (question: string) => {
        asked.push(question);
        return Promise.resolve(answers.shift() ?? "");
      },
    });
    expect(typed.code).toBe(0);
    expect(asked).toStrictEqual([
      "Passphrase: ",
      "A passphrase for the backup, of its own: ",
      "The same again: ",
    ]);
    expect(typed.out + typed.err).not.toContain(BACKUP_PASSPHRASE);
    // With no terminal and no variable there is no passphrase to seal it with, and no file.
    const none = await place.oip(["keys", "backup", file("none.backup"), "--dir", ada], {
      env: { OIP_PASSPHRASE: PASSPHRASE },
    });
    expect(none.code).toBe(2);
    expect(none.err).toContain("set OIP_BACKUP_PASSPHRASE, or run this where one can be typed");
    expect(existsSync(file("none.backup"))).toBe(false);
  });

  it("makes the mind's directory again from a backup: the same mind, which signs and changes as before", async () => {
    const dir = place.dir("restored");
    const restored = await place.oip(
      ["keys", "restore", file("first.backup"), "--local", "--dir", dir],
      { env },
    );
    expect(restored.err).toBe("");
    expect(restored.code).toBe(0);
    expect(place.plain(restored.out)).toMatchSnapshot();
    expect(restored.out).toContain(`The mind is ${mind}\n`);
    expect(readFileSync(join(dir, "config.json"), "utf8")).toBe(
      readFileSync(join(ada, "config.json"), "utf8"),
    );
    // It is the mind: it publishes, and its identity changes, from the restored keys.
    expect((await place.oip(["publish", "location", "--dir", dir])).code).toBe(0);
    expect((await place.oip(["rotate", "--dir", dir, "--json"])).json()).toMatchObject({
      mind,
      seq: 1,
    });
  });

  it(`${clause("L1 3.4")} says so where the mind has changed since the backup was made`, async () => {
    // The mind's identity changed after the first backup: its control keys were used.
    const stale = place.dir("stale");
    const restored = await place.oip(
      ["keys", "restore", file("first.backup"), "--local", "--dir", stale, "--json"],
      { env },
    );
    expect(restored.code).toBe(0);
    expect(restored.json()).toStrictEqual({
      directory: stale,
      mind,
      events: 2,
      signs: true,
      identity: false,
    });
    const text = await place.oip(
      ["keys", "restore", file("first.backup"), "--local", "--dir", place.dir("stale-too")],
      { env },
    );
    expect(text.out).toContain(
      "  identity   can change no more from this backup: its control keys were used since.",
    );
    // It signs as before, and its identity is not changed from here: the next keys are elsewhere.
    expect((await place.oip(["publish", "location", "--dir", stale])).code).toBe(0);
    const refused = await place.oip(["rotate", "--dir", stale]);
    expect(refused.code).toBe(1);
    expect(refused.err).toContain(
      "the keystore does not hold the control keys the mind's log commits to",
    );
  });

  it("writes nothing where it is given what it cannot use", async () => {
    const dir = place.dir("never");
    const junk = file("junk.backup");
    writeFileSync(junk, "not a backup");
    for (const [argv, more, code, said] of [
      [["keys", "restore"], { env }, 2, "keys restore takes one file: the backup"],
      [
        ["keys", "restore", file("missing.backup"), "--local"],
        { env },
        2,
        "there is no such file to read",
      ],
      [["keys", "restore", junk, "--local"], { env }, 2, "is no backup of a mind's keys"],
      [["keys", "restore", file("first.backup")], { env }, 2, "a mind needs a resolver"],
      [
        ["keys", "restore", file("first.backup"), "--local"],
        { env: { ...env, OIP_BACKUP_PASSPHRASE: "not it" } },
        1,
        "the lock does not open this",
      ],
      [
        ["keys", "restore", file("first.backup"), "--local"],
        { env: { OIP_PASSPHRASE: PASSPHRASE } },
        2,
        "set OIP_BACKUP_PASSPHRASE",
      ],
      [["keys", "backup"], { env }, 2, "keys backup takes one file"],
    ] as const) {
      const refused = await place.oip([...argv, "--dir", dir], more);
      expect(refused.code, argv.join(" ")).toBe(code);
      expect(refused.err, argv.join(" ")).toContain(said);
      expect(refused.err).not.toContain("not it");
      expect(existsSync(dir), argv.join(" ")).toBe(false);
    }
    // A directory that holds keys takes no backup over them.
    const taken = await place.oip(
      ["keys", "restore", file("first.backup"), "--local", "--dir", ada],
      {
        env,
      },
    );
    expect(taken.code).toBe(2);
    expect(taken.err).toContain("holds keys already");
  });
});

describe("oip completions", () => {
  /** What bash would offer for the words typed so far, the last of them unfinished. */
  function offered(script: string, ...words: string[]): string[] {
    const ran = spawnSync(
      "bash",
      [
        "-c",
        `${script}\nCOMP_WORDS=(oip "$@"); COMP_CWORD=$#; _oip; printf '%s\\n' "\${COMPREPLY[@]}"`,
        "bash",
        ...words,
      ],
      { encoding: "utf8" },
    );
    expect(ran.stderr).toBe("");
    return ran.stdout.split("\n").filter((word) => word !== "");
  }

  it("teaches bash every command and its options, from the commands themselves", async () => {
    const printed = await place.oip(["completions", "bash"]);
    expect(printed.code).toBe(0);
    expect(printed.out).toMatchSnapshot();
    const checked = spawnSync("bash", ["-n"], { input: printed.out, encoding: "utf8" });
    expect(checked.stderr).toBe("");
    expect(checked.status).toBe(0);
    const firsts = [...new Set(COMMANDS.map(({ name }) => name.split(" ")[0]))].sort();
    expect(offered(printed.out, "").sort()).toStrictEqual(firsts);
    expect(offered(printed.out, "pub")).toStrictEqual(["publish"]);
    expect(offered(printed.out, "publish", "").sort()).toStrictEqual([
      "location",
      "profile",
      "record",
    ]);
    expect(offered(printed.out, "keys", "re")).toStrictEqual(["restore"]);
    expect(offered(printed.out, "init", "--k").sort()).toStrictEqual(["--keychain", "--kind"]);
    expect(offered(printed.out, "collective", "sign", "--").sort()).toStrictEqual(
      ["--dir", "--get", "--help", "--json", "--out", "--publish", "--send-to", "--version"].sort(),
    );
    // A command with no options of its own is offered those every command takes, all of them.
    expect(offered(printed.out, "show", "--").sort()).toStrictEqual(
      Object.keys(GLOBAL_FLAGS)
        .map((flag) => `--${flag}`)
        .sort(),
    );
    // Every option of every command is offered after its command.
    for (const command of COMMANDS) {
      const flags = offered(printed.out, ...command.name.split(" "), "--");
      for (const flag of Object.keys(command.flags))
        expect(flags, command.name).toContain(`--${flag}`);
    }
  });

  it("prints the same for zsh, and one of its own for fish", async () => {
    const zsh = await place.oip(["completions", "zsh"]);
    expect(zsh.out).toContain("bashcompinit");
    expect(zsh.out).toContain("complete -F _oip oip\n");
    const fish = await place.oip(["completions", "fish"]);
    expect(fish.out).toMatchSnapshot();
    for (const command of COMMANDS) {
      const [first = "", second] = command.name.split(" ");
      expect(fish.out).toContain(` -a ${second ?? first} `);
      for (const flag of Object.keys(command.flags)) expect(fish.out).toContain(` -l ${flag}`);
    }
    // As JSON, the script is one string, for a program that writes it to a file.
    const asJson = (await place.oip(["completions", "fish", "--json"])).json();
    expect(asJson).toStrictEqual({ shell: "fish", script: fish.out });
    for (const argv of [
      ["completions"],
      ["completions", "powershell"],
      ["completions", "bash", "zsh"],
    ]) {
      const refused = await place.oip(argv);
      expect(refused.code).toBe(2);
      expect(refused.err).toContain("completions takes one shell: bash, zsh or fish");
    }
  });
});
