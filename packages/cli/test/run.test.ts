// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { COMMANDS, GLOBAL_FLAGS, VERSION } from "../src/index.ts";
import { Place } from "./harness.ts";

let place: Place;
beforeAll(() => {
  place = new Place();
});
afterAll(async () => {
  await place.close();
});

describe("oip, asked for nothing or for help", () => {
  it("lists its commands, and says how to learn more of one", async () => {
    const helped = await place.oip(["--help"]);
    expect(helped.code).toBe(0);
    expect(helped.err).toBe("");
    expect(helped.out).toMatchSnapshot();
    // Every command is there, with the options they all take.
    for (const { name } of COMMANDS) expect(helped.out).toContain(`  ${name} `);
    for (const name of Object.keys(GLOBAL_FLAGS)) expect(helped.out).toContain(`--${name}`);
    // With nothing asked, the same is shown: but nothing was done, and the exit says so.
    const bare = await place.oip([]);
    expect(bare).toMatchObject({ code: 2, out: helped.out, err: "" });
  });

  it("has help for every command: what it does, its options, and an example to type", async () => {
    for (const command of COMMANDS) {
      const helped = await place.oip([...command.name.split(" "), "--help"]);
      expect(helped.code, command.name).toBe(0);
      expect(helped.out, command.name).toMatchSnapshot(command.name);
      expect(helped.out).toContain(command.summary);
      expect(helped.out).toContain(`Example:\n  ${command.example}\n`);
      for (const flag of Object.keys(command.flags)) expect(helped.out).toContain(`--${flag}`);
      // An example is of the command it is an example for.
      expect(command.example.startsWith(`oip ${command.name}`), command.name).toBe(true);
      // The same, for a program.
      const asJson = await place.oip([...command.name.split(" "), "--help", "--json"]);
      expect(asJson.json()).toStrictEqual({
        command: command.name,
        summary: command.summary,
        options: Object.keys(command.flags),
        example: command.example,
      });
    }
  });

  it("prints one member of an answer alone, for a script to take", async () => {
    expect(await place.oip(["--version", "--get", "version"])).toMatchObject({
      code: 0,
      out: `${VERSION}\n`,
    });
    // Before the command's name or after it, and a member within a member by its path.
    const listed = await place.oip(["--get", "commands.0", "--help"]);
    expect(listed).toMatchObject({ code: 0, out: `${COMMANDS[0]?.name ?? ""}\n` });
    expect((await place.oip(["init", "--help", "--get", "options"])).out).toBe(
      `${JSON.stringify(Object.keys(COMMANDS[0]?.flags ?? {}), undefined, 2)}\n`,
    );
    // What is not there is said to be not there, and nothing is printed for a script to take.
    for (const path of ["nothing", "commands.99", "commands.0.name"]) {
      const none = await place.oip(["--help", "--get", path]);
      expect(none).toMatchObject({ code: 2, out: "" });
      expect(none.err).toContain(`the answer has no member ${path}: --json shows what it has`);
    }
  });

  it("says its version", async () => {
    expect(await place.oip(["--version"])).toMatchObject({ code: 0, out: `${VERSION}\n` });
    expect((await place.oip(["--version", "--json"])).json()).toStrictEqual({ version: VERSION });
  });

  it("lists its commands for a program too", async () => {
    const listed = await place.oip(["--help", "--json"]);
    expect(listed.json()).toStrictEqual({ commands: COMMANDS.map(({ name }) => name) });
  });
});

describe("oip, asked wrongly", () => {
  it("says what it does not know, and where the help is, and exits with 2", async () => {
    const unknown = await place.oip(["frobnicate"]);
    expect(unknown).toMatchObject({ code: 2, out: "" });
    expect(unknown.err).toBe(
      "oip: there is no command `frobnicate`: `oip --help` lists them\n" +
        "Run `oip --help` for how it is used.\n",
    );
    const option = await place.oip(["show", "--frob"]);
    expect(option).toMatchObject({ code: 2, out: "" });
    expect(option.err).toContain("--frob");
    expect(option.err).toContain("Run `oip show --help` for how it is used.\n");
    // An option that takes a value, given none.
    expect((await place.oip(["show", "--dir"])).code).toBe(2);
  });

  it("says so as JSON where JSON was asked for, on standard output", async () => {
    const unknown = await place.oip(["frobnicate", "--json"]);
    expect(unknown).toMatchObject({ code: 2, err: "" });
    expect(unknown.json()).toStrictEqual({
      error: {
        code: "usage",
        message: "there is no command `frobnicate`: `oip --help` lists them",
      },
    });
  });

  it("finds a command whose options come before its name, and the directory wherever it is named", async () => {
    const before = await place.oip(["--dir", place.dir("nobody"), "show"]);
    const after = await place.oip(["show", "--dir", place.dir("nobody")]);
    expect(before.code).toBe(2);
    expect(before.err).toBe(after.err);
    expect(place.plain(before.err)).toContain("there is no mind in <home>/nobody");
    // The directory may come from the environment, and is `.oip` in the home otherwise.
    const named = await place.oip(["show"], { env: { OIP_DIR: place.dir("elsewhere") } });
    expect(place.plain(named.err)).toContain("there is no mind in <home>/elsewhere");
    expect(place.plain((await place.oip(["show"])).err)).toContain(
      "there is no mind in <home>/.oip:",
    );
  });

  it("does not hide a fault of its own", async () => {
    await expect(
      place.oip(["show"], {
        get env(): never {
          throw new RangeError("a fault of the command's own");
        },
      }),
    ).rejects.toThrow(RangeError);
  });
});
