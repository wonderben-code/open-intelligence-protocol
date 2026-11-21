// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { Keystore } from "@oip/keystore";
import { fileStorage } from "@oip/keystore/node";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { LOCAL, type Network } from "../src/index.ts";
import { PASSPHRASE, Place } from "./harness.ts";

let place: Place;
let network: Network;
beforeAll(async () => {
  place = new Place();
  network = await place.network();
});
afterAll(async () => {
  await place.close();
});

describe("oip demo", () => {
  it("runs a resolver, a host and an indexer on this machine, and says where they are", async () => {
    expect(network).toMatchObject(LOCAL);
    expect(Object.keys(network.routes).sort()).toStrictEqual(Object.values(LOCAL).sort());
    for (const place of Object.values(network.routes)) {
      expect(place).toMatch(/^http:\/\/127\.0\.0\.1:[0-9]+$/u);
      // Each answers, as itself.
      const ready = await fetch(`${place}/readyz`);
      expect(ready.status).toBe(200);
    }
    // What a mind made with `--local` reads, for as long as the network runs.
    const file = join(place.home, ".oip-demo", "network.json");
    expect(JSON.parse(readFileSync(file, "utf8"))).toStrictEqual({
      ...LOCAL,
      routes: network.routes,
    });
  });

  it("says so for a person too, and stops when it is told to", async () => {
    const other = new Place();
    let stop: (() => void) | undefined;
    const stopped = new Promise<void>((resolve) => {
      stop = resolve;
    });
    let said = "";
    const running = other.oip(["demo"], {
      stopped: () => stopped,
      out: (text) => {
        said += text;
      },
    });
    for (let turn = 0; turn < 500 && said === ""; turn++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(other.plain(said)).toMatchSnapshot();
    const file = join(other.home, ".oip-demo", "network.json");
    expect(existsSync(file)).toBe(true);
    stop?.();
    expect((await running).code).toBe(0);
    expect(said).toContain("The network has stopped.\n");
    // Nothing says a network is there once it is not.
    expect(existsSync(file)).toBe(false);
    // What it held is kept: it starts again with the same indexer.
    const indexer = readFileSync(join(other.home, ".oip-demo", "indexer", "bundle.json"), "utf8");
    const again = await other.network();
    expect(readFileSync(join(other.home, ".oip-demo", "indexer", "bundle.json"), "utf8")).toBe(
      indexer,
    );
    expect(again.resolver).toBe(LOCAL.resolver);
    await other.close();
  });
});

describe("oip init", () => {
  it("makes a mind on the local network: its keys sealed in its directory, and its first event published", async () => {
    const dir = place.dir("ada");
    const made = await place.oip(["init", "--local", "--dir", dir]);
    expect(made.err).toBe("");
    expect(made.code).toBe(0);
    expect(place.plain(made.out)).toMatchSnapshot();
    // The directory is the user's alone, and nothing in it is a key in the clear.
    expect(statSync(dir).mode & 0o077).toBe(0);
    expect(readdirSync(dir).sort()).toStrictEqual(["config.json", "keys", "memory"]);
    expect(JSON.parse(readFileSync(join(dir, "config.json"), "utf8"))).toStrictEqual({
      resolvers: [LOCAL.resolver],
      indexers: [LOCAL.indexer],
      lock: "passphrase",
      network: join(place.home, ".oip-demo"),
    });
    for (const name of readdirSync(join(dir, "keys"))) {
      const kept = readFileSync(join(dir, "keys", name), "utf8");
      expect(kept).not.toContain(PASSPHRASE);
      expect(statSync(join(dir, "keys", name)).mode & 0o077).toBe(0);
    }
    // The resolver has it.
    const shown = await place.oip(["show", "--dir", dir, "--json"]);
    expect(shown.code).toBe(0);
    const state = shown.json() as { mind: string; homes: string[]; location: { status: string } };
    expect(made.out).toContain(`Your mind is ${state.mind}\n`);
    expect(state).toMatchObject({
      kind: "agent",
      seq: 0,
      retired: false,
      homes: [LOCAL.host],
      resolvers: [LOCAL.resolver],
      indexers: [LOCAL.indexer],
      location: { status: "active" },
      participant: null,
    });
  });

  it("says the same for a program, with nothing of a key", async () => {
    const dir = place.dir("bob");
    const made = await place.oip(["init", "--local", "--kind", "human", "--dir", dir, "--json"]);
    expect(made.code).toBe(0);
    const said = made.json() as Record<string, unknown>;
    expect(said).toStrictEqual({
      mind: said["mind"],
      directory: dir,
      resolvers: [LOCAL.resolver],
      homes: [LOCAL.host],
      indexers: [LOCAL.indexer],
      lock: "passphrase",
      published: 1,
    });
    expect(String(said["mind"])).toMatch(/^did:oip:/u);
    expect((await place.oip(["show", "--dir", dir, "--json"])).json()).toMatchObject({
      kind: "human",
    });
  });

  it("makes one mind in a directory, and no second", async () => {
    const dir = place.dir("ada");
    const again = await place.oip(["init", "--local", "--dir", dir]);
    expect(again.code).toBe(2);
    expect(place.plain(again.err)).toBe(
      "oip: a mind lives in <home>/ada already: `oip show` says which. Another needs a directory of its own (--dir)\n" +
        "Run `oip init --help` for how it is used.\n",
    );
  });

  it("takes the services it is named, each an HTTPS origin, and needs a resolver", async () => {
    const dir = place.dir("cyd");
    const none = await place.oip(["init", "--dir", dir]);
    expect(none.code).toBe(2);
    expect(none.err).toContain("a mind needs a resolver");
    for (const flag of ["--resolver", "--host", "--indexer"]) {
      const wrong = await place.oip([
        "init",
        "--local",
        "--dir",
        dir,
        flag,
        "http://plain.example",
      ]);
      expect(wrong.code, flag).toBe(2);
      expect(wrong.err).toContain("http://plain.example is no HTTPS origin");
    }
    expect(existsSync(dir)).toBe(false);
    // Named, a service is used in the place of the local network's: here a host is, twice over.
    const made = await place.oip([
      "init",
      "--local",
      "--dir",
      dir,
      "--host",
      LOCAL.host,
      "--host",
      LOCAL.host,
      "--json",
    ]);
    expect(made.json()).toMatchObject({ homes: [LOCAL.host] });
  });

  it("needs the local network to be running, where it is asked to use it", async () => {
    const nowhere = await place.oip(["init", "--local", "--network", place.dir("no-network")]);
    expect(nowhere.code).toBe(2);
    expect(place.plain(nowhere.err)).toContain(
      "no network is running from <home>/no-network: start one with `oip demo`, in another terminal",
    );
    // A file there that no network wrote is not taken for one.
    const dir = place.dir("forged-network");
    await place.oip(["init", "--dir", dir, "--resolver", "https://resolver.example"]);
    for (const forged of [
      "not JSON",
      JSON.stringify({ ...LOCAL, routes: { [LOCAL.resolver]: "http://evil.example:80" } }),
      JSON.stringify({ ...LOCAL, resolver: "http://plain.example", routes: {} }),
      JSON.stringify({ resolver: LOCAL.resolver, routes: {} }),
    ]) {
      writeFileSync(join(dir, "network.json"), forged);
      const refused = await place.oip([
        "init",
        "--local",
        "--network",
        dir,
        "--dir",
        place.dir("x"),
      ]);
      expect(refused.code, forged).toBe(2);
      expect(refused.err).toContain("is not what a running network wrote");
    }
  });

  it("goes on with the same mind where its first event could not be published", async () => {
    const dir = place.dir("dee");
    // No resolver answers at this origin.
    const failed = await place.oip([
      "init",
      "--dir",
      dir,
      "--resolver",
      "https://resolver.invalid",
    ]);
    expect(failed.code).toBe(1);
    expect(failed.err).toContain("oip: ");
    const unfinished = await place.oip(["show", "--dir", dir]);
    expect(unfinished.code).toBe(2);
    expect(unfinished.err).toContain("was never published: run `oip init` again");
    // The keys are there. With a resolver that answers, the same keystore makes the mind.
    const keystore = async (): Promise<Keystore> =>
      Keystore.open({ storage: fileStorage(join(dir, "keys")) });
    const before = await keystore();
    expect(before.mind).toBeUndefined();
    const made = await place.oip(["init", "--local", "--dir", dir, "--json"]);
    expect(made.code).toBe(0);
    const after = await keystore();
    expect(after.id).toBe(before.id);
    expect(after.mind).toBe((made.json() as { mind: string }).mind);
  });
});

describe("the passphrase that seals a mind's keys", () => {
  it("is typed where there is a terminal, twice when it is new, and is never shown", async () => {
    const dir = place.dir("typed");
    const asked: string[] = [];
    const typing = (answers: string[]) => ({
      env: {},
      secret: (question: string) => {
        asked.push(question);
        return Promise.resolve(answers.shift() ?? "");
      },
    });
    const made = await place.oip(
      ["init", "--local", "--dir", dir],
      typing([PASSPHRASE, PASSPHRASE]),
    );
    expect(made.code).toBe(0);
    expect(asked).toStrictEqual(["A passphrase for the keys: ", "The same again: "]);
    expect(made.out + made.err).not.toContain(PASSPHRASE);
    // Typed twice differently, or not at all, nothing is made.
    const other = place.dir("mistyped");
    const mistyped = await place.oip(
      ["init", "--local", "--dir", other],
      typing([PASSPHRASE, "another one entirely"]),
    );
    expect(mistyped.code).toBe(2);
    expect(mistyped.err).toContain("the two passphrases are not the same");
    const empty = await place.oip(["init", "--local", "--dir", other], typing(["", ""]));
    expect(empty.err).toContain("no passphrase was typed");
    // Nothing was written for a mind that was not made.
    expect(existsSync(other)).toBe(false);
  });

  it("is asked for somewhere: with no terminal and none in the environment, the command says how", async () => {
    const nowhere = await place.oip(["init", "--local", "--dir", place.dir("unsealed")], {
      env: {},
    });
    expect(nowhere.code).toBe(2);
    expect(nowhere.err).toContain(
      "the keys are sealed with a passphrase: set OIP_PASSPHRASE, or run this where one can be typed",
    );
    // An empty one in the environment is none.
    const empty = await place.oip(["init", "--local", "--dir", place.dir("unsealed")], {
      env: { OIP_PASSPHRASE: "" },
    });
    expect(empty.code).toBe(2);
  });

  it("is refused where it is too weak to keep keys under", async () => {
    const weak = await place.oip(["init", "--local", "--dir", place.dir("weak")], {
      env: { OIP_PASSPHRASE: "short" },
    });
    expect(weak.code).toBe(1);
    expect(weak.err).toContain("oip: ");
    expect(
      (
        await place.oip(["init", "--local", "--dir", place.dir("weak"), "--json"], {
          env: { OIP_PASSPHRASE: "short" },
        })
      ).json(),
    ).toMatchObject({ error: { code: "weak-lock" } });
  });

  it("is not needed where the machine's keychain keeps the key", async () => {
    const dir = place.dir("keychained");
    const made = await place.oip(["init", "--local", "--keychain", "--dir", dir], { env: {} });
    expect(made.code).toBe(0);
    expect(made.out).toContain("sealed with a key in this machine's keychain.");
    expect(JSON.parse(readFileSync(join(dir, "config.json"), "utf8"))).toMatchObject({
      lock: "keychain",
    });
  });
});

describe("oip show", () => {
  it("shows the mind of a directory as its resolvers have it, and asks for no passphrase", async () => {
    const shown = await place.oip(["show", "--dir", place.dir("ada")], { env: {} });
    expect(shown.code).toBe(0);
    expect(place.plain(shown.out)).toMatchSnapshot();
  });

  it("says what is wrong with a directory that is not a mind's", async () => {
    const dir = place.dir("spoiled");
    await place.oip(["init", "--local", "--dir", dir]);
    for (const spoiled of [
      "not JSON",
      "null",
      JSON.stringify({ resolvers: ["http://plain.example"], indexers: [], lock: "passphrase" }),
      JSON.stringify({ resolvers: [LOCAL.resolver], indexers: "none", lock: "passphrase" }),
      JSON.stringify({ resolvers: [LOCAL.resolver], indexers: [], lock: "none" }),
      JSON.stringify({ resolvers: [LOCAL.resolver], indexers: [], lock: "keychain", network: 7 }),
    ]) {
      writeFileSync(join(dir, "config.json"), spoiled);
      const refused = await place.oip(["show", "--dir", dir]);
      expect(refused.code, spoiled).toBe(2);
      expect(place.plain(refused.err)).toContain(
        "<home>/spoiled/config.json is not a configuration this command wrote",
      );
    }
  });

  it("says that a network which has stopped is not there", async () => {
    const other = new Place();
    const running = await other.network();
    const dir = other.dir("eve");
    expect((await other.oip(["init", "--local", "--dir", dir])).code).toBe(0);
    await running.stop();
    const shown = await other.oip(["show", "--dir", dir]);
    expect(shown.code).toBe(2);
    expect(other.plain(shown.err)).toContain("no network is running from <home>/.oip-demo");
    await other.close();
  });
});
