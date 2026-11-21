// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { PASSPHRASE, Place } from "./harness.ts";

let place: Place;
let dir: string;
/** What `oip show --json` says of a mind. */
interface Shown {
  readonly mind: string;
  readonly seq: number;
  readonly keys: string[];
  readonly parents: { mind: string; at: string; status: string }[];
  readonly children: string[];
}
const shown = async (of: string): Promise<Shown> =>
  (await place.oip(["show", "--dir", of, "--json"])).json() as Shown;

beforeAll(async () => {
  place = new Place();
  await place.network();
  dir = place.dir("ada");
  expect((await place.oip(["init", "--local", "--dir", dir])).code).toBe(0);
});
afterAll(async () => {
  await place.close();
});

describe("oip rotate", () => {
  it(`${clause("L1 3.7")} adds an event that rotates the control keys, and changes nothing else`, async () => {
    const before = await shown(dir);
    const rotated = await place.oip(["rotate", "--dir", dir]);
    expect(rotated.err).toBe("");
    expect(rotated.code).toBe(0);
    expect(rotated.out).toBe(
      "The control keys are rotated.\nThis mind's log has 2 events. Resolvers that have the new one: 1 of 1.\n",
    );
    expect(await shown(dir)).toStrictEqual({ ...before, seq: 1 });
    const again = await place.oip(["rotate", "--dir", dir, "--json"]);
    expect(again.json()).toStrictEqual({ mind: before.mind, seq: 2, published: 1 });
  });

  it("needs the passphrase the keys are sealed with", async () => {
    const wrong = await place.oip(["rotate", "--dir", dir], { env: { OIP_PASSPHRASE: "not it" } });
    expect(wrong.code).toBe(1);
    expect(wrong.out).toBe("");
    expect(wrong.err).not.toContain("not it");
    const none = await place.oip(["rotate", "--dir", dir], { env: {} });
    expect(none.code).toBe(2);
    expect(none.err).toContain("set OIP_PASSPHRASE, or run this where one can be typed");
    // Nothing was added to the log by either.
    expect((await shown(dir)).seq).toBe(2);
  });

  it("is of a mind: a directory that holds none says how to make one", async () => {
    const nobody = await place.oip(["rotate", "--dir", place.dir("nobody")]);
    expect(nobody.code).toBe(2);
    expect(place.plain(nobody.err)).toMatchSnapshot();
  });
});

describe("oip add-key and oip revoke-key", () => {
  it(`${clause("L1 3.7")} adds a key of everyday work, and takes one away for good`, async () => {
    const before = await shown(dir);
    expect(before.keys).toHaveLength(1);
    const added = await place.oip(["add-key", "--label", "laptop", "--dir", dir, "--json"]);
    expect(added.code).toBe(0);
    const { key } = added.json() as { key: string };
    expect(key).toMatch(/^z6Mk/u);
    expect((await shown(dir)).keys).toStrictEqual([...before.keys, key]);
    // Said for a person, the key is named: it is public.
    const second = await place.oip(["add-key", "--dir", dir]);
    expect(second.out).toMatch(
      /^The mind has a new key: z6Mk[1-9A-HJ-NP-Za-km-z]+\nThis mind's log has 5 events\. Resolvers that have the new one: 1 of 1\.\n$/u,
    );
    const [first = ""] = before.keys;
    const revoked = await place.oip(["revoke-key", first, "--dir", dir]);
    expect(revoked.code).toBe(0);
    expect(revoked.out).toContain(`The key is revoked: ${first}\n`);
    const after = await shown(dir);
    expect(after.keys).not.toContain(first);
    expect(after.keys).toHaveLength(2);
    // The mind goes on with a key it has: it publishes, signed with one that is left.
    expect((await place.oip(["publish", "location", "--dir", dir])).code).toBe(0);
  });

  it(`${clause("L1 6.2")} withdraws what a stolen key signed from a time on`, async () => {
    const { keys } = await shown(dir);
    const [stolen = ""] = keys;
    const since = "2026-01-31T12:00:00Z";
    const revoked = await place.oip([
      "revoke-key",
      stolen,
      "--compromised-since",
      since,
      "--dir",
      dir,
      "--json",
    ]);
    expect(revoked.code).toBe(0);
    expect(revoked.json()).toMatchObject({ revoked: stolen, compromisedSince: since });
    const said = await place.oip(["add-key", "--dir", dir, "--json"]);
    const { key } = said.json() as { key: string };
    const other = await place.oip(["revoke-key", key, "--compromised-since", since, "--dir", dir]);
    expect(other.out).toContain(
      `The key is revoked, and what it signed from ${since} on is withdrawn: ${key}\n`,
    );
  });

  it("says what is wrong with what it was given, and changes nothing", async () => {
    const before = await shown(dir);
    expect(before.keys).toHaveLength(1);
    const [last = ""] = before.keys;
    for (const [argv, said] of [
      [["revoke-key"], "revoke-key takes one key"],
      [["revoke-key", last, last], "revoke-key takes one key"],
      [["revoke-key", "z6MkNobody"], "z6MkNobody is not one of the mind's keys"],
      [["revoke-key", last, "--compromised-since", "yesterday"], "yesterday is no time"],
    ] as const) {
      const refused = await place.oip([...argv, "--dir", dir]);
      expect(refused.code, said).toBe(2);
      expect(refused.err).toContain(said);
    }
    // A mind keeps a key: its last is not revoked.
    const kept = await place.oip(["revoke-key", last, "--dir", dir]);
    expect(kept.code).toBe(1);
    expect(kept.err).toBe(
      "oip: that is the mind's last operational key: add another before it is revoked\n",
    );
    expect(await shown(dir)).toStrictEqual(before);
  });
});

describe("oip fork", () => {
  it(`${clause("L1 8.1")} makes a child that names its parent, and ${clause("L1 8.2")} the parent's log acknowledges it`, async () => {
    const parent = await shown(dir);
    const child = place.dir("child");
    const terms = join(place.home, "terms.json");
    writeFileSync(terms, JSON.stringify({ received: "the lease archive" }));
    const forked = await place.oip(["fork", child, "--terms", terms, "--dir", dir]);
    expect(forked.err).toBe("");
    expect(forked.code).toBe(0);
    expect(place.plain(forked.out)).toMatchSnapshot();
    const made = await shown(child);
    expect(forked.out).toContain(`The child is ${made.mind}\n`);
    expect(made.mind).not.toBe(parent.mind);
    // The child says whose it is, and the parent says so too.
    expect(made.parents).toHaveLength(1);
    expect(made.parents[0]).toMatchObject({ mind: parent.mind, status: "acknowledged" });
    expect((await shown(dir)).children).toStrictEqual([made.mind]);
    // It is a mind of its own: its own keys, the same services.
    expect(made.keys).toHaveLength(1);
    expect(parent.keys).not.toContain(made.keys[0]);
    expect(JSON.parse(readFileSync(join(child, "config.json"), "utf8"))).toStrictEqual(
      JSON.parse(readFileSync(join(dir, "config.json"), "utf8")),
    );
    // Anyone reads the same of it.
    const read = await place.oip(["resolve", made.mind, "--local"]);
    expect(read.out).toContain(`  parent     ${parent.mind} (which says so too)\n`);
    expect((await place.oip(["show", "--dir", dir])).out).toContain(`  child      ${made.mind}\n`);
  });

  it("makes a child of another kind, at other hosts, and says so for a program", async () => {
    const child = place.dir("service");
    const forked = await place.oip([
      "fork",
      child,
      "--kind",
      "service",
      "--host",
      "https://host.oip.localhost",
      "--dir",
      dir,
      "--json",
    ]);
    expect(forked.code).toBe(0);
    const said = forked.json() as { child: string; directory: string; mind: string };
    expect(said).toMatchObject({ directory: child, published: 1 });
    const made = (await place.oip(["show", "--dir", child, "--json"])).json();
    expect(made).toMatchObject({ mind: said.child, kind: "service" });
  });

  it(`${clause("L1 8.2")} acknowledges a child that was made elsewhere, which until then only claims its parent`, async () => {
    const parent = await shown(dir);
    // A mind that names no parent may still be acknowledged as a child: the parent's log says what it says.
    const other = place.dir("elsewhere");
    await place.oip(["init", "--local", "--dir", other]);
    const { mind } = await shown(other);
    const acknowledged = await place.oip(["fork", "--acknowledge", mind, "--dir", dir]);
    expect(acknowledged.code).toBe(0);
    expect(acknowledged.out).toContain(`This mind's log acknowledges its child: ${mind}\n`);
    expect((await shown(dir)).children).toContain(mind);
    expect((await shown(dir)).seq).toBe(parent.seq + 1);
  });

  it("takes a directory or an address, and makes nothing where it is given neither or both", async () => {
    const before = await shown(dir);
    const child = place.dir("never");
    for (const argv of [
      ["fork"],
      ["fork", child, "--acknowledge", before.mind],
      ["fork", child, place.dir("another")],
    ]) {
      const refused = await place.oip([...argv, "--dir", dir]);
      expect(refused.code).toBe(2);
      expect(refused.err).toContain(
        "fork takes a directory to make the child in, or --acknowledge",
      );
    }
    // What the child received is a JSON object, in a file that is there.
    const terms = join(place.home, "not-terms.json");
    for (const [text, said] of [
      [undefined, "there is no such file to read"],
      ["[1, 2]", "holds no JSON object"],
      ['{"a": 1, "a": 2}', "is not JSON a record may be in"],
      ['{"a": 1.5}', "is not JSON a record may be in"],
    ] as const) {
      if (text !== undefined) writeFileSync(terms, text);
      const refused = await place.oip(["fork", child, "--terms", terms, "--dir", dir]);
      expect(refused.code, said).toBe(2);
      expect(refused.err).toContain(said);
    }
    expect(existsSync(child)).toBe(false);
    expect(await shown(dir)).toStrictEqual(before);
    // A directory that holds a mind takes no other, and the parent's log is left as it is.
    const taken = await place.oip(["fork", place.dir("child"), "--dir", dir]);
    expect(taken.code).toBe(2);
    expect(taken.err).toContain("a mind lives in");
    expect(await shown(dir)).toStrictEqual(before);
  });

  it("never prints a key that is not public, or the passphrase", async () => {
    const said = await place.oip(["fork", place.dir("quiet"), "--dir", dir, "--json"]);
    expect(said.out + said.err).not.toContain(PASSPHRASE);
    expect(said.out).not.toMatch(/secret|private|seed/iu);
  });
});
