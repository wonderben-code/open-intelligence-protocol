// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Place } from "./harness.ts";

let place: Place;
let ada: string;
let bob: string;
let adaMind: string;
let bobMind: string;
const mindOf = async (dir: string): Promise<string> =>
  ((await place.oip(["show", "--dir", dir, "--json"])).json() as { mind: string }).mind;

/** What `oip inbox --json` says. */
interface Read {
  readonly new: number;
  readonly kept: number;
  readonly received: {
    id: string;
    from: string;
    sealed: boolean;
    time: string;
    packet: { purpose: { verb: string }; content: Record<string, unknown> };
  }[];
  readonly refused: unknown[];
  readonly retried: { id: string; expired: boolean }[];
}
const read = async (dir: string, ...more: string[]): Promise<Read> =>
  (await place.oip(["inbox", "--dir", dir, "--json", ...more])).json() as Read;

/**
 * Whether text has a character a terminal acts on, or that reorders what is
 * shown: a control other than the newline, or a control of bidirectional text.
 */
function actedOn(text: string): boolean {
  for (const character of text) {
    const point = character.codePointAt(0) ?? 0;
    if (
      (point < 0x20 && point !== 0x0a) ||
      (point >= 0x7f && point <= 0x9f) ||
      [0x2028, 0x2029, 0x200e, 0x200f].includes(point) ||
      (point >= 0x202a && point <= 0x202e) ||
      (point >= 0x2066 && point <= 0x2069)
    ) {
      return true;
    }
  }
  return false;
}

beforeAll(async () => {
  place = new Place();
  await place.network();
  ada = place.dir("ada");
  bob = place.dir("bob");
  expect((await place.oip(["init", "--local", "--dir", ada])).code).toBe(0);
  expect((await place.oip(["init", "--local", "--dir", bob])).code).toBe(0);
  adaMind = await mindOf(ada);
  bobMind = await mindOf(bob);
});
afterAll(async () => {
  await place.close();
});

describe("oip send and oip inbox", () => {
  it(`${clause("L1 12.1")} sends a packet, signed and sealed, and the recipient reads it once it is verified`, async () => {
    const sent = await place.oip([
      "send",
      bobMind,
      "--verb",
      "request",
      "--goal",
      "A translation",
      "--text",
      "Could you translate a lease by Friday?",
      "--dir",
      ada,
    ]);
    expect(sent.err).toBe("");
    expect(sent.code).toBe(0);
    expect(place.plain(sent.out)).toMatchSnapshot();
    const arrived = await place.oip(["inbox", "--dir", bob]);
    expect(arrived.err).toBe("");
    expect(arrived.code).toBe(0);
    expect(place.plain(arrived.out)).toMatchSnapshot();
    expect(arrived.out).toContain(`  from       ${adaMind}\n`);
    // A mailbox gives a packet once: it is kept, and shown again when asked for.
    const [id = ""] = /bciq[a-z2-7]{52}/u.exec(sent.out) ?? [];
    const kept = join(bob, "inbox", `${id}.json`);
    expect(existsSync(kept)).toBe(true);
    expect(statSync(kept).mode & 0o077).toBe(0);
    expect((await place.oip(["inbox", "--dir", bob])).out).toBe("0 new packets. 1 kept in all.\n");
    const all = await read(bob, "--all");
    expect(all).toMatchObject({
      new: 0,
      kept: 1,
      received: [{ id, from: adaMind, sealed: true, packet: { purpose: { verb: "request" } } }],
    });
  });

  it(`${clause("L1 12.2")} carries records, and the recipient holds them from then on`, async () => {
    // A record Ada has: her profile, as it was published.
    const profile = await place.oip([
      "publish",
      "profile",
      "--name",
      "Ada",
      "--dir",
      ada,
      "--json",
    ]);
    const { id, record } = profile.json() as { id: string; record: object };
    const file = join(place.home, "profile.json");
    writeFileSync(file, JSON.stringify(record));
    const sent = await place.oip([
      "send",
      bobMind,
      "--text",
      "This is who I am.\nRead it when you can.",
      "--record",
      file,
      "--dir",
      ada,
      "--json",
    ]);
    expect(sent.code).toBe(0);
    expect(sent.json()).toMatchObject({
      mind: adaMind,
      packet: {
        content: {
          parts: [{ mediaType: "text/plain" }, { mediaType: "application/oip+json", body: record }],
        },
      },
      deliveries: [{ to: bobMind, sealed: true, stored: true }],
    });
    const arrived = await place.oip(["inbox", "--dir", bob]);
    expect(arrived.out).toContain("1 new packet. 2 kept in all.\n");
    expect(arrived.out).toContain("  text\n    This is who I am.\n    Read it when you can.\n");
    expect(arrived.out).toContain(`  record     Participant ${id}\n`);
    // Held by the mind, and so kept in its directory for the commands that come after.
    expect(readdirSync(join(bob, "records"))).toContain(`${id}.json`);
    const kept = JSON.parse(readFileSync(join(bob, "records", `${id}.json`), "utf8")) as {
      record: object;
      seen: Record<string, string>;
    };
    expect(kept.record).toStrictEqual(record);
    // With when Bob first obtained its proof: his own record, which is evidence it existed then.
    expect(Object.keys(kept.seen)).toHaveLength(1);
    expect(Object.values(kept.seen)[0]).toMatch(/^[0-9]{19}$/u);
    // The next command holds it again as first seen then, and writes down the same.
    const before = readFileSync(join(bob, "records", `${id}.json`), "utf8");
    await new Promise((resolve) => setTimeout(resolve, 5));
    expect((await place.oip(["inbox", "--dir", bob])).code).toBe(0);
    expect(readFileSync(join(bob, "records", `${id}.json`), "utf8")).toBe(before);
  });

  it(`${clause("L1 12.6")} sends in the clear when told to, and says so on both sides`, async () => {
    const sent = await place.oip(["send", bobMind, "--text", "Hello.", "--unsealed", "--dir", ada]);
    expect(sent.out).toContain(`  delivered  ${bobMind}, not sealed`);
    const [packet] = (await read(bob)).received;
    expect(packet).toMatchObject({ sealed: false });
    expect((await place.oip(["inbox", "--all", "--dir", bob])).out).toContain(", not sealed\n");
  });

  it(`${clause("L1 12.5")} shows what a packet says as data: nothing in it reaches the terminal as a control`, async () => {
    // Text that would clear the screen, and write another sender's name over the line before it.
    const escape = String.fromCodePoint(0x1b);
    const hostile = [
      `${escape}[2J${escape}[1;1H`,
      `${String.fromCodePoint(0x9b)}1A  from       did:oip:someone-else`,
      `${String.fromCodePoint(0x202e)}reversed${String.fromCodePoint(0x7)}`,
    ].join("\r");
    expect((await place.oip(["send", bobMind, "--text", hostile, "--dir", ada])).code).toBe(0);
    const shown = await place.oip(["inbox", "--dir", bob]);
    expect(actedOn(shown.out)).toBe(false);
    expect(shown.out).toContain("    \\u001b[2J\\u001b[1;1H\n");
    expect(shown.out).toContain("    \\u009b1A  from       did:oip:someone-else\n");
    expect(shown.out).toContain("    \\u202ereversed\\u0007\n");
    // For a program it is the same text, in JSON that a terminal can be shown as well.
    const asJson = await place.oip(["inbox", "--all", "--dir", bob, "--json"]);
    expect(actedOn(asJson.out)).toBe(false);
    const { received } = asJson.json() as Read;
    expect(received.at(-1)?.packet.content).toStrictEqual({
      mediaType: "text/plain",
      body: hostile,
    });
    // The sender's own terminal is no more obeyed than the recipient's.
    const sent = await place.oip(["send", bobMind, "--text", hostile, "--dir", ada]);
    expect(actedOn(sent.out)).toBe(false);
    await read(bob);
  });

  it(`${clause("L1 15.3")} keeps a packet for a recipient that is not there yet, and tries it again`, async () => {
    const nobody = `did:oip:bciq${"a".repeat(52)}`;
    const sent = await place.oip(["send", nobody, "--text", "Are you there?", "--dir", ada]);
    expect(sent.code).toBe(0);
    expect(sent.out).toContain(`  waiting    ${nobody} (not-found): it is kept, and tried again\n`);
    const [id = ""] = /bciq[a-z2-7]{52}/u.exec(sent.out) ?? [];
    // It is not due yet: a reading leaves it. Told not to wait, a packet is not kept at all.
    expect((await read(ada)).retried).toStrictEqual([]);
    const both = await place.oip(["send", nobody, bobMind, "--text", "To two.", "--dir", ada]);
    expect(both.out).toContain(`  waiting    ${nobody} (not-found)`);
    expect(both.out).toContain(`  delivered  ${bobMind}, sealed`);
    expect(id).toMatch(/^bciq/u);
    await read(bob);
  });

  it("says what is wrong with what it was given, and sends nothing", async () => {
    const before = (await read(bob, "--all")).kept;
    for (const [argv, said] of [
      [["--text", "To nobody."], "send takes the address of each recipient"],
      [[bobMind], "a packet carries something: say it with --text, or carry a --record"],
      [[bobMind, "--text", "x", "--expires-in", "soon"], "soon is no number of seconds"],
      [[bobMind, "--record", join(place.home, "none.json")], "there is no such file to read"],
    ] as const) {
      const refused = await place.oip(["send", ...argv, "--dir", ada]);
      expect(refused.code, said).toBe(2);
      expect(refused.err).toContain(said);
    }
    // What makes no packet is the client's to refuse.
    for (const argv of [
      [bobMind, "--text", "x", "--verb", "Not A Verb"],
      [bobMind, "--text", "x", "--expires-in", "999999"],
      ["did:oip:nobody", "--text", "x"],
    ]) {
      const refused = await place.oip(["send", ...argv, "--dir", ada]);
      expect(refused.code, argv.join(" ")).toBe(1);
      expect(refused.err).toMatch(/^oip: /u);
    }
    expect((await place.oip(["inbox", "more", "--dir", bob])).code).toBe(2);
    expect((await read(bob, "--all")).kept).toBe(before);
  });

  it(`${clause("L1 13.4")} listens, and shows each packet as it arrives, until it is stopped`, async () => {
    let stop: (() => void) | undefined;
    const stopped = new Promise<void>((resolve) => {
      stop = resolve;
    });
    let said = "";
    const listening = place.oip(["inbox", "--listen", "--dir", bob], {
      stopped: () => stopped,
      out: (text) => {
        said += text;
      },
    });
    const until = async (text: string): Promise<void> => {
      for (let turn = 0; turn < 1000 && !said.includes(text); turn++) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      expect(said).toContain(text);
    };
    // What was there is read first.
    await until("0 new packets.");
    expect(
      (await place.oip(["send", bobMind, "--text", "While you listen.", "--dir", ada])).code,
    ).toBe(0);
    await until("    While you listen.\n");
    expect(said).toContain("1 new packet.");
    stop?.();
    expect((await listening).code).toBe(0);
    expect(said.endsWith("No longer listening.\n")).toBe(true);
    // It is kept as any other is.
    expect((await place.oip(["inbox", "--dir", bob])).out).toMatch(/^0 new packets\. /u);
  });
});
