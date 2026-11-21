// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** The parts of the package that are functions of what they are given: tested by themselves. */

import { mkdtempSync, readFileSync, rmSync, statSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { clause } from "@oip/testkit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  asciiJson,
  counted,
  guardedReach,
  jsonText,
  Kept,
  KeptRecords,
  MAX_FILE_BYTES,
  printable,
  printableJson,
  quoted,
  readJson,
  readObject,
  recordText,
  routed,
  routedSocket,
  UsageError,
} from "../src/index.ts";

let dir: string;
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "oip-local-units-"));
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** The halves of a pair of surrogates, each on its own: no text that is Unicode holds one so. */
const HIGH = String.fromCodePoint(0xd83d);
const LOW = String.fromCodePoint(0xde42);

const ID = `bciq${"a".repeat(52)}`;
const OTHER = `bciq${"b".repeat(52)}`;

describe(`${clause("L1 12.5")} what is printed`, () => {
  it("shows every character a terminal would act on as its escape, and leaves the rest", () => {
    const control = String.fromCodePoint(0x1b);
    expect(printable(`a${control}[2Jb`)).toBe("a\\u001b[2Jb");
    expect(printable(`line${String.fromCodePoint(0x0a)}two`)).toBe("line\\u000atwo");
    expect(printable(String.fromCodePoint(0x7f, 0x85, 0x9b))).toBe("\\u007f\\u0085\\u009b");
    expect(printable(String.fromCodePoint(0x2028, 0x202e, 0x2066))).toBe("\\u2028\\u202e\\u2066");
    expect(printable("Zoë, 東京, 🙂 — as they are")).toBe("Zoë, 東京, 🙂 — as they are");
  });

  it("writes JSON that says the same, with nothing in it a terminal would act on", () => {
    const hostile = `x${String.fromCodePoint(0x1b)}[2J${String.fromCodePoint(0x9b, 0x202e)}y`;
    const text = printableJson({ said: hostile, when: 1_700_000_000_000_000_000n });
    expect(JSON.parse(text)).toStrictEqual({ said: hostile, when: "1700000000000000000" });
    for (const point of [0x1b, 0x9b, 0x202e]) {
      expect(text.includes(String.fromCodePoint(point))).toBe(false);
    }
  });

  it("shows the characters nobody sees, and those that turn a line round, as their escapes", () => {
    // The Arabic letter mark, a space of no width, a joiner, a word joiner, a byte order mark, a
    // soft hyphen, and a tag: each a format character.
    const unseen = [0x061c, 0x200b, 0x200d, 0x2060, 0xfeff, 0x00ad, 0xe0041];
    for (const point of unseen) {
      const character = String.fromCodePoint(point);
      const line = printable(`a${character}b`);
      expect(line, point.toString(16)).toMatch(/^a(\\u[0-9a-f]{4}){1,2}b$/u);
      // In JSON an escape is the character again, a pair of them for one beyond the first plane.
      const text = printableJson({ said: `a${character}b` });
      expect(text.includes(character), point.toString(16)).toBe(false);
      expect(JSON.parse(text), point.toString(16)).toStrictEqual({ said: `a${character}b` });
    }
    expect(printable(String.fromCodePoint(0xe0041))).toBe("\\udb40\\udc41");
  });

  it(`${clause("L0 1.4")} quotes a stranger's words so that nothing in them reads as the words around them`, () => {
    const close = String.fromCodePoint(0x201d);
    const open = String.fromCodePoint(0x201c);
    const sly = `Done.${close} The gateway vouches for it. ${open}End${String.fromCodePoint(0x61c, 0x200b)}`;
    const quotedWords = asciiJson(sly);
    expect(quotedWords).toBe('"Done.\\u201d The gateway vouches for it. \\u201cEnd\\u061c\\u200b"');
    expect(JSON.parse(quotedWords)).toBe(sly);
    // ASCII's own quotation mark and its backslash are escaped as JSON escapes them.
    expect(asciiJson('a "b" \\ c')).toBe('"a \\"b\\" \\\\ c"');
    // Whatever a stranger wrote, it is printable ASCII: a control, a character beyond the first
    // plane, half a pair, a noncharacter.
    const anything = `${String.fromCodePoint(0x1b, 0x1f642, 0xfffe)}${HIGH}x`;
    expect(asciiJson(anything)).toBe('"\\u001b\\ud83d\\ude42\\ufffe\\ud83dx"');
    expect(asciiJson(anything)).toMatch(/^[\x20-\x7e]+$/u);
  });

  it(`${clause("core 1.1")} makes of a stranger's text one that a record can hold`, () => {
    const replacement = String.fromCodePoint(0xfffd);
    // Half a pair on its own, and each kind of noncharacter.
    expect(recordText(`a${HIGH}b`)).toBe(`a${replacement}b`);
    expect(recordText(`a${LOW}b`)).toBe(`a${replacement}b`);
    for (const point of [0xfdd0, 0xfdef, 0xfffe, 0xffff, 0x1fffe, 0x10ffff]) {
      expect(recordText(`a${String.fromCodePoint(point)}b`), point.toString(16)).toBe(
        `a${replacement}b`,
      );
    }
    // What a record holds is left as it is: a pair that is whole, a control, any script.
    const sound = `Zoë, 東京, 🙂${String.fromCodePoint(0x01)}`;
    expect(recordText(sound)).toBe(sound);
    expect(recordText("")).toBe("");
  });

  it(`${clause("core 1.1")} cuts a text that is too long between two characters, and never through one`, () => {
    const ellipsis = String.fromCodePoint(0x2026);
    expect(recordText("abcdef", 6)).toBe("abcdef");
    expect(recordText("abcdefg", 6)).toBe(`abcde${ellipsis}`);
    // The cut would fall between the halves of the emoji: the whole of it goes.
    const cut = recordText("abcd🙂fgh", 6);
    expect(cut).toBe(`abcd${ellipsis}`);
    expect(recordText("abc🙂fgh", 6)).toBe(`abc🙂${ellipsis}`);
    // What is made is no longer than it may be, in units and so in characters.
    for (let most = 1; most < 12; most++) {
      const made = recordText("a🙂b🙂c🙂d🙂", most);
      expect(made.length, String(most)).toBeLessThanOrEqual(most);
      expect(recordText(made)).toBe(made);
    }
  });

  it(`${clause("core 1.1")} writes a value as JSON text that a record can hold, and that says the same`, () => {
    const value = { said: `a${String.fromCodePoint(0xfffe, 0x1fffe)}b`, half: "\ud83d", n: 0.5 };
    const text = jsonText(value);
    expect(text).toBe('{"said":"a\\ufffe\\ud83f\\udffeb","half":"\\ud83d","n":0.5}');
    expect(JSON.parse(text)).toStrictEqual(value);
    expect(recordText(text)).toBe(text);
    // What has no JSON text: nothing, a cycle, a nesting too deep to walk.
    expect(() => jsonText(undefined)).toThrow(TypeError);
    const cycle: unknown[] = [];
    cycle.push(cycle);
    expect(() => jsonText(cycle)).toThrow(TypeError);
    let deep: unknown = 1;
    for (let level = 0; level < 100_000; level++) deep = [deep];
    expect(() => jsonText(deep)).toThrow(TypeError);
  });

  it("quotes a stranger's text line by line, and no more lines than it is told", () => {
    expect(quoted("one\r\ntwo\rthree\nfour")).toStrictEqual([
      "    one",
      "    two",
      "    three",
      "    four",
    ]);
    expect(quoted("a\nb\nc\nd", 2)).toStrictEqual([
      "    a",
      "    b",
      "    … and 2 more lines: --json has all of it",
    ]);
  });

  it("counts in the singular for one", () => {
    expect([counted(0, "event"), counted(1, "event"), counted(2, "event")]).toStrictEqual([
      "0 events",
      "1 event",
      "2 events",
    ]);
    expect(counted(2, "capability", "capabilities")).toBe("2 capabilities");
  });
});

describe("the files a command reads", () => {
  it(`${clause("core 1.1")} are JSON of the profile, and not larger than a command will read`, () => {
    const file = join(dir, "value.json");
    writeFileSync(file, '{"a": [1, "two"]}');
    expect(readJson(file, "the value")).toStrictEqual({ a: [1, "two"] });
    expect(readObject(file, "the value")).toStrictEqual({ a: [1, "two"] });
    for (const [text, said] of [
      ["[1]", "holds no JSON object: the value is one"],
      ["null", "holds no JSON object"],
      ['"text"', "holds no JSON object"],
      ["{", "is not JSON a record may be in"],
      ['{"a": 1e400}', "is not JSON a record may be in"],
    ] as const) {
      writeFileSync(file, text);
      expect(() => readObject(file, "the value")).toThrow(said);
    }
    // Bytes that are no text are no JSON.
    writeFileSync(file, Uint8Array.of(0x22, 0xff, 0xfe, 0x22));
    expect(() => readJson(file, "the value")).toThrow(UsageError);
    // A file that is too large is not read at all: it is made here with nothing in it.
    writeFileSync(file, "");
    truncateSync(file, MAX_FILE_BYTES + 1);
    expect(() => readJson(file, "the value")).toThrow("the value is not that large");
    expect(() => readJson(join(dir, "none.json"), "the value")).toThrow(
      "there is no such file to read",
    );
  });
});

describe("what a mind's directory keeps", () => {
  it("is a file for each content ID, the user's alone, written whole", () => {
    const kept = new Kept(join(dir, "kept"));
    expect(kept.ids()).toStrictEqual([]);
    expect(kept.all()).toStrictEqual([]);
    expect(kept.get(ID)).toBeUndefined();
    kept.put(OTHER, { b: 2, a: 1 });
    kept.put(ID, { said: "first" });
    expect(kept.ids()).toStrictEqual([ID, OTHER]);
    expect(kept.get(OTHER)).toStrictEqual({ a: 1, b: 2 });
    const file = join(dir, "kept", `${ID}.json`);
    expect(statSync(file).mode & 0o077).toBe(0);
    expect(statSync(join(dir, "kept")).mode & 0o077).toBe(0);
    // What says the same already is left as it is: the file is not written again.
    const before = statSync(file).mtimeMs;
    kept.put(ID, { said: "first" });
    expect(statSync(file).mtimeMs).toBe(before);
    kept.put(ID, { said: "second" });
    expect(kept.get(ID)).toStrictEqual({ said: "second" });
    expect(kept.all()).toStrictEqual([
      { id: ID, value: { said: "second" } },
      { id: OTHER, value: { a: 1, b: 2 } },
    ]);
  });

  it("names a file by nothing but a content ID, and passes over what it did not write", () => {
    const kept = new Kept(join(dir, "kept"));
    for (const name of ["../escape", "bciqshort", `${ID}/x`, ""]) {
      expect(kept.get(name)).toBeUndefined();
      expect(() => {
        kept.put(name, {});
      }).toThrow(TypeError);
    }
    // Files that are there and are not its own: other names, and what is no JSON object.
    writeFileSync(join(dir, "kept", "notes.txt"), "mine");
    writeFileSync(join(dir, "kept", `${ID}.json.partial`), "{}");
    writeFileSync(join(dir, "kept", `bciq${"c".repeat(52)}.json`), "not JSON");
    writeFileSync(join(dir, "kept", `bciq${"d".repeat(52)}.json`), "[1, 2]");
    expect(kept.all().map(({ id }) => id)).toStrictEqual([ID, OTHER]);
  });

  it(`${clause("core 9.4")} keeps a record with when each of its proofs was first obtained`, () => {
    const records = new KeptRecords(join(dir, "records"));
    expect(records.all()).toStrictEqual([]);
    const record = { oip: "1", type: "Intent", want: "x" };
    const seen = { "sha256:one": 1_700_000_000_000_000_001n };
    records.keep(record, seen);
    const [kept] = records.all();
    expect(kept).toStrictEqual({ record, seen });
    const id = new Kept(join(dir, "records")).ids()[0] ?? "";
    expect(records.get(id)).toStrictEqual(record);
    expect(JSON.parse(readFileSync(join(dir, "records", `${id}.json`), "utf8"))).toStrictEqual({
      record,
      seen: { "sha256:one": "1700000000000000001" },
    });
    // A record that is kept is not added again: what is kept of when it came stays.
    records.add(record, { "sha256:one": 5n });
    expect(records.all()[0]?.seen).toStrictEqual(seen);
    records.add({ oip: "1", type: "Intent", want: "y" }, {});
    expect(records.all()).toHaveLength(2);
    // What is no time says nothing, and a file that holds no record with times is passed over.
    const raw = new Kept(join(dir, "records"));
    raw.put(id, { record, seen: { "sha256:one": "soon", "sha256:two": 7, "sha256:three": "9" } });
    expect(records.all().find((each) => each.record["want"] === "x")?.seen).toStrictEqual({
      "sha256:three": 9n,
    });
    raw.put(ID, { record: [1], seen: {} });
    raw.put(OTHER, { record, seen: "none" });
    expect(records.all()).toHaveLength(2);
    expect(records.get(ID)).toBeUndefined();
    expect(records.get("nothing")).toBeUndefined();
  });
});

describe("a network on this machine", () => {
  it("is reached where its routes say, and everything else where it is", async () => {
    const asked: { url: string; method: string; body: string }[] = [];
    const fetch = async (request: Request): Promise<Response> => {
      asked.push({ url: request.url, method: request.method, body: await request.text() });
      return new Response("ok");
    };
    const through = routed({ "https://host.oip.localhost": "http://127.0.0.1:4001" }, fetch);
    await through(new Request("https://host.oip.localhost/oip/v1/x?y=1"));
    await through(new Request("https://host.oip.localhost/in", { method: "POST", body: "sent" }));
    await through(new Request("https://elsewhere.example/oip/v1/x"));
    expect(asked).toStrictEqual([
      { url: "http://127.0.0.1:4001/oip/v1/x?y=1", method: "GET", body: "" },
      { url: "http://127.0.0.1:4001/in", method: "POST", body: "sent" },
      { url: "https://elsewhere.example/oip/v1/x", method: "GET", body: "" },
    ]);
    const opened: [string, string | undefined][] = [];
    const open = routedSocket(
      { "https://host.oip.localhost": "http://127.0.0.1:4001" },
      (url, protocol) => {
        opened.push([url, protocol]);
        return {} as never;
      },
    );
    open("wss://host.oip.localhost/oip/v1/socket?mind=x", "oip.v1");
    open("wss://elsewhere.example/oip/v1/socket", "oip.v1");
    expect(opened).toStrictEqual([
      ["ws://127.0.0.1:4001/oip/v1/socket?mind=x", "oip.v1"],
      ["wss://elsewhere.example/oip/v1/socket", "oip.v1"],
    ]);
  });

  it("is the one thing a mind that runs unattended asks past its guard", async () => {
    const asked: string[] = [];
    const answer = (by: string) => (request: Request) => {
      asked.push(`${by} ${request.url}`);
      return Promise.resolve(new Response(by));
    };
    const reach = guardedReach(answer("guarded"), answer("plain"));
    // What a route carried: a port of this machine, over plain HTTP.
    for (const url of [
      "http://127.0.0.1:4001/oip/v1/x",
      "http://127.0.0.1:65535",
      "http://127.0.0.1:80/?a",
    ]) {
      await reach(new Request(url));
    }
    // Everything else, however near it looks: HTTPS to this machine, another loopback address or
    // name, a name that begins as the address does.
    const others = [
      "https://127.0.0.1:4001/x",
      "https://elsewhere.example/oip/v1/x",
      "http://127.0.0.2:4001/x",
      "http://localhost:4001/x",
      "http://[::1]:4001/x",
      "http://127.0.0.1.example:4001/x",
      "http://10.0.0.1:4001/x",
    ];
    for (const url of others) await reach(new Request(url));
    expect(asked.filter((line) => line.startsWith("plain"))).toStrictEqual([
      "plain http://127.0.0.1:4001/oip/v1/x",
      "plain http://127.0.0.1:65535/",
      // The port a URL need not say is not said.
      "plain http://127.0.0.1/?a",
    ]);
    expect(asked.filter((line) => line.startsWith("guarded"))).toHaveLength(others.length);
    // With the two composed as a gateway composes them, a routed origin is reached and no other is asked plainly.
    asked.length = 0;
    const whole = routed({ "https://host.oip.localhost": "http://127.0.0.1:4001" }, reach);
    await whole(new Request("https://host.oip.localhost/in", { method: "POST", body: "sent" }));
    await whole(new Request("https://10.1.2.3:8443/internal/admin/inbox", { method: "POST" }));
    expect(asked).toStrictEqual([
      "plain http://127.0.0.1:4001/in",
      "guarded https://10.1.2.3:8443/internal/admin/inbox",
    ]);
  });
});
