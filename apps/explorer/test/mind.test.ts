// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind as the Explorer shows it, made of what a stranger resolves on a
 * real resolver, host and indexer on ports of this machine.
 */

import { LOCAL } from "@oip/cli";
import { formatTimestamp } from "@oip/core";
import { clause } from "@oip/testkit";
import { type Player, Stage } from "@oip/translation-demo";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { mindView } from "../src/oip/mind.ts";

let stage: Stage;
let amina: Player;
let first: string;
let added: string;

beforeAll(async () => {
  stage = await Stage.open();
  amina = await stage.cast("amina", "human", { name: "Amina", summary: "A person." });
  [first = ""] = amina.mind.state.keys;
  // A second key, and then the first is given up: three events, and two stretches of keys.
  added = await amina.mind.addKey({ control: amina.lock, label: "laptop" });
  await amina.mind.revokeKey(first, { control: amina.lock });
});
afterAll(async () => {
  await stage.close();
});

describe("a mind, as a page shows it", () => {
  it(`${clause("L1 3.2", "core 9.5")} has its log as a line of events, each with its place, its content ID and when it took effect`, async () => {
    const view = mindView(await stage.stranger().resolve(amina.mind.address));
    expect(view).toMatchObject({
      address: amina.mind.address,
      kind: "human",
      controller: "key",
      retired: false,
      duplicitous: false,
    });
    expect(view.events.map(({ seq, type }) => [seq, type])).toStrictEqual([
      [0, "Genesis"],
      [1, "Update"],
      [2, "Update"],
    ]);
    const [genesis, adding, removing] = view.events;
    expect(view.address).toBe(`did:oip:${genesis?.id ?? ""}`);
    for (const event of view.events) {
      expect(event.id).toMatch(/^bciq[a-z2-7]{52}$/u);
      // The evaluation time is never before what the author says, and never decreases.
      expect(Date.parse(event.evaluated)).toBeGreaterThanOrEqual(Date.parse(event.created));
    }
    expect(Date.parse(removing?.evaluated ?? "")).toBeGreaterThanOrEqual(
      Date.parse(adding?.evaluated ?? ""),
    );
    expect(genesis?.changes).toContainEqual({ says: "adds the operational key", code: [first] });
    expect(genesis?.changes).toContainEqual({ says: "names its homes:", code: [LOCAL.host] });
    const next = {
      says: "commits to 1 control key for the next event, of which 1 must sign it",
    };
    expect(genesis?.changes).toContainEqual(next);
    expect(adding?.changes).toStrictEqual([
      { says: "adds the operational key", code: [added] },
      next,
    ]);
    // The key is given up for good: the event lists it as revoked, and names no time of compromise.
    expect(removing?.changes).toStrictEqual([
      { says: "revokes the operational key", code: [first] },
      next,
    ]);
  });

  it(`${clause("L1 4.1", "L1 4.3")} says of each event who signed it, by what the log's rules ask: which the client verified, or it gave no log`, async () => {
    const { log } = await stage.stranger().resolve(amina.mind.address);
    const view = mindView(await stage.stranger().resolve(amina.mind.address));
    const [genesis, adding] = view.events;
    const revealed = (position: number): string[] =>
      (log.entries[position]?.event as { controller?: { keys?: string[] } }).controller?.keys ?? [];
    expect(revealed(0)).toHaveLength(1);
    expect(genesis?.signed).toStrictEqual({
      says: "Signed by each control key it names:",
      code: revealed(0),
    });
    expect(adding?.signed).toStrictEqual({
      says: "Signed by each control key it reveals, which the event before had committed to:",
      code: revealed(1),
    });
    // A control key signs one event: the next is signed by the key that event committed to.
    expect(revealed(1)).not.toStrictEqual(revealed(0));
    // Nothing is counted from the proofs an event carries, which anyone can add to.
    expect(JSON.stringify(view.events)).not.toMatch(/"proofs"/u);
    expect(view.next).toStrictEqual({ keys: 1, threshold: 1 });
    expect(view.members).toBeUndefined();
  });

  it(`${clause("L1 6.1", "core 9.3")} has each key with the stretch of the log in which it is the mind's`, async () => {
    const view = mindView(await stage.stranger().resolve(amina.mind.address));
    const operational = view.keys.filter(({ role }) => role === "operational");
    expect(operational).toStrictEqual([
      {
        key: first,
        role: "operational",
        since: 0,
        sinceTime: view.events[0]?.evaluated,
        ended: { time: view.events[2]?.evaluated, why: "removed", event: 2 },
        never: false,
      },
      {
        key: added,
        role: "operational",
        since: 1,
        sinceTime: view.events[1]?.evaluated,
        never: false,
      },
    ]);
    // A mind that can be written to has a key to seal to, from its genesis on.
    expect(view.keys.filter(({ role }) => role === "agreement")).toMatchObject([{ since: 0 }]);
    expect(view.keys.find(({ role }) => role === "agreement")?.ended).toBeUndefined();
  });

  it(`${clause("L1 7.3")} closes a key that an event of another branch of the log removed, though the log as shown still has it`, async () => {
    const resolved = await stage.stranger().resolve(amina.mind.address);
    const [genesis, adding, removing] = resolved.log.entries;
    if (adding === undefined || removing === undefined) throw new Error("the log has three events");
    // The log as a verifier holds it where two events stand at place 2: it ends before them, and
    // the events of each branch are kept apart, for what they remove.
    const view = mindView({
      ...resolved,
      duplicitous: true,
      state: adding.state,
      log: {
        ...resolved.log,
        entries: [genesis, adding],
        duplicitous: true,
        branchTails: [removing],
      },
    });
    expect(view.events).toHaveLength(2);
    expect(view.keys.find(({ key }) => key === first)).toStrictEqual({
      key: first,
      role: "operational",
      since: 0,
      sinceTime: view.events[0]?.evaluated,
      // No event of the log as shown is named: the one that removed it is on a branch.
      ended: { time: formatTimestamp(removing.time), why: "branch" },
      never: false,
    });
    expect(view.keys.find(({ key }) => key === added)?.ended).toBeUndefined();
  });

  it(`${clause("L1 6.1", "L1 6.2")} says of a key the mind declares compromised from when, and that none of its signatures counts from then on`, async () => {
    const wanjiru = await stage.cast("wanjiru", "human", { name: "Wanjiru" });
    const [stolen = ""] = wanjiru.mind.state.keys;
    const kept = await wanjiru.mind.addKey({ control: wanjiru.lock, label: "new" });
    // Stolen an hour ago, she says: before the key was hers on this network at all.
    const since = `${new Date(Date.now() - 3_600_000).toISOString().slice(0, 19)}Z`;
    await wanjiru.mind.revokeKey(stolen, { control: wanjiru.lock, compromisedSince: since });
    const view = mindView(await stage.stranger().resolve(wanjiru.mind.address));
    const [, , revoking] = view.events;
    expect(revoking?.changes).toContainEqual({
      says: "revokes the operational key",
      code: [stolen],
      more: `, and declares it compromised since ${since}`,
    });
    const byKey = new Map(
      view.keys.filter(({ role }) => role === "operational").map((key) => [key.key, key]),
    );
    expect(byKey.get(stolen)).toStrictEqual({
      key: stolen,
      role: "operational",
      since: 0,
      sinceTime: view.events[0]?.evaluated,
      ended: { time: view.events[2]?.evaluated, why: "removed", event: 2 },
      compromisedSince: since,
      // The time she names is before the key's stretch began: no signature by it counts at all.
      never: true,
    });
    expect(byKey.get(kept)).toMatchObject({ never: false });
    expect(byKey.get(kept)?.compromisedSince).toBeUndefined();
    expect(byKey.get(kept)?.ended).toBeUndefined();

    // A key stolen while it was hers keeps what it signed before.
    const later = await stage.cast("njeri", "human", { name: "Njeri" });
    const [lost = ""] = later.mind.state.keys;
    await later.mind.addKey({ control: later.lock, label: "new" });
    const now = `${new Date(Date.now() + 1000).toISOString().slice(0, 19)}Z`;
    await later.mind.revokeKey(lost, { control: later.lock, compromisedSince: now });
    const other = mindView(await stage.stranger().resolve(later.mind.address));
    expect(other.keys.find(({ key }) => key === lost)).toMatchObject({
      compromisedSince: now,
      never: false,
    });
  });

  it(`${clause("L1 3.10", "L1 6.1")} closes every key of a mind that retired, at the event that retired it`, async () => {
    const gone = await stage.cast("gone", "agent", { name: "An agent that retired" });
    const [signing = ""] = gone.mind.state.keys;
    const reason = `Replaced.${String.fromCodePoint(0x202e)}`;
    await gone.mind.retire({
      control: gone.lock,
      successor: amina.mind.address,
      reason: `${reason}${"x".repeat(400)}`,
    });
    const view = mindView(await stage.stranger().resolve(gone.mind.address));
    expect(view).toMatchObject({ retired: true, next: { keys: 0, threshold: 0 } });
    const [, retiring] = view.events;
    expect(retiring?.type).toBe("Retire");
    expect(retiring?.changes).toStrictEqual([
      { says: "commits to no control key for a next event: the log can never be extended" },
      { says: "retires the mind: it signs nothing more" },
      { says: "names its successor:", code: [amina.mind.address] },
      // Its own words, cut to a length. A page shows them as any stranger's text.
      {
        says: "gives as its reason, in its own words:",
        code: [`${reason}${"x".repeat(256 - Array.from(reason).length)}…`],
      },
    ]);
    // No key is "still the mind's".
    expect(view.keys.length).toBeGreaterThanOrEqual(2);
    for (const key of view.keys) {
      expect(key.ended, key.role).toStrictEqual({
        time: retiring?.evaluated,
        why: "retired",
        event: 1,
      });
    }
    expect(view.keys.map(({ key }) => key)).toContain(signing);
  });

  it(`${clause("L1 5.3")} has the other names a log lists as the mind's own word, and says when it listed them`, async () => {
    const lexis = await stage.cast("lexis", "institution", { name: "Lexis Ltd" });
    expect(mindView(await stage.stranger().resolve(lexis.mind.address)).alsoKnownAs).toStrictEqual(
      [],
    );
    const aliases = ["https://www.gov.uk", "dns:lexis.example"];
    await lexis.mind.update({ alsoKnownAs: aliases }, { control: lexis.lock });
    const view = mindView(await stage.stranger().resolve(lexis.mind.address));
    expect(view.alsoKnownAs).toStrictEqual(aliases);
    expect(view.events[1]?.changes).toContainEqual({
      says: "says it is also known as",
      code: aliases,
      more: ", which nobody has checked here",
    });
    await lexis.mind.update({ alsoKnownAs: [] }, { control: lexis.lock });
    const after = mindView(await stage.stranger().resolve(lexis.mind.address));
    expect(after.events[2]?.changes).toContainEqual({
      says: "lists no other name for itself any more",
    });
  });

  it(`${clause("L1 4.1", "L1 4.4")} has a collective with its members and its threshold, and no key of its own`, async () => {
    const [a, b, c] = await Promise.all(
      ["one", "two", "three"].map((name) => stage.cast(name, "agent", { name })),
    );
    if (a === undefined || b === undefined || c === undefined) throw new Error("no cast");
    const members = [a.mind.address, b.mind.address, c.mind.address];
    let founding = await a.mind.foundCollective(
      { members, threshold: 2, homes: [LOCAL.host] },
      { invocation: a.lock },
    );
    founding = await b.mind.signEvent(founding, { invocation: b.lock });
    founding = await c.mind.signEvent(founding, { invocation: c.lock });
    const collective = (await a.mind.publishLog([founding])).mind;
    const view = mindView(await stage.stranger().resolve(collective));
    expect(view).toMatchObject({
      controller: "member",
      members: { minds: members, threshold: 2 },
      keys: [],
    });
    expect(view.next).toBeUndefined();
    expect(view.events).toHaveLength(1);
    expect(view.events[0]?.signed).toStrictEqual({
      says: "Signed by each of its founding members:",
      code: members,
    });
    expect(view.events[0]?.changes).toContainEqual({
      says: "has 3 members, of which 2 must sign each later event:",
      code: members,
    });
  });

  it(`${clause("L1 15.2", "L1 16.4")} has no location and no profile that a key since given up signed, until the mind says them again`, async () => {
    // Both were signed by the first key, which is the mind's no longer: they describe the
    // present, and count only while their signer does.
    const stale = mindView(await stage.stranger().resolve(amina.mind.address));
    expect(stale.location).toBeUndefined();
    expect(stale.profile).toBeUndefined();
    await amina.mind.publishLocation();
    await amina.mind.publishProfile({ name: "Amina", summary: "A person." });
    const view = mindView(await stage.stranger().resolve(amina.mind.address));
    expect(view.profile?.record).toMatchObject({
      type: "Participant",
      name: "Amina",
      summary: "A person.",
      kind: "human",
    });
    expect(view.location).toMatchObject({ stale: false, record: { type: "Location" } });
  });

  it(`${clause("L1 5.1")} has the DID document, the mind's homes, and what each resolver answered`, async () => {
    const view = mindView(await stage.stranger().resolve(amina.mind.address));
    expect(view.didDocument).toMatchObject({ id: amina.mind.address });
    expect(view.homes).toHaveLength(1);
    expect(view.alsoKnownAs).toStrictEqual([]);
    expect(view.sources).toHaveLength(1);
    expect(view.sources[0]?.failure).toBeUndefined();
  });
});
