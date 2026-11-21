// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A mind as the Explorer shows it, made of what a stranger resolves on a
 * real resolver, host and indexer on ports of this machine.
 */

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
      expect(event.proofs).toBeGreaterThan(0);
      // The evaluation time is never before what the author says, and never decreases.
      expect(Date.parse(event.evaluated)).toBeGreaterThanOrEqual(Date.parse(event.created));
    }
    expect(Date.parse(removing?.evaluated ?? "")).toBeGreaterThanOrEqual(
      Date.parse(adding?.evaluated ?? ""),
    );
    expect(genesis?.changes).toContain(`adds the operational key ${first}`);
    expect(genesis?.changes.some((change) => change.startsWith("names its homes: https://"))).toBe(
      true,
    );
    expect(adding?.changes).toStrictEqual([`adds the operational key ${added}`]);
    expect(removing?.changes).toStrictEqual([`removes the operational key ${first}`]);
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
        until: 2,
        untilTime: view.events[2]?.evaluated,
      },
      { key: added, role: "operational", since: 1, sinceTime: view.events[1]?.evaluated },
    ]);
    // A mind that can be written to has a key to seal to, from its genesis on.
    expect(view.keys.filter(({ role }) => role === "agreement")).toMatchObject([{ since: 0 }]);
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
