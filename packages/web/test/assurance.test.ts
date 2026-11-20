// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** Assurance levels (Layer 0, 1.3): a mind a gateway acts for, shown or only said. */

import { contentId, formatRecordRef } from "@oip/core";
import { type DelegationContext, RecordSet } from "@oip/delegation";
import { type JudgedRecord, judgeRecord } from "@oip/identity";
import { clause, type JsonObject } from "@oip/testkit";
import { bookOf, KeyMind, type Mind, T } from "@oip/testkit/minds";
import { describe, expect, it } from "vitest";

import { assuranceOf, BRIDGE_BLOCK } from "../src/index.ts";

const judged = (record: object): JudgedRecord => {
  const result = judgeRecord(record);
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
};

type Blocks = Record<string, Record<string, unknown>>;

/** The block a bridged mind names its gateway in. */
const block = (gateway: Mind, more: JsonObject = {}): Blocks => ({
  [BRIDGE_BLOCK]: {
    protocol: "a2a",
    endpoint: "https://agent.example/a2a",
    gateway: gateway.address,
    assurance: "bridged",
    ...more,
  },
});

const gateway = new KeyMind("gateway");
const other = new KeyMind("another gateway");
/** A mind the gateway made for an agent that is not on the network. */
const agent = new KeyMind("agent", 0, { kind: "service", ext: block(gateway) });
/** A mind with nothing of a bridge about it. */
const plain = new KeyMind("plain");
const minds = [gateway, other, agent, plain];

/** An entry of a mind's feed that names an object. */
const entry = (author: Mind, object: string, objectType: string, signer: Mind = author) =>
  signer.sign({
    oip: "1",
    type: "Entry",
    author: author.address,
    seq: 0,
    created: T(5),
    object,
    objectType,
  });

const genesisOf = (mind: Mind): string => contentId(mind.events[0]);

/** The gateway's own word that the agent's mind is one it bridges. */
const attestation = entry(gateway, genesisOf(agent), "Genesis");

/** A profile of a mind, signed by it, with the extension blocks given. */
const profile = (of: Mind, ext?: Blocks, signer: Mind = of, kind = "service") =>
  signer.sign({
    oip: "1",
    type: "Participant",
    author: of.address,
    created: T(10),
    name: of.name,
    kind,
    ...(ext === undefined ? {} : { ext }),
  });

const refTo = (author: Mind, record: object): string =>
  formatRecordRef(author.address, contentId(record));

/** What a verifier holds: the logs of the minds, and these records, each seen when it was signed. */
function holding(records: readonly object[]): DelegationContext {
  const set = new RecordSet();
  for (const record of records) set.add(record);
  return { identity: bookOf(minds, records), records: set };
}

/** The level of a profile, for a verifier that holds it and these records besides. */
const level = (of: object, records: readonly object[] = []): string =>
  assuranceOf(judged(of), holding([of, ...records]));

/** The agent's profile, naming an attestation. */
const bridged = (attested: object = attestation, more: JsonObject = {}): object =>
  profile(agent, block(gateway, { attestation: refTo(gateway, attested), ...more }));

describe(`${clause("L0 1.3")} the assurance level of a mind`, () => {
  it("is `native` where no gateway has declared the mind bridged", () => {
    expect(level(profile(plain, undefined, plain, "agent"))).toBe("native");
    // Other extensions say nothing of a bridge.
    expect(level(profile(plain, { "com.example": { note: "hello" } }, plain, "agent"))).toBe(
      "native",
    );
    // It is the default, and says no more: a profile that omits the block is not found out
    // by its mind's genesis.
    expect(level(profile(agent), [attestation])).toBe("native");
  });

  it(`${clause("L0 1.2")} is \`bridged\` where the genesis and the profile name a gateway, and an entry of that gateway's feed names the genesis`, () => {
    expect(level(bridged(), [attestation])).toBe("bridged");
  });

  it("is `claimed` where the entry is not held: nothing shows the gateway said so", () => {
    expect(level(bridged())).toBe("claimed");
  });

  it("is `claimed` where the profile names no attestation, or what it names is no reference", () => {
    expect(level(profile(agent, block(gateway)), [attestation])).toBe("claimed");
    for (const named of ["", "the gateway said so", contentId(attestation), 7, null]) {
      expect(
        level(profile(agent, block(gateway, { attestation: named })), [attestation]),
        JSON.stringify(named),
      ).toBe("claimed");
    }
  });

  it("is `claimed` where the mind attests itself: the entry is its own, and not the gateway's", () => {
    const own = entry(agent, genesisOf(agent), "Genesis");
    expect(level(bridged(own), [own])).toBe("claimed");
  });

  it("is `claimed` where the entry is not signed by the gateway whose it says it is", () => {
    const forged = entry(gateway, genesisOf(agent), "Genesis", agent);
    expect(level(bridged(forged), [forged])).toBe("claimed");
  });

  it("is `claimed` where the entry is for another genesis, or names the genesis as something else", () => {
    const elsewhere = entry(gateway, genesisOf(plain), "Genesis");
    expect(level(bridged(elsewhere), [elsewhere])).toBe("claimed");
    const mistyped = entry(gateway, genesisOf(agent), "Participant");
    expect(level(bridged(mistyped), [mistyped])).toBe("claimed");
  });

  it("is `claimed` where what the profile names is the gateway's, and is no entry", () => {
    const intent = gateway.sign({
      oip: "1",
      type: "Intent",
      author: gateway.address,
      created: T(5),
      want: "To be taken for an attestation",
    });
    expect(level(bridged(intent), [intent])).toBe("claimed");
  });

  it("is `claimed` where the profile names a gateway the genesis does not", () => {
    // Another gateway attests the mind, and the profile names that one. The genesis names the first.
    const theirs = entry(other, genesisOf(agent), "Genesis");
    expect(
      level(profile(agent, block(other, { attestation: refTo(other, theirs) })), [theirs]),
    ).toBe("claimed");
    // A mind that was made with no block cannot be made a bridged mind by its profile.
    const late = entry(gateway, genesisOf(plain), "Genesis");
    expect(
      level(profile(plain, block(gateway, { attestation: refTo(gateway, late) }), plain, "agent"), [
        late,
      ]),
    ).toBe("claimed");
  });

  it("is `claimed` where the profile is not its mind's own", () => {
    const forged = profile(
      agent,
      block(gateway, { attestation: refTo(gateway, attestation) }),
      plain,
    );
    expect(level(forged, [attestation])).toBe("claimed");
  });

  it("is `claimed` where the block names no gateway", () => {
    const named = { attestation: refTo(gateway, attestation) };
    for (const said of [{}, named, { ...named, gateway: 7 }, { ...named, gateway: null }]) {
      expect(
        level(profile(agent, { [BRIDGE_BLOCK]: said }), [attestation]),
        JSON.stringify(said),
      ).toBe("claimed");
    }
    // A block that is no object is no record at all (core 8.1): there is nothing to ask of.
    expect(
      judgeRecord({ ...(bridged() as JsonObject), ext: { [BRIDGE_BLOCK]: "bridged" } }).ok,
    ).toBe(false);
  });

  it("is `claimed` for a verifier that does not hold the mind's log", () => {
    const set = new RecordSet();
    set.add(attestation);
    const record = bridged();
    set.add(record);
    const context = { identity: bookOf([gateway], [record, attestation]), records: set };
    expect(assuranceOf(judged(record), context)).toBe("claimed");
  });

  it(`${clause("L0 1.5")} lets several gateways bridge one system: each mind is bridged by its own`, () => {
    const second = new KeyMind("the same agent, by another gateway", 0, {
      kind: "service",
      ext: block(other),
    });
    const theirs = entry(other, genesisOf(second), "Genesis");
    const record = profile(second, block(other, { attestation: refTo(other, theirs) }));
    const set = new RecordSet();
    for (const held of [record, theirs, attestation]) set.add(held);
    const context = {
      identity: bookOf([...minds, second], [record, theirs, attestation]),
      records: set,
    };
    expect(assuranceOf(judged(record), context)).toBe("bridged");
    expect(assuranceOf(judged(bridged()), { ...context, records: set })).toBe("claimed");
  });
});
