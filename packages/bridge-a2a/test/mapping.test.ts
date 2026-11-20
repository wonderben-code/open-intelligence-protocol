// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/** What a thing of A2A is in OIP, and the other way round (Layer 0, 3.1 and 3.2). */

import { judgeRecord } from "@oip/identity";
import { clause } from "@oip/testkit";
import { KeyMind, T } from "@oip/testkit/minds";
import { validateRecordOfType } from "@oip/schema";
import type { Participant } from "@oip/schema";
import { describe, expect, it } from "vitest";

import {
  type AgentCard,
  capabilitiesOf,
  cardFor,
  isTerminal,
  OIP_EXTENSION,
  readCard,
  saidOf,
  TASK_STATES,
} from "../src/index.ts";

const card = (skills: AgentCard["skills"]): AgentCard => ({
  name: "An agent",
  description: "It does things.",
  version: "1.0.0",
  supportedInterfaces: [
    { url: "https://agent.example/a2a", protocolBinding: "JSONRPC", protocolVersion: "1.0" },
  ],
  skills,
  extensions: [],
  defaultInputModes: ["text/plain"],
  defaultOutputModes: ["text/plain"],
  signatures: [],
});

const skill = (id: string, more: Partial<AgentCard["skills"][number]> = {}) => ({
  id,
  name: "Translate",
  description: "Translates a lease from Swahili to English.",
  tags: ["translation", "legal"],
  ...more,
});

describe(`${clause("L0 3.1")} the skills of an Agent Card`, () => {
  it("are the capabilities of the bridged mind: the skill's id, its own words, and its tags under a namespace", () => {
    expect(capabilitiesOf(card([skill("translate")]))).toStrictEqual([
      {
        id: "translate",
        summary: "Translate: Translates a lease from Swahili to English.",
        tags: ["a2a:translation", "a2a:legal"],
      },
    ]);
    // A skill whose name says all there is has it once, and one without tags has none.
    expect(
      capabilitiesOf(card([skill("echo", { name: "Echo", description: "Echo", tags: [] })])),
    ).toStrictEqual([{ id: "echo", summary: "Echo" }]);
  });

  it("make a profile that is one: no two capabilities of one id, none with an id too long to carry", () => {
    const capabilities = capabilitiesOf(
      card([
        skill("a"),
        skill("a", { name: "The same again" }),
        skill("x".repeat(129)),
        skill("b", { tags: ["one", "one", "two"] }),
        skill("c", { description: "y".repeat(5000) }),
      ]),
    );
    expect(capabilities.map(({ id }) => id)).toStrictEqual(["a", "b", "c"]);
    expect(capabilities[0]?.summary).toMatch(/^Translate: /u);
    expect(capabilities[1]?.tags).toStrictEqual(["a2a:one", "a2a:two"]);
    expect(capabilities[2]?.summary).toHaveLength(1024);
    // A profile takes them: its schema, and the rule that no two share an id (Layer 1, 16.2).
    const mind = new KeyMind("a bridged agent", 0, { kind: "service" });
    const signed = mind.sign({
      oip: "1",
      type: "Participant",
      author: mind.address,
      created: T(10),
      name: "An agent",
      kind: "service",
      capabilities,
    });
    const profile = validateRecordOfType("Participant", signed);
    expect(profile.ok ? [] : profile.issues).toStrictEqual([]);
    expect(judgeRecord(signed).ok).toBe(true);
  });

  it("are no more than a profile carries", () => {
    const many = Array.from({ length: 300 }, (_, n) =>
      skill(`s${String(n)}`, { tags: Array.from({ length: 100 }, (__, t) => `t${String(t)}`) }),
    );
    const capabilities = capabilitiesOf(card(many));
    expect(capabilities).toHaveLength(256);
    expect(capabilities[0]?.tags).toHaveLength(64);
  });
});

describe(`${clause("L0 3.2")} the Agent Card of an OIP mind`, () => {
  const profile = {
    oip: "1",
    type: "Participant",
    author: `did:oip:bciqa${"a".repeat(50)}a`,
    created: "2026-11-20T00:00:00Z",
    name: "Lexis translation agent",
    kind: "agent",
    summary: "Translates legal texts.",
    capabilities: [
      { id: "translate", summary: "Translates a lease", tags: ["domain:legal"] },
      { id: "review", summary: `Reviews a translation${", carefully".repeat(10)}` },
    ],
    proof: [],
  } as unknown as Participant;
  const served = { url: "https://gateway.example/a2a/lexis", version: "2026.11" };

  it("is generated from its profile: capabilities as skills, a summary as the name where it is short", () => {
    const made = cardFor(profile, served);
    expect(made).toMatchObject({
      name: "Lexis translation agent",
      description: "Translates legal texts.",
      version: "2026.11",
      supportedInterfaces: [
        {
          url: "https://gateway.example/a2a/lexis",
          protocolBinding: "JSONRPC",
          protocolVersion: "1.0",
        },
      ],
      skills: [
        {
          id: "translate",
          name: "Translates a lease",
          description: "Translates a lease",
          tags: ["domain:legal"],
        },
        { id: "review", name: "review", tags: [] },
      ],
    });
    // A profile with no summary and no capabilities still makes a card.
    const { summary: _, capabilities: __, ...bare } = profile;
    expect(cardFor(bare as Participant, served)).toMatchObject({
      description: "Lexis translation agent",
      skills: [],
    });
  });

  it(`${clause("L0 3.3")} declares the OIP extension, by its URI`, () => {
    const made = cardFor(profile, served) as { capabilities: { extensions: { uri: string }[] } };
    expect(made.capabilities.extensions.map(({ uri }) => uri)).toStrictEqual([OIP_EXTENSION]);
    expect(OIP_EXTENSION).toBe(
      "https://github.com/wonderben-code/open-intelligence-protocol/blob/main/spec/layer-0-bridge.md#a2a-extension",
    );
  });

  it("is a card this gateway would itself read", () => {
    const made = readCard(new TextEncoder().encode(JSON.stringify(cardFor(profile, served))));
    if (!made.ok) throw new Error(JSON.stringify(made.issues));
    expect(made.value.card.skills).toHaveLength(2);
    expect(made.value.card.extensions).toStrictEqual([{ uri: OIP_EXTENSION, required: false }]);
  });
});

describe(`${clause("L0 3.1")} the state of a task`, () => {
  it("maps to a Receipt, a packet, or nothing yet, as the table says", () => {
    expect(Object.fromEntries(TASK_STATES.map((state) => [state, saidOf(state)]))).toStrictEqual({
      TASK_STATE_SUBMITTED: { as: "nothing" },
      TASK_STATE_WORKING: { as: "nothing" },
      TASK_STATE_COMPLETED: { as: "receipt", outcome: "fulfilled" },
      TASK_STATE_FAILED: { as: "receipt", outcome: "broken" },
      TASK_STATE_CANCELED: { as: "receipt", outcome: "cancelled" },
      TASK_STATE_INPUT_REQUIRED: { as: "packet", verb: "request" },
      TASK_STATE_REJECTED: { as: "packet", verb: "decline" },
      TASK_STATE_AUTH_REQUIRED: { as: "packet", verb: "request" },
    });
  });

  it(`${clause("L0 1.4")} has nothing said of it where the gateway does not know the state: it says what it observed, and no more`, () => {
    for (const state of [
      "TASK_STATE_UNSPECIFIED",
      "completed",
      "COMPLETED",
      "",
      3,
      null,
      undefined,
      {},
    ]) {
      expect(saidOf(state), JSON.stringify(state)).toStrictEqual({ as: "nothing" });
      expect(isTerminal(state)).toBe(false);
    }
  });

  it("is final where the task will change no more", () => {
    expect(TASK_STATES.filter((state) => isTerminal(state))).toStrictEqual([
      "TASK_STATE_COMPLETED",
      "TASK_STATE_FAILED",
      "TASK_STATE_CANCELED",
      "TASK_STATE_REJECTED",
    ]);
  });
});
