// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import { contentId, keyHash, OipError, type Signer } from "@oip/core";
import { clause } from "@oip/testkit";
import { describe, expect, it } from "vitest";

import {
  draftFork,
  draftGenesis,
  draftRetire,
  draftUpdate,
  latestState,
  signEvent,
  signEventSync,
  verifyLog,
} from "../src/index.ts";
import { bookOf, KeyMind, LATER, signer, T, witness } from "@oip/testkit/minds";

const control = [signer("c0"), signer("c1"), signer("c2"), signer("c3")] as const;
const commit = (n: number) => [keyHash((control[n] ?? control[0]).publicKey)];

describe(`${clause("L1 3.6", "L1 3.7", "L1 3.8", "L1 3.10")} writing the four events`, () => {
  it("writes a log that verifies, each event chained to the one before", () => {
    const genesis = signEventSync(
      draftGenesis(T(0), {
        kind: "service",
        controller: { keys: [control[0].publicKey], next: commit(1) },
        keys: [{ key: signer("operational").publicKey, label: "server" }],
      }),
      [{ control: control[0] }],
    );
    const events: object[] = [genesis];
    const head = () => {
      const log = verifyLog(events, { evidence: witness([events as never]), asOf: LATER });
      if (!log.ok) throw new Error(JSON.stringify(log.issues));
      return latestState(log.value);
    };
    events.push(
      signEventSync(
        draftUpdate(head(), T(10), {
          controller: { keys: [control[1].publicKey], next: commit(2) },
          homes: ["https://service.example"],
        }),
        [{ control: control[1] }],
      ),
    );
    const child = new KeyMind("child").address;
    events.push(
      signEventSync(
        draftFork(head(), T(20), {
          controller: { keys: [control[2].publicKey], next: commit(3) },
          child,
        }),
        [{ control: control[2] }],
      ),
    );
    events.push(
      signEventSync(
        draftRetire(head(), T(30), {
          controller: { keys: [control[3].publicKey], next: [] },
          reason: "replaced",
        }),
        [{ control: control[3] }],
      ),
    );
    const state = head();
    expect(state).toMatchObject({ seq: 3, retired: true, homes: ["https://service.example"] });
    const log = verifyLog(events, { evidence: witness([events as never]), asOf: LATER });
    expect(log.ok && log.value.children).toEqual([{ position: 2, child }]);
    expect(events.map((event) => (event as { type: string }).type)).toEqual([
      "Genesis",
      "Update",
      "Fork",
      "Retire",
    ]);
  });

  it(`${clause("L1 3.2")} takes mind, seq and prev from the log, whatever the author passes`, () => {
    const ada = new KeyMind("ada").update(10);
    const log = bookOf([ada]).log(ada.address);
    if (!log.ok) throw new Error("the log does not verify");
    const state = latestState(log.value);
    const chain = { mind: ada.address, seq: 2, prev: contentId(ada.events[1]) };
    const sneaky = { mind: "did:oip:other", seq: 9, prev: "x", type: "Genesis", oip: "2" };
    expect(draftUpdate(state, T(20), sneaky as never)).toEqual({
      oip: "1",
      type: "Update",
      created: T(20),
      ...chain,
    });
    expect(draftFork(state, T(20), { child: ada.address })).toMatchObject({
      ...chain,
      type: "Fork",
    });
    expect(draftRetire(state, T(20))).toEqual({
      oip: "1",
      type: "Retire",
      created: T(20),
      ...chain,
    });
    // Only the head of the log is needed, not the whole state.
    expect(
      draftUpdate({ mind: state.mind, seq: state.seq, head: state.head }, T(20)),
    ).toMatchObject(chain);
    const genesis = draftGenesis(T(0), {
      kind: "agent",
      controller: { keys: [control[0].publicKey], next: [] },
      ...({ type: "Update", oip: "2", created: T(9) } as object),
    });
    expect(genesis).toMatchObject({ oip: "1", type: "Genesis", created: T(0) });
    expect(genesis).not.toHaveProperty("proof");
  });
});

describe(`${clause("L1 3.11", "core 6.2")} signing an event`, () => {
  const draft = draftGenesis(T(0), {
    kind: "agent",
    controller: { keys: [control[0].publicKey], next: [] },
  });

  it("signs for a control key with its own control-key-ref, and for a member with a key-ref", async () => {
    const member = new KeyMind("member");
    const signed = signEventSync(draft, [{ control: control[0] }, member.asMember()], T(5));
    expect(
      signed.proof.map(({ verificationMethod, proofPurpose, created }) => ({
        verificationMethod,
        proofPurpose,
        created,
      })),
    ).toEqual([
      {
        verificationMethod: `did:key:${control[0].publicKey}#${control[0].publicKey}`,
        proofPurpose: "capabilityInvocation",
        created: T(5),
      },
      {
        verificationMethod: `${member.address}?versionId=${member.versionId()}#${member.invocation().publicKey}`,
        proofPurpose: "capabilityInvocation",
        created: T(5),
      },
    ]);
    // A proof is dated as its event unless the signer says otherwise.
    expect(signEventSync(draft, [{ control: control[0] }]).proof[0]?.created).toBe(T(0));
    // A signer that answers later signs the same bytes.
    const slow: Signer = {
      publicKey: control[0].publicKey,
      sign: (message) => Promise.resolve(control[0].sign(message)),
    };
    expect(await signEvent(draft, [{ control: slow }, member.asMember()], T(5))).toEqual(signed);
    expect((await signEvent(draft, [{ control: slow }])).proof[0]?.created).toBe(T(0));
  });

  it("leaves the event itself as it was: the proofs cover it without them", () => {
    const signed = signEventSync(draft, [{ control: control[0] }]);
    const { proof: _, ...rest } = signed;
    expect(rest).toEqual(draft);
    expect(contentId(signed)).toBe(contentId(draft));
  });

  it("refuses to sign with no signer, and asks no signer to sign a malformed event", async () => {
    expect(() => signEventSync(draft, [])).toThrow(
      new TypeError("an identity event is signed by at least one signer"),
    );
    await expect(signEvent(draft, [])).rejects.toThrow(TypeError);
    let asked = 0;
    const counting = {
      publicKey: control[0].publicKey,
      sign: (message: Uint8Array) => {
        asked++;
        return control[0].sign(message);
      },
    };
    const malformed = { ...draft, kind: "" };
    expect(() => signEventSync(malformed, [{ control: counting }])).toThrow(OipError);
    await expect(signEvent(malformed, [{ control: counting }])).rejects.toThrow(OipError);
    expect(asked).toBe(0);
  });
});
