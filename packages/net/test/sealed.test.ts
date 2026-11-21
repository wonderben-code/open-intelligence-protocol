// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  bytesToBase64url,
  bytesToHex,
  canonicalBytes,
  contentId,
  encodeX25519Multikey,
  hexToBytes,
  hpkeOpen,
  hpkeSeal,
  sha256,
  utf8,
  x25519PublicKey,
} from "@oip/core";
import { judgeRecord, LogBook } from "@oip/identity";
import { validateRecord } from "@oip/schema";
import { clause, type JsonObject } from "@oip/testkit";
import { at, KeyMind, LATER, type Mind, T, witness } from "@oip/testkit/minds";
import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  draftAck,
  receiveSealed,
  type SealedOpener,
  type SealedReceiver,
  sealPacket,
} from "../src/index.ts";

type Signed = JsonObject & { proof: JsonObject[] };

const HOUR = 3_600_000_000_000n;

/** A private agreement key made from a name, as the test minds' other keys are. */
const secretOf = (name: string): Uint8Array => sha256(utf8(`${name}/agreement/secret`));
const publicOf = (name: string): string => encodeX25519Multikey(x25519PublicKey(secretOf(name)));

/** A mind whose agreement key is a real one, of which the test holds the private key. */
const withAgreement = (name: string, ...keys: string[]) =>
  new KeyMind(name, 0, {
    agreement: (keys.length > 0 ? keys : [publicOf(name)]).map((key) => ({ key })),
  });

const ada = new KeyMind("ada");
const bob = withAgreement("bob");
const cy = withAgreement("cy");
const everyone: Mind[] = [ada, bob, cy];

const RANDOM = new Uint8Array(32).fill(42);

const packetTo = (to: readonly Mind[], more: JsonObject = {}): Signed =>
  ada.sign({
    oip: "1",
    type: "Packet",
    from: ada.address,
    to: to.map((mind) => mind.address),
    created: T(10),
    expires: T(3610),
    nonce: "nonce-0001",
    purpose: { verb: "inform" },
    content: { mediaType: "text/plain", body: "For your eyes only." },
    ...more,
  });

function viewOf(minds: readonly Mind[] = everyone) {
  const seen = witness(minds.map((mind) => mind.events));
  const book = new LogBook(seen);
  for (const mind of minds) book.hold(mind.events, LATER);
  return { book, seen };
}

/** A receiver of sealed records that holds its own agreement key, at 20. */
function receiverOf(
  of: Mind,
  more: Partial<SealedReceiver> = {},
  minds: readonly Mind[] = everyone,
): SealedReceiver {
  const { book, seen } = viewOf(minds);
  return {
    address: of.address,
    now: at(20),
    view: book,
    seen,
    accepted: () => false,
    window: HOUR,
    agreementKey: (key) => (key === publicOf(of.name) ? secretOf(of.name) : undefined),
    ...more,
  };
}

async function sealFor(to: Mind, packet: unknown, randomness = RANDOM, minds = everyone) {
  const sealed = await sealPacket({ packet, to: to.address, view: viewOf(minds).book, randomness });
  if (!sealed.ok) throw new Error(JSON.stringify(sealed.issues));
  return sealed.value;
}

async function refusal(value: unknown, receiver: SealedReceiver) {
  const result = await receiveSealed(value, receiver);
  if (result.ok) throw new Error("the record was received");
  return { clause: result.issues[0].clause, path: result.issues[0].path };
}

/** What a hand-made plaintext seals to, for Bob, as a `Sealed` record. */
async function sealedOf(plaintext: Uint8Array, to: Mind = bob, aad = to.address) {
  const made = await hpkeSeal({
    recipientPublicKey: x25519PublicKey(secretOf(to.name)),
    info: utf8("oip/1 sealed"),
    aad: utf8(aad),
    plaintext,
    randomness: RANDOM,
  });
  if (made === undefined) throw new Error("not sealed");
  return {
    oip: "1",
    type: "Sealed",
    to: to.address,
    key: publicOf(to.name),
    suite: "hpke-base-x25519-sha256-chacha20poly1305",
    enc: bytesToBase64url(made.enc),
    ciphertext: bytesToBase64url(made.ciphertext),
  };
}

describe(`${clause("L1 12.6")} sealing a packet`, () => {
  const packet = packetTo([bob]);

  it("gives an unsigned Sealed record for the recipient, to one of its agreement keys", async () => {
    const sealed = await sealFor(bob, packet);
    expect(sealed).toMatchObject({
      oip: "1",
      type: "Sealed",
      to: bob.address,
      key: publicOf("bob"),
      suite: "hpke-base-x25519-sha256-chacha20poly1305",
    });
    expect(Object.keys(sealed).sort()).toStrictEqual(
      ["ciphertext", "enc", "key", "oip", "suite", "to", "type"].sort(),
    );
    // An encapsulated key of 32 bytes, and the packet with a tag of 16.
    expect(sealed.enc).toHaveLength(43);
    expect(sealed.ciphertext).toHaveLength(
      Math.ceil(((canonicalBytes(packet).length + 16) * 4) / 3),
    );
    expect(validateRecord(sealed).ok).toBe(true);
    // It shows whom it is for, and nothing of the packet.
    const shown = JSON.stringify(sealed);
    expect(shown).not.toContain(ada.address);
    expect(shown).not.toContain("eyes");
  });

  it("is the same record for the same randomness, and another for other randomness", async () => {
    const first = await sealFor(bob, packet);
    expect(await sealFor(bob, packet)).toStrictEqual(first);
    const other = await sealFor(bob, packet, new Uint8Array(32).fill(43));
    expect(other.enc).not.toBe(first.enc);
    expect(other.ciphertext).not.toBe(first.ciphertext);
  });

  it("seals a signed Packet, and nothing else", async () => {
    const view = viewOf().book;
    const seal = (value: unknown) =>
      sealPacket({ packet: value, to: bob.address, view, randomness: RANDOM });
    const { proof: _, ...unsigned } = packet;
    // A packet with no `proof` is no well-formed packet at all.
    expect(await seal(unsigned)).toMatchObject({ ok: false, issues: [{ path: "/packet" }] });
    const intent = ada.sign({
      oip: "1",
      type: "Intent",
      author: ada.address,
      created: T(5),
      want: "Privacy.",
    });
    expect(await seal(intent)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 12.6", path: "/packet/type" }],
    });
    // A proof that does not verify is no signature.
    const [proof] = packet.proof as [JsonObject];
    const broken = {
      ...packet,
      proof: [{ ...proof, proofValue: `${String(proof["proofValue"]).slice(0, -1)}z` }],
    };
    expect(await seal(broken)).toMatchObject({
      ok: false,
      issues: [{ clause: "L1 12.6", path: "/packet/proof" }],
    });
    for (const value of [undefined, null, 7, "packet", {}, []]) {
      expect((await seal(value)).ok, JSON.stringify(value)).toBe(false);
    }
  });

  it("seals to the first agreement key of the recipient's latest state that can be sealed to", async () => {
    // A key of small order comes first: nothing is sealed to it (RFC 9180, 7.1.4).
    const small = encodeX25519Multikey(
      hexToBytes("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    );
    const dan = withAgreement("dan", small, publicOf("dan"), publicOf("spare"));
    const sealed = await sealFor(dan, packetTo([dan]), RANDOM, [...everyone, dan]);
    expect(sealed.key).toBe(publicOf("dan"));
    // The latest state: a key the recipient has replaced is sealed to no longer.
    const eve = withAgreement("eve");
    eve.update(5, { agreement: [{ key: publicOf("eve-next") }] });
    const next = await sealFor(eve, packetTo([eve]), RANDOM, [...everyone, eve]);
    expect(next.key).toBe(publicOf("eve-next"));
  });

  it("seals to nobody who has no agreement key a packet can be sealed to", async () => {
    const small = encodeX25519Multikey(new Uint8Array(32));
    const none = new KeyMind("none", 0, { agreement: [] });
    const weak = withAgreement("weak", small);
    const minds = [...everyone, none, weak];
    const view = viewOf(minds).book;
    for (const mind of [none, weak]) {
      const sealed = await sealPacket({
        packet: packetTo([mind]),
        to: mind.address,
        view,
        randomness: RANDOM,
      });
      expect(sealed, mind.name).toMatchObject({
        ok: false,
        issues: [{ clause: "L1 12.6", path: "/to" }],
      });
    }
    // A recipient whose log the sender does not hold has no keys the sender knows.
    const stranger = withAgreement("stranger");
    const unknown = await sealPacket({
      packet: packetTo([stranger]),
      to: stranger.address,
      view,
      randomness: RANDOM,
    });
    expect(unknown.ok).toBe(false);
  });

  it("takes 32 bytes of randomness from the caller, and draws none", async () => {
    const view = viewOf().book;
    for (const randomness of [new Uint8Array(31), new Uint8Array(33), undefined, "random"]) {
      await expect(
        sealPacket({ packet, to: bob.address, view, randomness: randomness as never }),
      ).rejects.toThrow(TypeError);
      // Whatever the packet: the mistake is the caller's, and is not hidden behind a rejection.
      await expect(
        sealPacket({ packet: null, to: bob.address, view, randomness: randomness as never }),
      ).rejects.toThrow(TypeError);
    }
  });
});

describe(`${clause("L1 12.6", "L1 12.4")} receiving a sealed packet`, () => {
  const packet = packetTo([bob]);

  it("opens the record and judges the packet inside as any packet that arrives", async () => {
    const sealed = await sealFor(bob, packet);
    const result = await receiveSealed(sealed, receiverOf(bob));
    if (!result.ok) throw new Error(JSON.stringify(result.issues));
    expect(result.value.id).toBe(contentId(packet));
    expect(result.value.sealed).toBe(contentId(sealed));
    expect(result.value.packet.from).toBe(ada.address);
    expect(result.value.time).toBe(at(20));
    expect(result.value.duplicate).toBe(false);
    // The acknowledgement names the packet, and the Sealed record it arrived in (13.2).
    const ack = draftAck({
      received: result.value,
      recipient: bob.address,
      at: T(20),
      created: T(21),
      sealed: result.value.sealed,
    });
    expect(ack).toMatchObject({ packet: contentId(packet), sealed: contentId(sealed) });
    expect(judgeRecord(bob.sign(ack)).ok).toBe(true);
  });

  it("is told as a duplicate by the packet inside, however it was sealed", async () => {
    const id = contentId(packet);
    const receiver = receiverOf(bob, { accepted: (asked) => asked === id });
    const again = await sealFor(bob, packet, new Uint8Array(32).fill(9));
    const result = await receiveSealed(again, receiver);
    expect(result.ok && result.value.duplicate).toBe(true);
  });

  it("opens for the mind it is for, with a key that mind holds", async () => {
    const sealed = await sealFor(bob, packet);
    // Cy is not the recipient.
    expect(await refusal(sealed, receiverOf(cy))).toStrictEqual({ clause: "L1 12.6", path: "/to" });
    // Bob no longer holds the key.
    expect(await refusal(sealed, receiverOf(bob, { agreementKey: () => undefined }))).toStrictEqual(
      { clause: "L1 12.6", path: "/key" },
    );
    // Another key of Bob's does not open it.
    expect(
      await refusal(sealed, receiverOf(bob, { agreementKey: () => secretOf("other") })),
    ).toStrictEqual({ clause: "L1 12.6", path: "/ciphertext" });
  });

  it("opens with what the receiver gives in place of a key: an opener that keeps the key to itself", async () => {
    const sealed = await sealFor(bob, packet);
    const asked: Parameters<SealedOpener>[0][] = [];
    const opener: SealedOpener = (sealing) => {
      asked.push(sealing);
      return hpkeOpen({ ...sealing, recipientPrivateKey: secretOf("bob") });
    };
    const withKey = await receiveSealed(sealed, receiverOf(bob));
    const withOpener = await receiveSealed(
      sealed,
      receiverOf(bob, { agreementKey: (key) => (key === publicOf("bob") ? opener : undefined) }),
    );
    expect(withOpener.ok).toBe(true);
    expect(withOpener).toStrictEqual(withKey);
    // It is given the sealing, with the receiver's address as the associated data, and no key.
    expect(asked).toHaveLength(1);
    expect(Object.keys(asked[0] ?? {}).sort()).toStrictEqual(["aad", "ciphertext", "enc", "info"]);
    expect(asked[0]?.aad).toStrictEqual(utf8(bob.address));
    // What it does not open, and what it answers that is no bytes, is a record that does not open.
    for (const answer of [undefined, "text", {}, [1, 2, 3]]) {
      const receiver = receiverOf(bob, {
        agreementKey: () => () => Promise.resolve(answer as never),
      });
      expect(await refusal(sealed, receiver), JSON.stringify(answer)).toStrictEqual({
        clause: "L1 12.6",
        path: "/ciphertext",
      });
    }
    // An opener that fails is the receiver's own failure, and the caller hears of it.
    const locked = receiverOf(bob, {
      agreementKey: () => () => Promise.reject(new Error("the keys are locked")),
    });
    await expect(receiveSealed(sealed, locked)).rejects.toThrow("the keys are locked");
  });

  it("does not open under another recipient's name, though that recipient holds the key", async () => {
    // Zed lists Bob's agreement key as its own, and holds the private key too.
    const zed = withAgreement("zed", publicOf("bob"));
    const minds = [...everyone, zed];
    const both = packetTo([bob, zed]);
    const sealed = await sealFor(bob, both, RANDOM, minds);
    const renamed = { ...sealed, to: zed.address };
    const receiver = receiverOf(zed, { agreementKey: () => secretOf("bob") }, minds);
    expect(await refusal(renamed, receiver)).toStrictEqual({
      clause: "L1 12.6",
      path: "/ciphertext",
    });
    // Sealed for Zed, the same packet opens for Zed.
    const forZed = await sealFor(zed, both, RANDOM, minds);
    expect((await receiveSealed(forZed, receiver)).ok).toBe(true);
  });

  it("does not open when anything in it was changed", async () => {
    const sealed = await sealFor(bob, packet);
    const receiver = receiverOf(bob);
    const swap = (text: string, at: number) =>
      text.slice(0, at) + (text[at] === "A" ? "B" : "A") + text.slice(at + 1);
    for (const changed of [
      { ...sealed, ciphertext: swap(sealed.ciphertext, 0) },
      { ...sealed, ciphertext: swap(sealed.ciphertext, 40) },
      { ...sealed, ciphertext: sealed.ciphertext.slice(0, -4) },
      { ...sealed, enc: swap(sealed.enc, 0) },
    ]) {
      expect(await refusal(changed, receiver)).toStrictEqual({
        clause: "L1 12.6",
        path: "/ciphertext",
      });
    }
    // A second text for the same bytes is no base64url at all.
    const last = sealed.enc.slice(-1);
    const twin = sealed.enc.slice(0, -1) + String.fromCharCode(last.charCodeAt(0) + 1);
    expect(await refusal({ ...sealed, enc: twin }, receiver)).toStrictEqual({
      clause: "L1 12.6",
      path: "/enc",
    });
  });

  it("gives nothing back of a record that opens to a packet which does not pass", async () => {
    const receiver = receiverOf(bob);
    // In Ada's name, by Cy.
    const forged = cy.sign({
      oip: "1",
      type: "Packet",
      from: ada.address,
      to: [bob.address],
      created: T(10),
      expires: T(3610),
      nonce: "nonce-0009",
      purpose: { verb: "inform" },
      content: { mediaType: "text/plain", body: "A secret no receiver should act on." },
    });
    const sealed = await sealedOf(canonicalBytes(forged));
    const result = await receiveSealed(sealed, receiver);
    expect(result).toMatchObject({ ok: false, issues: [{ clause: "L1 12.4", path: "/proof" }] });
    expect(JSON.stringify(result)).not.toContain("secret");
    // A packet for somebody else, sealed to Bob.
    const elsewhere = await sealedOf(canonicalBytes(packetTo([cy])));
    expect(await refusal(elsewhere, receiver)).toStrictEqual({ clause: "L1 12.4", path: "/to" });
  });

  it("opens to the canonical form of a Packet, and to nothing else", async () => {
    const receiver = receiverOf(bob);
    const notAPacket = { clause: "L1 12.6", path: "/ciphertext" };
    // Another record, text that is no JSON, and nothing.
    const intent = ada.sign({
      oip: "1",
      type: "Intent",
      author: ada.address,
      created: T(5),
      want: "Privacy.",
    });
    for (const plaintext of [
      canonicalBytes(intent),
      utf8("not JSON"),
      utf8("[]"),
      utf8("null"),
      new Uint8Array(0),
    ]) {
      expect(await refusal(await sealedOf(plaintext), receiver)).toStrictEqual(notAPacket);
    }
    // The same packet in another writing: members in another order, or with white space.
    const reordered = utf8(JSON.stringify(Object.fromEntries(Object.entries(packet).reverse())));
    const spaced = utf8(
      JSON.stringify(JSON.parse(new TextDecoder().decode(canonicalBytes(packet))), null, 1),
    );
    expect(bytesToHex(reordered)).not.toBe(bytesToHex(canonicalBytes(packet)));
    for (const plaintext of [reordered, spaced]) {
      expect(await refusal(await sealedOf(plaintext), receiver)).toStrictEqual(notAPacket);
    }
    expect((await receiveSealed(await sealedOf(canonicalBytes(packet)), receiver)).ok).toBe(true);
  });

  it("is a Sealed record: a packet that arrives in the clear is not received here", async () => {
    const receiver = receiverOf(bob);
    expect(await refusal(packet, receiver)).toStrictEqual({ clause: "L1 12.6", path: "/type" });
    for (const value of [undefined, null, 7, "sealed", {}, []]) {
      expect((await receiveSealed(value, receiver)).ok, JSON.stringify(value)).toBe(false);
    }
    await fc.assert(
      fc.asyncProperty(fc.anything(), async (value) => {
        expect((await receiveSealed(value, receiver)).ok).toBe(false);
      }),
      { numRuns: 100 },
    );
  });

  it("needs to be told which agreement keys the receiver holds", async () => {
    const sealed = await sealFor(bob, packet);
    const { agreementKey: _, ...without } = receiverOf(bob);
    await expect(receiveSealed(sealed, without as never)).rejects.toThrow(TypeError);
    await expect(receiveSealed(null, without as never)).rejects.toThrow(TypeError);
  });

  it(`${clause("core 8.3")} is opened with a critical extension only by a receiver that implements it`, async () => {
    const sealed = await sealFor(bob, packet);
    const extended = {
      ...sealed,
      ext: { "com.example": { route: "relay-7" } },
      critical: ["com.example"],
    };
    expect(await refusal(extended, receiverOf(bob))).toStrictEqual({
      clause: "core 8.3",
      path: "/critical",
    });
    const understood = ["com.example"];
    expect((await receiveSealed(extended, receiverOf(bob, { understood }))).ok).toBe(true);
  });
});
