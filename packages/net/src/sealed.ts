// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * Sealing a packet (Layer 1, 12.6): a signed packet encrypted to one of its
 * recipient's agreement keys with HPKE, in a `Sealed` record that shows
 * only whom it is for.
 *
 * A packet is signed first and sealed after, so what is opened is judged as
 * any packet that arrives (12.4): `receiveSealed` opens and judges in one
 * step, and gives nothing back of a record whose packet does not pass.
 *
 * Sealing gives neither forward secrecy nor confidentiality against a
 * quantum computer: whoever later holds the agreement key reads what was
 * sealed to it (12.6).
 */

import {
  base64urlToBytes,
  bytesEqual,
  bytesToBase64url,
  canonicalBytes,
  contentId,
  decodeX25519Multikey,
  HPKE_SUITE,
  hpkeOpen,
  type HpkeOpenInput,
  hpkeSeal,
  parseJsonBytes,
  utf8,
} from "@oip/core";
import { type IdentityView, judgeRecord, latestState } from "@oip/identity";
import type { Sealed, Validation } from "@oip/schema";

import { type ReceivedPacket, receivePacket, type Receiver } from "./packet.ts";
import { judgingLater, no, ok, under } from "./result.ts";

/** Layer 1, 12.6: the `info` of every sealing. */
const INFO = utf8("oip/1 sealed");

/** What a sender seals, and to whom. */
export interface SealDraft {
  /** The packet, signed: what is sealed is its canonical form, proofs and all. */
  readonly packet: unknown;
  /** The address of the recipient the record is for. */
  readonly to: string;
  /**
   * The identity logs the sender holds: the recipient's agreement keys are
   * those of the latest state of its log.
   */
  readonly view: IdentityView;
  /**
   * 32 bytes from a cryptographically secure random source, for this one
   * record and never again. This package draws none. Used twice for one
   * recipient, they reveal both packets to anyone who sees both records.
   */
  readonly randomness: Uint8Array;
}

/**
 * Layer 1, 12.6: seals a signed packet to its recipient.
 *
 * The packet is a well-formed `Packet` that carries a proof. It is sealed
 * to the first agreement key of the recipient's latest state that can be
 * sealed to: a key that is a point of small order cannot (RFC 9180, 7.1.4).
 * The associated data is the recipient's address, so a record moved to
 * another recipient's name does not open.
 *
 * @returns The `Sealed` record, which is unsigned. A rejection if the
 *   packet is not one, or the recipient has no agreement key to seal to.
 * @throws TypeError if the randomness is not 32 bytes.
 */
export async function sealPacket(draft: SealDraft): Promise<Validation<Sealed>> {
  if (!(draft.randomness instanceof Uint8Array) || draft.randomness.length !== 32) {
    throw new TypeError("the randomness of a sender is 32 bytes");
  }
  return judgingLater(() => sealed(draft));
}

async function sealed(draft: SealDraft): Promise<Validation<Sealed>> {
  const judged = judgeRecord(draft.packet);
  if (!judged.ok) return under("/packet", judged);
  if (judged.value.record.type !== "Packet") {
    return no("what is sealed is a Packet", "L1 12.6", "/packet/type");
  }
  if (judged.value.proofs.length === 0) {
    return no("a packet is signed before it is sealed", "L1 12.6", "/packet/proof");
  }
  const log = draft.view.log(draft.to);
  if (!log.ok) return log;
  // The canonical form of the packet as it was judged, proofs and all (12.6).
  const plaintext = canonicalBytes(judged.value.record);
  for (const key of latestState(log.value).agreement) {
    const recipientPublicKey = decodeX25519Multikey(key);
    if (!recipientPublicKey.ok) continue;
    const made = await hpkeSeal({
      recipientPublicKey: recipientPublicKey.value,
      info: INFO,
      aad: utf8(draft.to),
      plaintext,
      randomness: draft.randomness,
    });
    if (made === undefined) continue;
    return ok({
      oip: "1",
      type: "Sealed",
      to: draft.to,
      key,
      suite: HPKE_SUITE,
      enc: bytesToBase64url(made.enc),
      ciphertext: bytesToBase64url(made.ciphertext),
    });
  }
  return no("the recipient has no agreement key that a packet can be sealed to", "L1 12.6", "/to");
}

/**
 * Opens what was sealed to an agreement key, for a receiver that does not
 * hand its keys out: a keystore, or a device. It is given everything of the
 * sealing but the key, and answers with the plaintext, or `undefined` if it
 * does not open.
 */
export type SealedOpener = (
  sealed: Omit<HpkeOpenInput, "recipientPrivateKey">,
) => Promise<Uint8Array | undefined>;

/** A recipient of sealed records: a receiver, and the agreement keys it holds. */
export interface SealedReceiver extends Receiver {
  /**
   * One of the receiver's agreement keys, named as its identity log lists it
   * (a Multikey): its private key, or what opens with it. Or `undefined` if
   * the receiver does not hold the key. A private key is used to open one
   * record and is kept nowhere.
   */
  readonly agreementKey: (key: string) => Uint8Array | SealedOpener | undefined;
}

/** A packet that arrived sealed. */
export interface ReceivedSealed extends ReceivedPacket {
  /**
   * The content ID of the `Sealed` record the packet arrived in. An `Ack`
   * for the packet carries it (Layer 1, 13.2).
   */
  readonly sealed: string;
}

/**
 * Layer 1, 12.6 and 12.4: opens a `Sealed` record and judges the packet
 * inside it as `receivePacket` judges any packet.
 *
 * The record is a well-formed `Sealed` record for this receiver, sealed to
 * an agreement key the receiver holds. What it opens to is the canonical
 * form of a `Packet`, and nothing else: no other record, and no other
 * writing of the same packet.
 *
 * Nothing of the packet is returned unless it passes: a record that opens
 * to a packet with no valid signature is a rejection, and its contents stay
 * here. It never throws on the value.
 */
export async function receiveSealed(
  value: unknown,
  receiver: SealedReceiver,
): Promise<Validation<ReceivedSealed>> {
  if (typeof (receiver.agreementKey as unknown) !== "function") {
    throw new TypeError("a recipient of sealed records says which agreement keys it holds");
  }
  return judgingLater(() => opened(value, receiver));
}

async function opened(
  value: unknown,
  receiver: SealedReceiver,
): Promise<Validation<ReceivedSealed>> {
  const judged = judgeRecord(
    value,
    receiver.understood === undefined ? undefined : { understood: receiver.understood },
  );
  if (!judged.ok) return judged;
  if (judged.value.record.type !== "Sealed") {
    return no("the record is not a Sealed record", "L1 12.6", "/type");
  }
  const record = judged.value.record as Sealed;
  if (record.to !== receiver.address) {
    return no("the record is sealed for another mind", "L1 12.6", "/to");
  }
  const enc = base64urlToBytes(record.enc);
  if (enc === undefined) return no("`enc` is not base64url without padding", "L1 12.6", "/enc");
  const ciphertext = base64urlToBytes(record.ciphertext);
  if (ciphertext === undefined) {
    return no("`ciphertext` is not base64url without padding", "L1 12.6", "/ciphertext");
  }
  const held = receiver.agreementKey(record.key);
  if (held === undefined) {
    return no("the record is sealed to a key this receiver does not hold", "L1 12.6", "/key");
  }
  const sealing = { enc, info: INFO, aad: utf8(receiver.address), ciphertext };
  const plaintext: unknown =
    typeof held === "function"
      ? await held(sealing)
      : await hpkeOpen({ ...sealing, recipientPrivateKey: held });
  // An opener is the receiver's own code, and what it answers is checked all the same.
  if (!(plaintext instanceof Uint8Array)) {
    return no("the record does not open with the key it names", "L1 12.6", "/ciphertext");
  }
  const NOT_A_PACKET = "the record does not open to the canonical form of a packet";
  const parsed = parseJsonBytes(plaintext);
  if (!parsed.ok) return no(NOT_A_PACKET, "L1 12.6", "/ciphertext");
  const inner = parsed.value as { readonly type?: unknown } | null;
  if (typeof inner !== "object" || inner?.type !== "Packet") {
    return no(NOT_A_PACKET, "L1 12.6", "/ciphertext");
  }
  const received = receivePacket(parsed.value, receiver);
  if (!received.ok) return received;
  // One writing for one packet: what was sealed is its canonical form, byte for byte.
  if (!bytesEqual(canonicalBytes(received.value.judged.record), plaintext)) {
    return no(NOT_A_PACKET, "L1 12.6", "/ciphertext");
  }
  return ok({ ...received.value, sealed: contentId(record) });
}
