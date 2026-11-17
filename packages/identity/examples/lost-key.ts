// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  contentId,
  createProofSync,
  formatKeyRef,
  formatTimestamp,
  formatVersionId,
  type Instant,
  keyHash,
  mindAddress,
  parseTimestamp,
  signerFromPrivateKey,
  withProofs,
} from "@oip/core";
import {
  draftGenesis,
  draftUpdate,
  FirstSeen,
  judgeRecord,
  LogBook,
  ownSignedTime,
  signEventSync,
  witnessLog,
  witnessRecord,
} from "@oip/identity";

const at = (timestamp: string): Instant => parseTimestamp(timestamp) ?? 0n;

/**
 * A mind signs an Intent with its phone, loses the phone, and removes the
 * phone's key. Does the Intent still count? That depends on what the
 * verifier can show about when the signature existed, and on nothing the
 * signer wrote.
 */
export function example(
  control0: Uint8Array,
  control1: Uint8Array,
  phoneKey: Uint8Array,
): string[] {
  const first = signerFromPrivateKey(control0);
  const second = signerFromPrivateKey(control1);
  const phone = signerFromPrivateKey(phoneKey);

  // 09:00. The genesis: one control key signs it and commits to the next by its hash.
  const genesis = signEventSync(
    draftGenesis("2026-11-17T09:00:00Z", {
      kind: "human",
      controller: { keys: [first.publicKey], next: [keyHash(second.publicKey)] },
      keys: [{ key: phone.publicKey, label: "phone" }],
    }),
    [{ control: first }],
  );
  const mind = mindAddress(contentId(genesis));

  // 10:00. An Intent, signed with the phone's key and pinned to the version of the log it was signed under.
  const unsigned = {
    oip: "1",
    type: "Intent",
    author: mind,
    created: "2026-11-17T10:00:00Z",
    want: "Translate a lease.",
  };
  const pinned = formatKeyRef(mind, formatVersionId(0, contentId(genesis)), phone.publicKey);
  const proof = createProofSync(
    unsigned,
    { verificationMethod: pinned, created: unsigned.created },
    phone,
  );
  const intent = withProofs(unsigned, [proof]);

  // 11:00. The phone is lost. An Update leaves its key out; the second control key signs it.
  const update = signEventSync(
    draftUpdate({ mind, seq: 0, head: contentId(genesis) }, "2026-11-17T11:00:00Z", {
      controller: { keys: [second.publicKey], next: [] },
      keys: [],
    }),
    [{ control: second }],
  );

  /**
   * What a verifier says that followed the log as it was published, and
   * first obtained the Intent at a given time.
   */
  const verdict = (obtained: string): string => {
    const seen = new FirstSeen();
    // It obtained each event a second after it was made. An event is
    // recorded as seen only once it has verified, never on sight of its content.
    witnessLog([genesis], at("2026-11-17T09:00:01Z"), seen);
    witnessLog([genesis, update], at("2026-11-17T11:00:01Z"), seen);
    const record = judgeRecord(intent);
    if (!record.ok) return "is not well formed";
    // Likewise the proofs on the record: those that verify, when it was obtained.
    witnessRecord(record.value, at(obtained), seen);
    const book = new LogBook(seen);
    book.hold([genesis, update], at("2026-11-17T13:00:00Z"));
    const time = ownSignedTime(record.value, mind, book);
    return time === undefined ? "does not count" : `counts from ${formatTimestamp(time)}`;
  };

  return [
    mind,
    `seen at 10:00:01, before the key was removed: ${verdict("2026-11-17T10:00:01Z")}`,
    `first seen at 12:00, after it was removed: ${verdict("2026-11-17T12:00:00Z")}`,
  ];
}
