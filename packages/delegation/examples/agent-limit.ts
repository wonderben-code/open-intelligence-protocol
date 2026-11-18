// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  contentId,
  createProofSync,
  formatKeyRef,
  formatTimestamp,
  formatVersionId,
  type Instant,
  mindAddress,
  parseTimestamp,
  signerFromPrivateKey,
  type SyncSigner,
  withProofs,
} from "@oip/core";
import {
  authorityOf,
  delegatedTime,
  draftDelegation,
  draftRevocation,
  RecordSet,
  witnessProofs,
} from "@oip/delegation";
import { draftGenesis, FirstSeen, judgeRecord, LogBook, signEventSync } from "@oip/identity";
import type { Delegation } from "@oip/schema";

const at = (timestamp: string): Instant => parseTimestamp(timestamp) ?? 0n;

/** A mind with one control key and one operational key, and how it signs a record. */
function mind(kind: string, control: Uint8Array, operational: Uint8Array) {
  const key: SyncSigner = signerFromPrivateKey(operational);
  const genesis = signEventSync(
    draftGenesis("2026-11-18T08:00:00Z", {
      kind,
      // No next key is committed to: this mind will not rotate its control key.
      controller: { keys: [signerFromPrivateKey(control).publicKey], next: [] },
      keys: [{ key: key.publicKey }],
    }),
    [{ control: signerFromPrivateKey(control) }],
  );
  const address = mindAddress(contentId(genesis));
  const method = formatKeyRef(address, formatVersionId(0, contentId(genesis)), key.publicKey);
  /** The record with one proof by this mind, which may list a chain of delegations. */
  const sign = <T extends { created: string }>(record: T, authority?: readonly Delegation[]) =>
    withProofs(record, [
      createProofSync(
        record,
        {
          verificationMethod: method,
          created: record.created,
          ...(authority === undefined ? {} : { authority: authorityOf(authority) }),
        },
        key,
      ),
    ]);
  return { address, log: [genesis], sign };
}

/**
 * A firm lets its agent sign Intents for it, up to 500 dollars each. The
 * agent signs one for 120 and one for 900, and later the firm revokes the
 * delegation. Which of the agent's signatures count for the firm?
 */
export function example(keys: readonly [Uint8Array, Uint8Array, Uint8Array, Uint8Array]): string[] {
  const firm = mind("institution", keys[0], keys[1]);
  const agent = mind("agent", keys[2], keys[3]);

  // 09:00. The firm delegates: Intents only, in dollars, up to 500, for a month.
  const grant = firm.sign(
    draftDelegation("2026-11-18T09:00:00Z", {
      author: firm.address,
      delegate: agent.address,
      subject: firm.address,
      command: "/oip/sign/Intent",
      policy: [
        ["==", ".constraints.budget.currency", "USD"],
        ["<=", ".constraints.budget.max", "500"],
      ],
      expires: "2026-12-18T09:00:00Z",
      nonce: "kq3v8n2x5m7d",
    }),
  ) as Delegation;

  // The agent signs Intents in the firm's name. Each proof carries the delegation.
  const intent = (created: string, max: string) =>
    agent.sign(
      {
        oip: "1",
        type: "Intent",
        author: firm.address,
        created,
        want: "A certified translation of a lease.",
        constraints: { budget: { max, currency: "USD" } },
      },
      [grant],
    );
  const within = intent("2026-11-18T10:00:00Z", "120");
  const beyond = intent("2026-11-18T10:05:00Z", "900");
  const afterwards = intent("2026-11-18T12:30:00Z", "120");

  // 12:00. The firm revokes the delegation.
  const revocation = firm.sign(draftRevocation("2026-11-18T12:00:00Z", grant));

  /**
   * What a verifier says that follows both logs, takes each record in when
   * it is made, and learns of the revocation a second after it is signed.
   */
  const verdict = (record: { created: string }): string => {
    const seen = new FirstSeen();
    const identity = new LogBook(seen);
    const records = new RecordSet();
    const take = (given: unknown, when: Instant): void => {
      const judged = judgeRecord(given);
      if (!judged.ok) return;
      // First sight of the proofs that verify, the delegation's own among them.
      witnessProofs(judged.value, when, seen);
      records.add(given);
    };
    const obtained = at(record.created) + 1_000_000_000n;
    const revoked = at(revocation.created) + 1_000_000_000n;
    // The logs, as known when the record is judged; and the revocation, if it came first.
    for (const log of [firm.log, agent.log])
      identity.witness(log, at("2026-11-18T08:00:01Z"), seen);
    for (const log of [firm.log, agent.log]) identity.hold(log, at("2026-11-18T13:00:00Z"));
    if (revoked <= obtained) take(revocation, revoked);
    take(record, obtained);
    const judged = judgeRecord(record);
    if (!judged.ok) return "is not well formed";
    const time = delegatedTime(judged.value, firm.address, { identity, records });
    return time === undefined ? "does not count" : `counts from ${formatTimestamp(time)}`;
  };

  return [
    `120 dollars, within the limit: ${verdict(within)}`,
    `900 dollars, beyond it: ${verdict(beyond)}`,
    `120 dollars, after the firm revoked the delegation: ${verdict(afterwards)}`,
  ];
}
