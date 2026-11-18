// SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
// SPDX-License-Identifier: Apache-2.0

import {
  contentId,
  createProofSync,
  formatKeyRef,
  formatRecordRef,
  formatVersionId,
  type Instant,
  mindAddress,
  parseTimestamp,
  signerFromPrivateKey,
  type SyncSigner,
  withProofs,
} from "@oip/core";
import { authorityOf, draftDelegation, witnessProofs } from "@oip/delegation";
import { draftGenesis, FirstSeen, judgeRecord, LogBook, signEventSync } from "@oip/identity";
import type { Delegation, Proof } from "@oip/schema";
import { countsFor, status, WebRecordSet } from "@oip/web";

const at = (timestamp: string): Instant => parseTimestamp(timestamp) ?? 0n;

/** A mind with one control key and one operational key, and how it adds its proof to a record. */
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
  /** The record with this mind's proof added, made at `created`, which may list a chain. */
  const sign = <T extends object>(
    record: T,
    created: string,
    authority?: readonly Delegation[],
  ) => {
    const earlier = (record as { proof?: Proof[] }).proof ?? [];
    const proof = createProofSync(
      record,
      {
        verificationMethod: method,
        created,
        ...(authority === undefined ? {} : { authority: authorityOf(authority) }),
      },
      key,
    );
    return withProofs(record, [...earlier, proof]);
  };
  return { address, log: [genesis], sign };
}

/**
 * Amina asks for a translation. A firm's agent commits the firm to it, under
 * a delegation from the firm; Amina signs too; and later she says it was
 * done. What a verifier that takes each record in as it is made says of the
 * Intent and the Commitment, step by step.
 */
export function example(keys: readonly Uint8Array[]): string[] {
  const [k0, k1, k2, k3, k4, k5] = keys;
  if (!k0 || !k1 || !k2 || !k3 || !k4 || !k5) throw new TypeError("six keys are needed");
  const amina = mind("human", k0, k1);
  const firm = mind("institution", k2, k3);
  const agent = mind("agent", k4, k5);

  // 09:00. The firm lets its agent sign Commitments for it, up to 500 dollars, paid to the firm.
  const grant = firm.sign(
    draftDelegation("2026-11-18T09:00:00Z", {
      author: firm.address,
      delegate: agent.address,
      subject: firm.address,
      command: "/oip/sign/Commitment",
      policy: [
        ["==", ".terms.price.currency", "USD"],
        ["<=", ".terms.price.amount", "500"],
        ["==", ".terms.price.payee", firm.address],
      ],
      expires: "2026-12-18T09:00:00Z",
      nonce: "kq3v8n2x5m7d",
    }),
    "2026-11-18T09:00:00Z",
  ) as Delegation;

  // 10:00. Amina's Intent.
  const intent = amina.sign(
    {
      oip: "1",
      type: "Intent",
      author: amina.address,
      created: "2026-11-18T10:00:00Z",
      want: "A certified translation of a lease.",
    },
    "2026-11-18T10:00:00Z",
  );

  // 10:30. The agent writes the Commitment and signs it for the firm.
  const terms = {
    oip: "1",
    type: "Commitment",
    author: agent.address,
    created: "2026-11-18T10:30:00Z",
    parties: [
      { mind: firm.address, role: "debtor", required: true },
      { mind: amina.address, role: "creditor", required: true },
    ],
    promise: "The firm will translate the lease by 20 November; Amina will pay 120 dollars.",
    terms: {
      deadline: "2026-11-20T18:00:00Z",
      price: { amount: "120", currency: "USD", payer: amina.address, payee: firm.address },
    },
    resolves: [formatRecordRef(amina.address, contentId(intent))],
    closesIntent: true,
  };
  const proposed = agent.sign(terms, "2026-11-18T10:30:00Z", [grant]);
  // 11:00. Amina adds her signature. The content ID does not change.
  const agreed = amina.sign(proposed, "2026-11-18T11:00:00Z");
  // 20 November, 15:00. Amina says it was done.
  const receipt = amina.sign(
    {
      oip: "1",
      type: "Receipt",
      author: amina.address,
      created: "2026-11-20T15:00:00Z",
      about: formatRecordRef(agent.address, contentId(agreed)),
      outcome: "fulfilled",
    },
    "2026-11-20T15:00:00Z",
  );

  // The verifier: its own evidence, the three logs, and the records as they come.
  const seen = new FirstSeen();
  const identity = new LogBook(seen);
  const records = new WebRecordSet();
  const context = { identity, records };
  for (const log of [amina.log, firm.log, agent.log]) {
    const looked = identity.witness(log, at("2026-11-18T08:00:01Z"), seen);
    if (!looked.ok) throw new Error("the example's logs verify");
  }
  const lines: string[] = [];
  const steps: [what: string, record: object, when: string][] = [
    ["Amina asks", intent, "2026-11-18T10:00:01Z"],
    ["the agent signs for the firm", proposed, "2026-11-18T10:30:01Z"],
    ["Amina signs too", agreed, "2026-11-18T11:00:01Z"],
    ["Amina says it was done", receipt, "2026-11-20T15:00:01Z"],
  ];
  for (const [what, record, when] of steps) {
    const now = at(when);
    // The logs it follows are known up to now, and the record is seen now.
    for (const log of [amina.log, firm.log, agent.log]) identity.hold(log, now);
    const taken = judgeRecord(record);
    if (!taken.ok) throw new Error("the example's records are well formed");
    // A look that was cut short says so, and is made again at the same reading.
    if (!witnessProofs(taken.value, now, seen).ok) throw new Error("the look was cut short");
    records.add(record);
    const of = (given: object): string => {
      const judged = records.record(contentId(given));
      const answer = judged === undefined ? undefined : status(judged, now, context);
      return answer?.ok === true ? answer.value : "not held";
    };
    lines.push(`${what}: the Intent is ${of(intent)}, the Commitment is ${of(agreed)}`);
  }
  const held = records.record(contentId(agreed));
  const bound = [
    ["Amina", amina.address],
    ["the firm", firm.address],
    ["the agent", agent.address],
  ].filter(([, address]) => held !== undefined && countsFor(held, address ?? "", context));
  lines.push(`it counts for: ${bound.map(([name]) => name).join(", ")}`);
  return lines;
}
