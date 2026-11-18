# @oip/web

The Mind Web: whether a record counts for a mind, and what state an Intent, an Offer or a Commitment is in. It implements [Layer 2](../../spec/layer-2-mind-web.md), Sections 5 to 9, of the [Open Intelligence Protocol](../../README.md).

`@oip/identity` says whether a key was a mind's to sign with, at the time the signature can be shown to have existed. `@oip/delegation` says whether a proof that names a chain of delegations acts for another mind. This package puts the routes together and answers the two questions an application asks:

- **Does this record count for this mind?** (Layer 2, Section 7.)
- **What is the status of this record?** (Layer 2, Section 8.)

It is pure: no I/O, and it never reads the clock. The logs, the evidence, the records a verifier holds and the time of computation are parameters.

## Use

```ts
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
    identity.witness(log, at("2026-11-18T08:00:01Z"), seen);
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
    witnessProofs(taken.value, now, seen);
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
```

This is [`examples/deal.ts`](examples/deal.ts); a test runs it and checks that this page shows it unchanged. With six test keys it gives:

```
Amina asks: the Intent is open, the Commitment is not held
the agent signs for the firm: the Intent is open, the Commitment is proposed
Amina signs too: the Intent is satisfied, the Commitment is accepted
Amina says it was done: the Intent is satisfied, the Commitment is fulfilled
it counts for: Amina, the firm, the agent
```

`judgeRecord` validates a record and verifies each proof on it. Everything here takes its result, so nothing is judged that has not been validated and verified first. The firm never signed the Commitment itself: it counts for the firm because its agent's proof carries a delegation that covers it.

## What it exports

| Export                                                                       | What it does                                                                                                                                                                                      |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `signedTime`, `countsFor`                                                    | Layer 2, 7.1: the earliest evaluation time at which a record counts for a mind, by any route, or whether it does at all                                                                           |
| `actsFor`                                                                    | Layer 2, 5.2: whether a proof by one mind on a record counts for another through a delegation or a charter role                                                                                   |
| `charterInForce`, `roleProofTime`, `roleTime`                                | Layer 2, 6.2 and 7.1 item 4: the charter of a collective in force at a time, and whether a member's proof counts for the collective through a role of it                                          |
| `commitmentAccepted`                                                         | Layer 2, 7.3: whether a Commitment is accepted                                                                                                                                                    |
| `status`, `intentStatus`, `offerStatus`, `commitmentStatus`, `charterStatus` | Layer 2, Section 8: the status of a record at a time                                                                                                                                              |
| `IntentStatus`, `OfferStatus`, `CommitmentStatus`, `CharterStatus`, `Status` | The values a status takes                                                                                                                                                                         |
| `WebRecordSet`, `WebRecords`, `WebContext`, `referenced`                     | The records a verifier holds, found by what they refer to: what supersedes a record, the Commitments that resolve it, the Receipts about it. `referenced` gives the content ID a record-ref names |
| `evidenceMatches`, `evidenceIsChecked`                                       | Layer 2, Section 9: whether bytes a verifier fetched are the bytes an evidence item names by its digest                                                                                           |

## Signing for a party (Layer 2, Section 7)

A record counts for a mind by one of four routes, and `signedTime` takes the earliest:

1. **The mind's own key**: a proof by a valid operational key of the mind (Layer 1, 6.1).
2. **A delegation chain**: a proof by another mind whose `authority` lists a valid chain from the mind to the signer (Layer 1, 11.4). Only for the types that can be delegated: Intent, Offer, Commitment and Receipt.
3. **A collective's threshold**: proofs without `authority` by enough of the collective's members (Layer 1, 9.5).
4. **A charter role**: a proof by a member whose `authority` names the collective's charter in force, which assigns the member a role with a power that covers the record (Layer 2, 6.2). Only for the same four types.

Three rules hold by every route:

- **A verdict is a time.** A proof counts from its evaluation time, which comes from evidence and never from the date the signer wrote (core 9.3).
- **A proof evaluated more than 300 seconds after the record's `expires` does not count** (core 9.6).
- **A proof counts for its signer and for at most one other mind**: the principal its `authority` leads back to.

## Status (Layer 2, Section 8)

Status is computed from the records the verifier holds and the time it gives, so two verifiers can answer differently, and one verifier can answer differently later. Nothing here stores a status.

- **An Intent** is `withdrawn` or `satisfied` if its author superseded it with a record that says so, `superseded` if its author edited it, `satisfied` if an accepted Commitment that closes it also counts for its author, `expired` after its `expires`, and `open` otherwise. Other minds cannot close someone's Intent by committing among themselves.
- **An Offer** is `withdrawn`, `superseded`, `expired`, `exhausted` when as many accepted Commitments take it up as its `terms.quantity`, or `open`.
- **A Commitment** is `proposed` until it is accepted: it counts for its author, its author is a party or signs for one, and it counts for every required party. From then on the Receipts of its parties decide: `cancelled`, `fulfilled`, `claimed-fulfilled`, `broken`, `disputed`, `overdue` or `accepted`, by the eight items of 8.3 in their order.
- **A charter** is `dissolved` once the collective's log is retired, and `active` until then.

Things to know:

- **`disputed` has two causes.** A party disputes how the Commitment went. Or a party's signature no longer counts because the party declared its key compromised from before it signed: the Commitment would be accepted with that declaration disregarded, so it is shown as `disputed` and not as `proposed`. The signature is not counted either way.
- **`broken` is a claim.** It is what the authors of the `broken` Receipts say. Show who said it.
- **Only parties are heard.** A Receipt counts towards a Commitment's status if its author is a party and it counts for its author. A Receipt whose `supersedes` names an earlier Receipt by the same author replaces it, and a `revoked` Receipt takes one back.
- **The time of computation is yours.** `expired` and `overdue` compare it with `expires` and `terms.deadline` exactly, with no tolerance: a status is a display at a time, and the tolerance of core 9.1 is for judging signatures.
- **A status function asked about the wrong type of record throws `TypeError`**, as does a time that is none: those are mistakes in the calling program ([ADR-0007](../../docs/adr/0007-programming-errors.md)). `status` answers by the type of the record, and refuses a type that has no status.

## The records a verifier holds

`WebRecordSet` holds records in memory. It judges each once when it is given, and finds them by what they refer to. Like a `LogBook`, it keeps what it is shown: the same record given again, with other proofs, is one record with every proof that verified, and no copy takes a proof away. A Commitment whose second signature arrives later gains it.

A status is only as complete as the set. A verifier that does not hold the Receipt that says `fulfilled` answers `accepted`. That is the meaning of the first sentence of Section 8, and it is why a status is never proof that nothing more exists.

`WebRecords` is the interface the functions read. An indexer (M5) implements it over its store.

## Evidence (Layer 2, Section 9)

`evidenceMatches(item, bytes)` says whether bytes are the bytes an evidence item names by its `digest`. A verifier that fetches a `uri` item checks this before it relies on what it fetched. An item with no digest matches nothing. This package fetches nothing.

## Results and errors

- **Nothing here throws on what arrives from outside.** A record that does not count gives `undefined` or `false`; `status` gives a result or a rejection with the clause.
- **The arguments a caller builds itself are another matter**: a judged record that is not one, a context without a view, a time that is no time. Those are mistakes in the calling program, and a `TypeError`.
