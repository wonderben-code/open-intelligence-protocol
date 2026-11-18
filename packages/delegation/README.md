# @oip/delegation

Delegation for the [Open Intelligence Protocol](../../README.md): what one mind lets another sign for it, and whether a proof that says it acts for another does ([Layer 1, Section 11](../../spec/layer-1-mind-network.md)).

A proof that acts for another mind lists, in its own `authority`, the delegations that let it: one chain, root first. This package says whether that chain is valid for the record at the time the proof can be shown to have existed, and nothing else decides it. A chain is checked exactly as listed. It is never searched for, reordered or cut down.

It is pure: no I/O, and it never reads the clock. The logs, the evidence and the records a verifier holds are parameters. Whether a record counts for a mind by any route, with charters and status, is [`@oip/web`](../web/README.md)'s.

## Use

```ts
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
```

This is [`examples/agent-limit.ts`](examples/agent-limit.ts); a test runs it and checks that this page shows it unchanged. With four test keys it gives:

```
120 dollars, within the limit: counts from 2026-11-18T10:00:01Z
900 dollars, beyond it: does not count
120 dollars, after the firm revoked the delegation: does not count
```

The Intent, the agent's key and the delegation are the same in the first and third verdicts. What differs is when the verifier can show the signature existed: after the revocation, it no longer counts for the firm, whatever date the agent wrote.

## What it exports

| Export                                                                                                                            | What it does                                                                                                                                                                                                          |
| --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `delegatedTime`, `delegatedProofTime`, `DelegationContext`, `DelegatedOptions`, `MAX_CHAIN`                                       | Layer 1, 11.4 and 11.6: whether a record, or one proof on it, counts for a principal through the chain the proof lists, and from when. A refusal names the entry of `authority` at fault. A chain has at most 8 links |
| `revokedTime`                                                                                                                     | Layer 1, 11.5: the time from which a delegation is revoked, by a revocation its own author signed                                                                                                                     |
| `sentFor`                                                                                                                         | Layer 1, 11.2: whether a packet counts as sent on another mind's behalf                                                                                                                                               |
| `evaluatePolicy`, `policyHolds`, `select`, `MAX_POLICY_STEPS`                                                                     | Layer 1, 11.3: whether a policy holds for a record, and why not                                                                                                                                                       |
| `covers`, `isCommand`, `isDelegableCommand`, `isDelegableType`, `signCommand`, `DELEGABLE_TYPES`, `DelegableType`, `SEND_COMMAND` | Layer 1, 11.2: commands, which of them may be granted, and the command that signing a type of record needs                                                                                                            |
| `RecordSet`, `RecordView`                                                                                                         | The records a verifier holds: delegations a proof names by reference, revocations and charters                                                                                                                        |
| `witnessProofs`                                                                                                                   | Records a verifier's own first sight of the proofs on a record that arrives, and of the proofs on the delegations and charters those proofs carry whole                                                               |
| `draftDelegation`, `draftSubDelegation`, `draftRevocation`, `authorityOf`, `DelegationFields`, `SubDelegationFields`              | Writing a delegation, the next link of a chain, a revocation, and the `authority` a proof lists                                                                                                                       |

## Chains (Layer 1, 11.4 to 11.6)

`delegatedTime(judged, principal, context)` answers with the earliest evaluation time at which a proof on the record counts for the principal through its chain, or `undefined`. For a proof `p` by a mind `D`, evaluated at `t(p)`:

- **The chain is the one listed**: from the principal, each delegation's delegate the author of the next, the last naming `D`, every one with the principal as its subject. At most 8.
- **Each link is signed by its author's own authority**, at a time not after `t(p)`. A delegate cannot sign a delegation in its principal's name: a `Delegation` is not a type that can be delegated.
- **Each link grants no more than the one before it**: a command the parent's covers, every statement of the parent's policy, an expiry no later than the parent's. `draftSubDelegation` writes such a link, and refuses to write one that asks for more.
- **Time is the proof's evaluation time**, which comes from evidence and never from the date the signer wrote. `t(p)` is no more than 300 seconds before any `notBefore` and no more than 300 seconds after any `expires`. A delegate cannot use an expired delegation by writing an earlier date.
- **No link was revoked at or before `t(p)`**. A revocation takes effect from its own evaluation time, so a backdated revocation cannot undo what evidence shows came before it. Only the delegation's author can revoke it.
- **The last command covers the signing of the record's type, and every policy of every link holds for the record.**

A delegation may be carried whole in the proof or named by reference. By reference, the verifier must hold it: give the records you hold as a `RecordView`. `RecordSet` is one in memory. It keeps what it is shown: the same record given again adds the proofs not seen before and takes none away, so a revocation shown once with its author's signature stays signed.

**If you keep your own first sight**, take a record in with `witnessProofs(judged, now, seen)`, not with `witnessRecord` of `@oip/identity`. A delegation carried inline is as new to you as the record, and its author's signature needs evidence of its own: seen with the record's proofs alone, a proof that carries its chain would never count.

A proof counts for its signer and for at most one other mind. A proof whose chain does not hold still counts for its signer, by the signer's own key.

## Commands (Layer 1, 11.2)

A command is `/` and a segment, any number of times. `covers(granted, needed)` holds when the two are equal or `needed` goes on after a `/`, so a command covers by whole segments: `/x402/pay` covers `/x402/pay/usd` and does not cover `/x402/payments`.

Under `/oip` there are exactly five commands: `/oip/sign/Intent`, `/oip/sign/Offer`, `/oip/sign/Commitment`, `/oip/sign/Receipt` and `/oip/send`. Every other command whose first segment is `oip` is reserved, `/oip` and `/oip/sign` among them, so there are no blanket grants. `isDelegableCommand` says whether a command may be granted.

## Policies (Layer 1, 11.3)

A policy is a list of statements about the record being authorised, taken without its `proof`. `evaluatePolicy(policy, record)` answers whether every statement holds, and if not, which statement and why.

```ts
import { evaluatePolicy } from "@oip/delegation";

const policy = [
  ["==", ".terms.price.currency", "USD"],
  ["<=", ".terms.price.amount", "500"],
  ["all", ".parties", ["!=", ".mind", "did:oip:the-delegate"]],
];
evaluatePolicy(policy, commitment); // { ok: true, value: true }, or the statements that fail
```

Three rules shape it:

- **Ordering is defined between decimals and nothing else.** `<`, `<=`, `>` and `>=` compare integers and decimal strings by value. Asked of anything else, they are an error. `==` and `!=` compare by value where both sides are decimals (`5` equals `"5.0"`), and by canonical form otherwise.
- **Every statement is evaluated in full.** Nothing is skipped because an earlier part already decided the answer.
- **An error anywhere fails the policy.** A selector that does not resolve, an ordering on what is no decimal, a quantifier over what is no array: each fails the whole policy, even under `not` or `or`. So a policy that constrains a member which may be absent must require it.

A quantifier tries its statement on every element of an array, so a policy can ask for work in proportion to the record. One policy is evaluated for at most `MAX_POLICY_STEPS` statements (100,000), counting a statement once for each value it is tried on; a policy that needs more does not hold. The specification sets no such bound yet, which is a question queued for the maintainer.

The whole policy is read before any of it is asked of the record. A statement that is none makes the policy not hold wherever it stands, the statement of a quantifier over an empty array among them.

## Results and errors

Nothing here does I/O or reads a clock, and nothing throws on what arrives from outside. A function that judges answers with a time or `undefined`, or with a rejection that names the clause and the place. The arguments a caller builds itself are another matter: `draftSubDelegation` throws `TypeError` when asked for more than the parent grants ([ADR-0007](../../docs/adr/0007-programming-errors.md)).
