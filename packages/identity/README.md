# @oip/identity

Who a mind is, and which of its keys may sign: the rules of [Layer 1](../../spec/layer-1-mind-network.md), Sections 2 to 9, and of [OIP Core](../../spec/core.md), Section 9, in the [Open Intelligence Protocol](../../README.md).

`@oip/core` says whether a proof is a valid signature by the key it names. This package says whether that key was the mind's to sign with, **at the time the signature can be shown to have existed**.

- **Identity logs** (Layer 1, 3 and 4): write and sign the four events, and verify a log event by event into the state after each. Key-controlled minds rotate by pre-rotation; member-controlled minds, the collectives, are signed for by a majority of their members.
- **Evidence of time** (core 9): every rule about time is judged at an evaluation time taken from evidence, never from the date a signer wrote. The two formulas are here and nowhere else.
- **Key validity** (Layer 1, 6): removal, retirement, compromise declarations and the rule for records that describe the present.
- **Duplicity** (Layer 1, 7): two events for one position, resolved by the earlier evidence and never by length.
- **DID documents** (Layer 1, 5), **lineage** (Layer 1, 8) and **collectives** acting as one (Layer 1, 9).

It is pure: no I/O, and it never reads the clock. The logs a verifier holds, its evidence and every time are parameters. Signing through a delegation or a charter role is `@oip/delegation`'s.

## Use

```ts
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
  proofDigest,
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

  /** What a verifier says that first saw the proof at a given time, and holds the whole log. */
  const verdict = (proofSeen: string): string => {
    const seen = new FirstSeen();
    seen.sawEvent(contentId(genesis), at("2026-11-17T09:00:01Z"));
    seen.sawEvent(contentId(update), at("2026-11-17T11:00:01Z"));
    seen.sawProof(proofDigest(proof), at(proofSeen));
    const book = new LogBook(seen);
    book.hold([genesis, update], at("2026-11-17T13:00:00Z"));
    const record = judgeRecord(intent);
    const time = record.ok ? ownSignedTime(record.value, mind, book) : undefined;
    return time === undefined ? "does not count" : `counts from ${formatTimestamp(time)}`;
  };

  return [
    mind,
    `seen at 10:00:01, before the key was removed: ${verdict("2026-11-17T10:00:01Z")}`,
    `first seen at 12:00, after it was removed: ${verdict("2026-11-17T12:00:00Z")}`,
  ];
}
```

This is [`examples/lost-key.ts`](examples/lost-key.ts); a test runs it and checks that this page shows it unchanged. With three test keys it prints:

```
did:oip:bciqp2jtrolnkbn56yz4cjzhfykd3hmmmnbnhkwl35zvqx5hsioe4pda
seen at 10:00:01, before the key was removed: counts from 2026-11-17T10:00:01Z
first seen at 12:00, after it was removed: does not count
```

The Intent, the key and the log are the same in both verdicts. What differs is the evidence. A verifier that first sees the signature after the key was removed cannot tell it from one made by whoever found the phone, whatever date it carries, so it does not count it (core 9.7).

## What it exports

| Export                                                                                                 | What it does                                                                                                                                                                        |
| ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `LogBook`, `IdentityView`                                                                              | The logs a verifier holds, one or more branches for each mind, with its evidence. `log(mind)` verifies a log when first asked, its members' logs with it, and resolves duplicity    |
| `divergence`                                                                                           | Where two verified logs of one mind part, and the two events they hold there: the evidence of duplicity a resolver publishes (Layer 1, 7.1)                                         |
| `verifyLog`, `LogContext`, `VerifiedLog`, `LogEntry`, `IdentityState`                                  | Verifies one log (Layer 1, 4). The result has each event with the state after it and its evaluation time                                                                            |
| `latestState`, `entryAt`, `stateAt`, `childrenAt`, `revokedAt`, `removalTime`, `compromisedSince`      | Questions about a verified log: the state now, at a version, at a time; the children and the revoked keys by an event; when a key was removed; from when it is declared compromised |
| `judgeRecord`, `JudgedRecord`                                                                          | Validates a record and verifies each proof on it, once. The rest takes its result                                                                                                   |
| `operationalProofTime`, `operationalProofs`, `CountedProof`, `CURRENT_STATE_TYPES`                     | Layer 1, 6.1: whether a proof is by a valid operational key, and its evaluation time                                                                                                |
| `ownSignedTime`, `collectiveSignedTime`                                                                | The earliest time a record is signed by a mind's own authority: one of its keys, or for a collective its threshold (Layer 1, 9.5)                                                   |
| `EvidenceView`, `FirstSeen`, `earliestEvidence`                                                        | What a verifier can show about when a proof or an event existed (core 9.4)                                                                                                          |
| `proofTime`, `eventTime`, `Evaluation`                                                                 | The two formulas: `t(p) = max(p.created, τ(p))` and the same for an event, never before the event before it (core 9.3, 9.5)                                                         |
| `didDocument`, `DidResolution`                                                                         | The DID document of a mind, current or at a `versionId` (Layer 1, 5.2, 2.4)                                                                                                         |
| `lineage`, `Lineage`                                                                                   | Whether each parent a mind names acknowledges it (Layer 1, 8.2)                                                                                                                     |
| `draftGenesis`, `draftUpdate`, `draftFork`, `draftRetire`, `signEvent`, `signEventSync`, `EventSigner` | Writes the four events and signs them, with control keys or as a member                                                                                                             |
| `MAX_HEIGHT`, `MAX_LOG_EVENTS`, `MIN_ACCEPTED_LOG_EVENTS`                                              | Limits                                                                                                                                                                              |

The API report is [`etc/identity.api.md`](etc/identity.api.md).

## Evidence, and why there is no shortcut

Every function that judges takes an `EvidenceView`: for a proof, by its digest, and for an identity event, by its content ID, the earliest time the verifier can show it existed. The answers come from the verifier's own first sight, a witness it trusts, an anchored checkpoint or an acknowledgement (core 9.4). Combining them is the caller's work; `earliestEvidence` takes the earliest of several sources.

- **`undefined` means no evidence, and nothing counts without evidence.** It never means "assume the date the signer wrote". There is no function here that verifies without a view, by design ([ADR-0003](../../docs/adr/0003-evidence-model.md)).
- **A verifier that receives a proof live records it first**: `seen.sawProof(proofDigest(proof), now)`, and then judges with a view that includes it. The record keeps the earliest time it is told.
- **A log is held with the time up to which it is known** (`book.hold(events, asOf)`): when a witness the verifier trusts served it, or the present for a verifier that follows the log itself. A proof first seen after that time is not counted until the log is refreshed, because the log may lack the event that removed the key (core 9.4, Layer 1, 6.3).
- **The times of a log's events come from the same view.** A resolver serves its first-seen times with a log (Layer 1, 17.2); a client puts them in its view and never substitutes its own later first sight.

## Results and errors

- **A function that judges returns a result and never throws**, whatever it is given: `verifyLog`, `LogBook.log`, `judgeRecord`, `didDocument`, `operationalProofTime`. A rejection carries the path to the value at fault, a message and the clause it breaks: `L1 4.3 /2/controller/keys/0: control key … was not committed to by the event before`.
- **When a member's proof on a collective's event does not count, the rejection says why**: the key was removed, the member's log is not held or does not verify, the nesting is too deep.
- **`ownSignedTime` answers with a time or `undefined`.** Ask `operationalProofTime` about one proof to learn why it does not count.
- **A function that writes throws**: `signEvent` and `signEventSync` throw `OipError` for an event that is not well formed, before any signer is asked, and `TypeError` when there is no signer.
- **What is judged is a plain copy**, as in `@oip/core`. A verified log holds copies of its events, not the objects it was given.

## What a verified log does not tell you

- **That the mind is not duplicitous elsewhere.** A book resolves the branches it holds. Witnesses and anchors are how a verifier learns of others (Layer 1, 7).
- **That an alias is the mind's.** `didDocument` lists an alias only if the caller has verified it both ways (Layer 1, 5.3).
- **That a control key was destroyed.** A control key signs one event; whoever keeps it afterwards can sign a second event for the same position. Destroy it once its event is published (Layer 1, 7.4). The key store does this from M6.

## Limits

| Limit                                      | Value                                                                   | From         |
| ------------------------------------------ | ----------------------------------------------------------------------- | ------------ |
| Events in a log                            | 10,000 by default; set `maxEvents` to change it. Never fewer than 1,000 | Layer 1, 4.7 |
| Height of a collective                     | 4: four levels of member logs below it                                  | Layer 1, 4.7 |
| Proofs on an event                         | 256                                                                     | core 5.1     |
| Control keys revealed, and committed to    | 16 each                                                                 | Layer 1, 3.4 |
| Members of a collective                    | 256                                                                     | Layer 1, 3.4 |
| Operational, invocation and agreement keys | 64, 16 and 16                                                           | Layer 1, 3.5 |

## Tests

- The golden vectors: every log verifies and every address derives from its genesis; the DID documents reproduce; every identity case has the verdict the vectors give.
- Each rule of Layer 1, Sections 2 to 9 and of core Section 9, against logs written by test minds whose keys are derived from names. Malformed events are signed as the holder of the keys could sign them, so each is refused for its rule and not for its signature.
- Properties of the two formulas of time.
- Differential tests against the independent Python checker, in `@oip/conformance`: generated logs of key-controlled minds and of collectives, and records signed by a mind's own keys, each with something done to it. The two verdicts must be the same.
- No function that judges throws, with the stack all but spent or with input that throws when read.
