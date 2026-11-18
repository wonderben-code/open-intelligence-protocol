# @oip/identity

Who a mind is, and which of its keys may sign: the rules of [Layer 1](../../spec/layer-1-mind-network.md), Sections 2 to 9, and of [OIP Core](../../spec/core.md), Section 9, in the [Open Intelligence Protocol](../../README.md).

`@oip/core` says whether a proof is a valid signature by the key it names. This package says whether that key was the mind's to sign with, **at the time the signature can be shown to have existed**.

- **Identity logs** (Layer 1, 3 and 4): write and sign the four events, and verify a log event by event into the state after each. Key-controlled minds rotate by pre-rotation; member-controlled minds, the collectives, are signed for by a majority of their members.
- **Evidence of time** (core 9): every rule about time is judged at an evaluation time taken from evidence, never from the date a signer wrote. The two formulas are here and nowhere else, and so is the one operation that records a verifier's own first sight: of what has verified, and of nothing else.
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
    const book = new LogBook(seen);
    // It obtained the log a second after each event was made, and again at
    // 13:00. Each time, an event is recorded as seen only once it has
    // verified, never on sight of its content, and the book holds the log
    // as it came, as known up to that time.
    const served: [unknown[], string][] = [
      [[genesis], "2026-11-17T09:00:01Z"],
      [[genesis, update], "2026-11-17T11:00:01Z"],
      [[genesis, update], "2026-11-17T13:00:00Z"],
    ];
    for (const [log, when] of served) {
      book.witness(log, at(when), seen);
    }
    const record = judgeRecord(intent);
    if (!record.ok) return "is not well formed";
    // Likewise the proofs on the record: those that verify, when it was obtained.
    witnessRecord(record.value, at(obtained), seen);
    const time = ownSignedTime(record.value, mind, book);
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

| Export                                                                                                 | What it does                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `LogBook`, `IdentityView`                                                                              | The logs a verifier holds: for each mind every event it has been shown, with its evidence. `log(mind)` verifies a log when first asked, its members' logs with it, and resolves duplicity. `hold`, `drop` and `forget` change what it holds and what it remembers. `witness` holds a copy and records the verifier's own first sight of what then verifies; `witnessHeld` records it for everything held |
| `witnessLog`, `witnessRecord`, `Replayed`                                                              | Records a verifier's own first sight of a log's events, or of a record's proofs: of those that verify, and of no other. `witnessLog` returns the events that verified, why the next one did not, and whether that event is invalid or undecided (Layer 1, 4.9), for the copy judged alone                                                                                                                |
| `divergence`                                                                                           | Where two verified logs of one mind part, and the two events they hold there: the evidence of duplicity a resolver publishes (Layer 1, 7.1)                                                                                                                                                                                                                                                              |
| `verifyLog`, `LogContext`, `VerifiedLog`, `LogEntry`, `IdentityState`                                  | Verifies one log (Layer 1, 4). The result has each event with the state after it and its evaluation time                                                                                                                                                                                                                                                                                                 |
| `latestState`, `entryAt`, `stateAt`, `childrenAt`, `revokedAt`, `removalTime`, `compromisedSince`      | Questions about a verified log: the state now, at a version, at a time; the children and the revoked keys by an event; when a key was removed; from when it is declared compromised                                                                                                                                                                                                                      |
| `judgeRecord`, `JudgedRecord`                                                                          | Validates a record and verifies each proof on it, once. The rest takes its result                                                                                                                                                                                                                                                                                                                        |
| `operationalProofTime`, `operationalProofs`, `CountedProof`, `CURRENT_STATE_TYPES`                     | Layer 1, 6.1: whether a proof is by a valid operational key, and its evaluation time                                                                                                                                                                                                                                                                                                                     |
| `disregardingCompromise`                                                                               | A view of the same logs and evidence with every compromise declaration (Layer 1, 6.2) disregarded. It answers one question, that of Layer 2, 8.3: whether a Commitment would be accepted had no party declared a key compromised. Ask nothing else of it                                                                                                                                                 |
| `ownSignedTime`, `collectiveSignedTime`                                                                | The earliest time a record is signed by a mind's own authority: one of its keys, or for a collective its threshold (Layer 1, 9.5)                                                                                                                                                                                                                                                                        |
| `EvidenceView`, `FirstSeen`, `earliestEvidence`                                                        | What a verifier can show about when a proof or an event existed (core 9.4)                                                                                                                                                                                                                                                                                                                               |
| `proofTime`, `eventTime`, `Evaluation`                                                                 | The two formulas: `t(p) = max(p.created, τ(p))` and the same for an event, never before the event before it (core 9.3, 9.5)                                                                                                                                                                                                                                                                              |
| `didDocument`, `DidResolution`                                                                         | The DID document of a mind, current or at a `versionId` (Layer 1, 5.2, 2.4)                                                                                                                                                                                                                                                                                                                              |
| `lineage`, `Lineage`                                                                                   | Whether each parent a mind names acknowledges it (Layer 1, 8.2)                                                                                                                                                                                                                                                                                                                                          |
| `draftGenesis`, `draftUpdate`, `draftFork`, `draftRetire`, `signEvent`, `signEventSync`, `EventSigner` | Writes the four events and signs them, with control keys or as a member                                                                                                                                                                                                                                                                                                                                  |
| `MAX_HEIGHT`, `MAX_LOG_EVENTS`, `MIN_ACCEPTED_LOG_EVENTS`                                              | Limits                                                                                                                                                                                                                                                                                                                                                                                                   |

The API report is [`etc/identity.api.md`](etc/identity.api.md).

## Evidence, and why there is no shortcut

Every function that judges takes an `EvidenceView`: for a proof, by its digest, and for an identity event, by its content ID, the earliest time the verifier can show it existed. The answers come from the verifier's own first sight, a witness it trusts, an anchored checkpoint or an acknowledgement (core 9.4). Combining them is the caller's work; `earliestEvidence` takes the earliest of several sources.

- **`undefined` means no evidence, and nothing counts without evidence.** It never means "assume the date the signer wrote". There is no function here that verifies without a view, by design ([ADR-0003](../../docs/adr/0003-evidence-model.md)).
- **Record first sight only of what has verified.** Evidence for an identity event is evidence that it existed _with proofs that make it valid_ (core 9.5), and an event's content ID does not cover its proofs. A verifier that noted the time it first saw an event's content, signed or not, would later judge a signature made with a removed key at that early time: the attack the whole model exists to stop (Layer 1, 9.6). So:
  - for a log that arrives, call `book.witness(events, now, seen)`. It holds the copy as it came, verifies what the book now holds as if each new event were first seen now, and records the events that verified;
  - for a record that arrives, call `judgeRecord` and then `witnessRecord(judged, now, seen)`, which records the proofs that verified;
  - `FirstSeen.sawEvent` and `sawProof` believe what they are told. Use them for times a witness you trust has given, never for what has just come in.
- **A log is held with the time up to which it is known** (`book.hold(events, asOf)`): when a witness the verifier trusts served it, or the present for a verifier that follows the log itself. A proof first seen after that time is not counted until the log is refreshed, because the log may lack the event that removed the key (core 9.4, Layer 1, 6.3). The same holds for the log of a collective whose threshold a proof is counted under, and for a member's log when its proof on a collective's event is judged.
- **The times of a log's events come from the same view.** A resolver serves its first-seen times with a log (Layer 1, 17.2); a client puts them in its view and never substitutes its own later first sight.

## What a book holds

- **Copies from a source you trust to serve the whole log**: a resolver you have chosen, or the mind itself. `asOf` says the log lacked nothing at that time, and no check can show that.
- **Its own copy.** `hold` copies the events it is given. Changing the array afterwards changes nothing in the book.
- **Everything it has been shown** (Layer 1, 4.9). `hold` adds a copy's events to what is held of the mind's log, each event in its position, with its proofs. It judges nothing and discards nothing. So an earlier state of the log takes nothing away, a copy that conflicts with what is held is kept beside it, the proofs of one event from two copies are kept together, and the order copies come in does not matter. Only a well-formed copy of an event adds its proofs (Layer 1, 7.1). One whose `proof` is wrong in any way (an entry that is no object, a number that is no integer, more than 1 MiB) adds nothing and spoils nothing, and what follows it in its copy is still held: an event is told by its content, which its `proof` is no part of. A value whose content is no object, is not plain data, or is larger than 1 MiB is no event of this version: it has no place, and nothing after it in that copy is held. If the verifier cannot read it (a later version, a type this revision does not define, a critical extension), it is still held where it stands, as an event the verifier cannot judge. A copy is read whole, however long it is. `drop(mind)` is how you say that what is held is wrong.
- **Judged when you ask** (Layer 1, 7.3). `log(mind)` goes through the events held, position by position, and an event can fail in two ways:
  - an **invalid** event is one the verifier can read, and whose fault can be seen in the log alone: it is malformed, out of place, or carries proofs that no evidence and no other log could make good. It is no event. The log is the events before it, and the copy takes nothing away from what other copies show;
  - an **undecided** event is every other that fails, because this verifier cannot judge it: it names a critical extension the verifier does not implement, or a type or a version of a later revision; or the verifier has no evidence for it; or a member's proof on it does not count by the member's log as the verifier holds it. It may be the event that removes a key, so the log is refused from there until the event can be judged.

  Where two events verify at one position, the one with the earlier evidence has it, never the longer branch or the later copy.

- **`book.witness(events, now, seen)` for a log that arrives, if you keep your own first sight.** It holds the copy as it came and records first sight of every event that verifies with all the proofs the book holds. So an event that reaches you in two copies, each with some of its proofs, is seen when the second arrives: a removal counts from the moment you first held it whole. It looks at that mind's events and at those of every mind held whose log rests on it: a collective's event that waited on a member's log is seen when the member's log arrives. After any other change that may let an event verify (a log held from a witness you trust, its first-seen times taken into your evidence and `forget()` called), call `book.witnessHeld(now, seen)`, which looks at everything held. `witnessLog` judges one copy alone; it says of the first event that fails whether it is invalid or undecided by that copy's proofs, and is for looking at a copy, not for taking one in.
- **One event nobody can read stops a mind, on purpose.** Anybody can write an event of the type `Merge`. Served by a source you trust for the whole log, it cannot be told from the mind's own event, and the mind is refused until the event can be judged or you drop the mind. The alternative is to go on counting a key that an event you could not read removed.
- **Verdicts, until a log they rest on changes.** Holding or dropping a log forgets the verdict on it and on every log that asked for it as a member's. The book cannot see its evidence change: call `forget()` when a time it has given may have moved, for example after taking in a witness's earlier first-seen times. If you keep your own first sight, call `witnessHeld` after it.
- **Bounds.** A book keeps every copy it is shown, however many: what it holds grows with what you give it, and it is for you to choose whose copies those are. It has one limit. For one event it holds the proofs that one record carries: 256, and 1 MiB with the event. Shown more than that by well-formed copies together, it cannot tell which to leave out, so it says so and refuses that mind until you drop it. A source that does this on purpose stops the mind for you, as one that serves an unreadable event does.
- **Cost.** `hold` reads a copy whole: a million values take seconds, and what a copy shows stays held until you drop the mind, the proofs on values that are no events among it. A verdict is for the whole log. When a copy adds an event or a proof, the next `log(mind)` verifies that log again from its genesis, and so does each collective that asked for it. A log followed one event at a time therefore costs the square of its length in all: about 12 seconds for 100 events. Hold a long log in batches.
- **Extensions.** A log with an event that lists an extension in `critical` verifies only for a verifier that implements it (core 8.3). Name what you implement in `understood`, for a book, for `verifyLog` and for `judgeRecord`. By default nothing is.

## Results and errors

- **A function that judges returns a result, and does not throw on what arrives from outside**: the events given to `verifyLog`, `witnessLog` and `hold`, the record given to `judgeRecord`, a mind's address, a version identifier. Those may be anything at all. The arguments a caller builds itself are another matter: a verified log, a judged record, a book or a view that is not one is a mistake in the calling program, and a `TypeError` ([ADR-0007](../../docs/adr/0007-programming-errors.md)). A rejection carries the path to the value at fault, a message and the clause it breaks: `L1 4.3 /2/controller/keys/0: control key … was not committed to by the event before`.
- **When a member's proof on a collective's event does not count, the rejection says why**: the key was removed, the member's log is not held or does not verify, the nesting is too deep.
- **`ownSignedTime` answers with a time or `undefined`.** Ask `operationalProofTime` about one proof to learn why it does not count.
- **A function that writes throws**: `signEvent` and `signEventSync` throw `OipError` for an event that is not well formed, before any signer is asked, and `TypeError` when there is no signer.
- **What is judged is a plain copy**, as in `@oip/core`. A verified log holds copies of its events, not the objects it was given.
- **What a book keeps is frozen.** A verified log, a judged record and every answer a book remembers, a rejection among them, are handed out as the book holds them, so none can be changed by whoever reads it. Copy before changing.
- **A clause names the rule broken, or the record that is malformed.** A refusal that comes from an event's schema cites the clause that defines the event (`L1 3.6` for a `Genesis`), with the path to the member at fault; a refusal that comes from a rule of verification cites that rule.

## What a verified log does not tell you

- **That the mind is not duplicitous elsewhere.** A book resolves the branches it holds. Witnesses and anchors are how a verifier learns of others (Layer 1, 7). A mind the book does find duplicitous has `duplicitous: true` on its log and in the metadata of its DID document.
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
| Keys revoked by one event                  | 80                                                                      | Layer 1, 3.7 |

## Tests

- The golden vectors: every log verifies and every address derives from its genesis; the DID documents reproduce; every identity case has the verdict the vectors give.
- Each rule of Layer 1, Sections 2 to 9 and of core Section 9, against logs written by test minds whose keys are derived from names. Malformed events are signed as the holder of the keys could sign them, so each is refused for its rule and not for its signature.
- Properties of the two formulas of time.
- Differential tests against the independent Python checker, in `@oip/conformance`: generated logs of key-controlled minds, of collectives and of collectives within collectives; records signed by a mind's own keys, pinned to a branch of a log, and signed under a collective's threshold; and lineages. The two verdicts must be the same, and so must the DID documents the two resolve.
- No function that judges throws, with the stack all but spent or with input that throws when read.
