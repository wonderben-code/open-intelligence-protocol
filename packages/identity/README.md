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

| Export                                                                                                           | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `LogBook`, `IdentityView`, `ReadingOptions`                                                                      | The logs a verifier holds: for each mind every event it has been shown, with its evidence. `log(mind)` verifies a log when first asked, its members' logs with it, and resolves duplicity. `hold`, `drop` and `forget` change what it holds and what it remembers. `witness` holds a copy and records the verifier's own first sight of what then verifies, for that mind and those that rest on it; `witnessHeld` records it for everything held. Both take `following`: the logs the verifier follows itself, known up to each reading |
| `witnessLog`, `witnessRecord`, `Replayed`                                                                        | Records a verifier's own first sight of a log's events, or of a record's proofs: of those that verify, and of no other. `witnessLog` returns the events that verified, why the next one did not, and whether that event is invalid or undecided (Layer 1, 4.9), for the copy judged alone                                                                                                                                                                                                                                                |
| `divergence`                                                                                                     | Where two verified logs of one mind part, and the two events they hold there: the evidence of duplicity a resolver publishes (Layer 1, 7.1)                                                                                                                                                                                                                                                                                                                                                                                              |
| `verifyLog`, `LogContext`, `VerifiedLog`, `LogEntry`, `IdentityState`                                            | Verifies one log (Layer 1, 4). The result has each event with the state after it and its evaluation time                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `latestState`, `entryAt`, `stateAt`, `childrenAt`, `revokedAt`, `removalTime`, `compromisedSince`                | Questions about a verified log: the state now, at a version, at a time; the children and the revoked keys by an event; when a key was removed; from when it is declared compromised                                                                                                                                                                                                                                                                                                                                                      |
| `judgeRecord`, `JudgedRecord`                                                                                    | Validates a record and verifies each proof on it, once. The rest takes its result                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `operationalProofTime`, `operationalProofEvaluation`, `operationalProofs`, `CountedProof`, `CURRENT_STATE_TYPES` | Layer 1, 6.1: whether a proof is by a valid operational key, and its evaluation time                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `requestKeyTime`                                                                                                 | Layer 1, 13.3: whether the key an authenticated HTTP request names is a valid operational key under the current-state rule                                                                                                                                                                                                                                                                                                                                                                                                               |
| `disregardingCompromise`                                                                                         | A view of the same logs and evidence with every compromise declaration (Layer 1, 6.2) disregarded. It answers one question, that of Layer 2, 8.3: whether a Commitment would be accepted had no party declared a key compromised. Ask nothing else of it                                                                                                                                                                                                                                                                                 |
| `ownSignedTime`, `collectiveSignedTime`                                                                          | The earliest time a record is signed by a mind's own authority: one of its keys, or for a collective its threshold (Layer 1, 9.5)                                                                                                                                                                                                                                                                                                                                                                                                        |
| `EvidenceView`, `FirstSeen`, `earliestEvidence`                                                                  | What a verifier can show about when a proof or an event existed (core 9.4)                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `proofTime`, `eventTime`, `Evaluation`                                                                           | The two formulas: `t(p) = max(p.created, τ(p))` and the same for an event, never before the event before it (core 9.3, 9.5)                                                                                                                                                                                                                                                                                                                                                                                                              |
| `didDocument`, `DidResolution`                                                                                   | The DID document of a mind, current or at a `versionId` (Layer 1, 5.2, 2.4)                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `lineage`, `Lineage`                                                                                             | Whether each parent a mind names acknowledges it (Layer 1, 8.2)                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `draftGenesis`, `draftUpdate`, `draftFork`, `draftRetire`, `signEvent`, `signEventSync`, `EventSigner`           | Writes the four events and signs them, with control keys or as a member                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `MAX_HEIGHT`, `MAX_LOG_EVENTS`, `MIN_ACCEPTED_LOG_EVENTS`                                                        | Limits                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

The API report is [`etc/identity.api.md`](etc/identity.api.md).

## Evidence, and why there is no shortcut

Every function that judges takes an `EvidenceView`: for a proof, by its digest, and for an identity event, by its content ID, the earliest time the verifier can show it existed. The answers come from the verifier's own first sight, a witness it trusts, an anchored checkpoint or an acknowledgement (core 9.4). Combining them is the caller's work; `earliestEvidence` takes the earliest of several sources.

- **`undefined` means no evidence, and nothing counts without evidence.** It never means "assume the date the signer wrote". There is no function here that verifies without a view, by design ([ADR-0003](../../docs/adr/0003-evidence-model.md)).
- **Record first sight only of what has verified.** Evidence for an identity event is evidence that it existed _with proofs that make it valid_ (core 9.5), and an event's content ID does not cover its proofs. A verifier that noted the time it first saw an event's content, signed or not, would later judge a signature made with a removed key at that early time: the attack the whole model exists to stop (Layer 1, 9.6). So:
  - for a log that arrives, call `book.witness(events, now, seen, { following })`. It holds the copy as it came, verifies what the book now holds as if each new event were first seen now, and records the events that verified. [What a book holds](#what-a-book-holds) says what else a verifier that is its own witness must do;
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

- **If you keep your own first sight**, you are your own witness (core 9.4). Three things are yours to do, and one is the book's:
  - **Take a copy in with `book.witness(events, now, seen, { following })`.** It holds the copy as it came and records first sight of every event that verifies with all the proofs the book holds and that you have not recorded. So an event that reaches you in two copies, each with some of its proofs, is seen when the second arrives: a removal counts from the moment you first held it whole. It looks at that mind's events, and at those of every mind held whose log rests on it or on a log that is now known further.
  - **Say which logs you follow, with every reading of your clock.** A collective's event verifies only when every log it rests on is known up to the time you see it (core 9.4). `following` names the minds whose logs you follow yourself: whatever is published of them reaches you. With each reading the book then knows every copy it holds of each up to `now`, every branch of a log held in two. Leave a member out, and its log is known only up to when you last held it: the collective's event waits for a reading that names the member, and a signature by a key the event removes that you first saw in between counts. Name only logs you do follow. One you fetched once may lack the event that removed a key, and to call it known up to now is to count that key. `following` is a list or a set of addresses, read to its end, or one address. Nothing moves back: a copy taken in at a reading earlier than the last is known only up to that reading. `hold` moves only the copy it is given: holding a log again by hand leaves the other branch of a duplicitous one where it was.
  - **Look at least every 300 seconds, with `book.witnessHeld(now, seen, { following })`.** It looks at everything held. An event dated more than 300 seconds ahead of your clock does not verify until your clock is within 300 seconds of its date (core 9.5). Seen then, it takes effect at its date. Seen later than its date, it takes effect when you see it, and a signature by a key it removes that you first saw in between counts. A verifier that looks at least every 300 seconds is never late. A collective's event dated ahead is open until its date: its members' proofs are judged at its date (Layer 1, 6.4), so a member that removes the key it signed with before then undoes the event. Look also after any other change that may let an event verify: a log held from a witness you trust, or its first-seen times taken into your evidence and `forget()` called.
  - **Your own sight is recorded beside whatever time your evidence gives.** If a witness you trust saw the event first, its time stands, and yours is what is left if you stop trusting that witness (Layer 1, 7.2). If the only time your evidence gives is later than your clock (a witness's clock runs ahead), the event is judged as seen at your reading, and recorded if it verifies so. An event dated more than 300 seconds ahead of your clock does not, whoever saw it: nothing is recorded of it until your clock is within 300 seconds of its date.

  `witnessLog` judges one copy alone, and says of the first event that fails whether it is invalid or undecided by that copy's proofs. It records first sight of what that copy alone verifies, which is right for a mind with keys of its own and one copy, and not for a verifier that holds copies in a book.

- **One event nobody can read stops a mind, on purpose.** Anybody can write an event of the type `Merge`. Served by a source you trust for the whole log, it cannot be told from the mind's own event, and the mind is refused until the event can be judged or you drop the mind. The alternative is to go on counting a key that an event you could not read removed.
- **Verdicts, until a log they rest on changes.** Holding or dropping a log forgets the verdict on it and on every log that asked for it as a member's. The book cannot see its evidence change: call `forget()` when a time it has given may have moved, for example after taking in a witness's earlier first-seen times. If you keep your own first sight, call `witnessHeld` after it.
- **Bounds.** A book keeps every copy it is shown, however many: what it holds grows with what you give it, and it is for you to choose whose copies those are. It has one limit. For one event it holds the proofs that one record carries: 256, and 1 MiB with the event. Shown more than that by well-formed copies together, it cannot tell which to leave out, so it says so and refuses that mind until you drop it. A source that does this on purpose stops the mind for you, as one that serves an unreadable event does. The book also remembers which minds held rest on which, as long as they are held.
- **Cost.** `hold` reads a copy whole: a million values take seconds, and what a copy shows stays held until you drop the mind, the proofs on values that are no events among it. A verdict is for the whole log. When a copy adds an event or a proof, the next `log(mind)` verifies that log again from its genesis, and so does each collective that asked for it. A log followed one event at a time therefore costs the square of its length in all: about 12 seconds for 100 events. Hold a long log in batches. `witness` and `witnessHeld` verify only the logs that have an event you have not recorded: a log that shows something new, once, and a log with an event that does not verify, at every look. Anyone whose copies you take in can add such an event to a log. A reading that names the logs you follow moves the time each is known up to, which forgets the verdict on it and on every log that asked for it: after each copy taken in, the next `log(mind)` of a followed mind verifies again. A resolver that follows many logs will want to keep its verdicts across readings (M5).
- **Extensions.** A log with an event that lists an extension in `critical` verifies only for a verifier that implements it (core 8.3). Name what you implement in `understood`, for a book, for `verifyLog` and for `judgeRecord`. By default nothing is.

## Results and errors

- **A function that judges returns a result, and does not throw on what arrives from outside**: the events given to `verifyLog`, `witnessLog` and `hold`, the record given to `judgeRecord`, a mind's address, a version identifier. Those may be anything at all. The arguments a caller builds itself are another matter: a verified log, a judged record, a book or a view that is not one is a mistake in the calling program, and a `TypeError` ([ADR-0007](../../docs/adr/0007-programming-errors.md)). A rejection carries the path to the value at fault, a message and the clause it breaks: `L1 4.3 /2/controller/keys/0: control key … was not committed to by the event before`.
- **When a member's proof on a collective's event does not count, the rejection says why**: the key was removed, the member's log is not held or does not verify, the nesting is too deep.
- **`ownSignedTime` answers with a time or `undefined`.** Ask `operationalProofTime` about one proof to learn why it does not count.
- **A function that writes throws**: `signEvent` and `signEventSync` throw `OipError` for an event that is not well formed, before any signer is asked, and `TypeError` when there is no signer.
- **A check that was cut short is refused, and nothing is kept of it.** With the call stack all but spent, or in a process where other code has put a `toJSON` on every object, a check cannot be made. `judgeRecord` and a book then refuse with the clause `implementation limit`. A book keeps no verdict, no copy and no first sight reached that way: ask again and it judges afresh ([ADR-0004](../../docs/adr/0004-error-model.md)).
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
- No function that judges throws, with the stack all but spent or with input that throws when read, and a book keeps nothing it concluded then. The spent stack is made in a process of its own (`test/spent-stack.node.ts`): the test runner reads a module's exports through getters that fail there. So the lines those tests reach are outside the coverage report and outside mutation testing. `test/cut-short.test.ts` makes the same faults in the runner, without the engine's help.
