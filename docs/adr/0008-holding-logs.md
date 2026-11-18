# ADR-0008: The log book, and the time a log is known up to

**Status:** Accepted, 17 November 2026 (M2). It carries out [ADR-0003](0003-evidence-model.md) in `@oip/identity` and adds what building it, and three independent reviews of it, showed.

## Context

ADR-0003 fixed how time enters verification: an `EvidenceView`, two formulas, and the rule that a verifier holds a signer's log with its first-seen times before it counts a proof. Writing `@oip/identity` raised four questions it had left open.

1. **Who holds the logs?** Verifying a collective's log needs its members' logs, to four levels (Layer 1, 4.7). A member may have two conflicting logs (Layer 1, 7). Something must hold them, bound the nesting and resolve the conflict.
2. **How does the code know a log is fresh enough?** core 9.4 asks for the signer's log "as a witness it trusts served it at some time no earlier than `τ(p)`". A function that takes only a log and a proof cannot tell.
3. **How often is a record validated?** Whether a record counts for a mind is asked once for each party, each signer and each link of a delegation. Each answer starts from the same validated record and the same verified proofs.
4. **What does a verdict look like to the layers above?** `@oip/delegation` adds two more ways for a record to count for a mind, and must compose them with the ones here.

## Decision

### One object holds the logs and the evidence

`LogBook` holds, for each mind, one log or several conflicting branches, and the `EvidenceView` they are judged against. `log(mind)` verifies when first asked and remembers the answer.

- **Nesting.** A member's log is verified one level down, and no log is verified more than four levels below the one asked for. A mind that is already being verified is not verified again inside itself: no collective is a member of itself, directly or indirectly.
- **A log verifies only if every member's log it asks for does.** Every member signs the event that makes it one (Layer 1, 4.1, 4.4), so a log is asked for first by an event that cannot stand without it. Verification asks for each member's log once and stops at the first that does not verify. That bounds the work of a hostile set of logs to one failing log at each level, where judging every proof against a failing log cost the fourth power of the number of proofs.
- **What is remembered.** An answer can depend on where the log was asked from: a log below it was refused for the depth, or for being a mind already being verified above it. With branches held, even a log that verifies may then be another log than it is when asked for directly. An answer that met no such refusal is the log's own, and is kept. One that did is kept only when the log was asked for directly; below that it is remembered for the one question being answered, by the path it was asked along, so that a hostile set of branches cannot make the book verify the same log again and again.
- **For how long.** A verdict stands until a log it rests on is held anew or dropped. The book notes which logs each verdict asked for, and forgets only those verdicts. It cannot see its evidence change, so `forget()` clears every verdict; a caller that takes in earlier first-seen times calls it.
- **Its own copy.** The book copies the events it is given, and takes a mind's address from the copy it will verify. What a caller does to its array afterwards changes nothing, and a value that reads differently the second time cannot be held under one address and verified as another.
- **Nothing goes back.** `hold` refuses a copy that is an earlier state of the log held (Layer 1, 4.9). A source that lags or lies must not undo a removal the verifier knows of. "Earlier" is judged by what verifies: a copy that is the beginning of the one held, and verifies no further than it, is refused; a copy held that ends in an invalid event, or that lost its proofs on the way, gives way to a clean one. `drop` is how a caller says it means to go back.
- **Branches.** `holdBranch` adds a conflicting branch, each known up to its own time. The book resolves duplicity by the earlier evidence at the point of divergence, and never by length (Layer 1, 7.3). When the evidence cannot separate the branches, the log it gives stops before that point and keeps the later events of every branch, so that their removals and compromise declarations all apply.
- **A copy counts for the events it has that verify.** A copy that fails after the point of divergence still takes part, so appending a junk event to the honest branch does not hand the position to the other. But the book knows where a log ends only if it could verify a copy to its end: if a copy that is left once the evidence has decided has an event that did not verify, or more events than the book reads, the answer is that rejection and not a shorter log. A shorter log could be missing a removal. The copies that are left are those that hold the event that won a position; where the evidence cannot separate the events at a position, they are all the copies that were left before it (Layer 1, 7.3).
- **The book judges a copy as it is.** It does not shorten one, and it does not decide what to keep of a log that arrives. That is the next section but one.
- It is plain data in memory. It fetches nothing and reads no clock; the client and the services fill it.

`verifyLog` is the function underneath, for one log and a way to obtain a member's verified log. Most callers want the book.

### A log is held with the time it is known up to

`book.hold(events, asOf)`. `asOf` is when a witness the verifier trusts served the log, or the present for a verifier that follows the log itself. Key validity compares it with the evidence for the proof: a proof first seen after `asOf` does not count until the log is refreshed, because the log may lack the event that removed the key. Every log that decides whether a proof counts is held to that rule (core 9.4, as OEP-0002 extends it):

- the log of the mind whose key signed, against the evidence for the proof;
- the log of a collective under whose threshold the proof is counted, against the same evidence: otherwise a member the collective has removed signs for it against a verifier's older copy;
- a member's log, for its proof on a collective's event, against the latest evidence among that event and the events before it. An event takes effect no earlier than the event before it (core 9.5), so the member's log must be known that far.

The comparison is with the evidence, `τ`, as core 9.4 says, and not with the evaluation time, which is later when a proof is dated up to 300 seconds ahead of the clock that received it. A verifier can therefore count a proof it has just received, whatever the signer's clock says. OEP-0002 records the narrow window this leaves as an open question.

**No function takes `now`.** ADR-0003 and BUILD.md 3.3 said that every verification function takes `now` and an `EvidenceView`. Building it showed that "now" is not one time: each log is known up to its own. So the functions that judge take the view and, for each log, `asOf`. The present enters in one place only, where a verifier records its own first sight.

### First sight is recorded only of what has verified

Evidence for an identity event is evidence that it existed with proofs that make it valid (core 9.5). An event's content ID does not cover its proofs. A verifier that recorded the time it first saw an event's content would judge a proof added later at that early time, and a thief holding a removed invocation key could then sign a collective's event that was shown to the verifier, unsigned, before the key was removed. That is the attack of Layer 1, 9.6.

`witnessLog(events, now, seen)` is therefore the operation for a log that arrives. It verifies the log with `now` standing in for the first sight of each event not seen before, records the events that verified, and returns them with the reason the next event did not verify, if there is one. `witnessRecord` does the same for the proofs on a judged record. `FirstSeen.sawEvent` and `sawProof` stay, for times a trusted witness has given; they believe what they are told, and their documentation says so.

### An event that fails is invalid, or undecided

The second review's advice, "hold what `witnessLog` found to verify", was wrong, and the third review showed how. If the first event that fails is one the verifier cannot judge, the events before it are a state the mind may have left: the event may remove a key, and a verifier that held the shorter log as known up to now went on counting that key. Refusing every copy with a failing event is safe, and lets anyone who can append one junk event to a copy in transit deny a mind to the verifier that receives it.

Layer 1, 4.9 (OEP-0002, item 19) tells the two apart, and the code follows it.

- **Invalid** is what is wrong for every verifier: the event is malformed, does not follow the event before it, or, for a key-controlled mind, is not signed by the keys the log committed to. That last check is made with every proof that verifies and no evidence at all, so it is a fact about the event.
- **Undecided** is everything that depends on this verifier: its evidence (none for the event, or a date or an expiry that other evidence would judge otherwise), a member's log it does not hold or holds too old a copy of, a critical extension it does not implement, a type or a version this revision does not define, a log longer than it reads. A collective's event that fails for its members' proofs is undecided when a proof was left out for its date or a member's log was wanting, and invalid when no reading of the evidence could have made it count.
- An event is asked about its critical extensions last, after its signatures. Anybody can write an event that names one; unsigned, it is junk like any other.

`witnessLog` reports it (`undecided`) and says what to hold (`toHold`): the log as it came if nothing failed or the failing event is undecided, and the events before an invalid event. A log held with an undecided event is refused by the book until the event can be judged, which is what 4.9 requires.

The book itself stays strict: a copy with any event that does not verify is a rejection. Section 4 says such a log is rejected, the vectors give the copies a verifier holds and expect one answer, and a book that shortened copies by itself would hide from its caller that a source is serving something wrong. What to keep is decided once, at intake.

`hold` is for a log from a source the verifier trusts to serve the whole of it. `asOf` asserts that the log lacked nothing at that time, and nothing in the log can show it.

### Extensions a verifier does not implement

core 8.3 forbids treating a record as valid for any decision when it lists, in `critical`, an extension the implementation does not understand. `verifyLog`, `LogBook` and `judgeRecord` take the namespaces the caller implements (`understood`), and refuse an event or a record that lists another. The default is none. For an identity event the decision is whether the log verifies, so such a log is rejected (Layer 1, 4.8).

### A record is judged once

`judgeRecord` validates a record and verifies every proof on it, and returns a `JudgedRecord`: the validated copy and the proofs that verified. Every question about who signed takes that, so nothing is validated or verified twice, and nothing can be asked about a record that was not validated.

### Verdicts are times

Whether a record counts for a mind is the question "from when?". `ownSignedTime` answers with the earliest evaluation time at which the mind's own authority signed the record, or `undefined`: one of its valid operational keys, or for a collective its threshold. `@oip/delegation` adds the times a delegation or a charter role gives, and the earliest of them all is the answer. Expiry (core 9.6) is applied to each time.

A verdict of `undefined` carries no reason. `operationalProofTime` judges one proof and says why it does not count.

### A verified log is one list

A `VerifiedLog` holds its events as entries, each with the state after it and its evaluation time. It has at least its genesis, by its type. A version identifier is looked up with `entryAt`.

A state is of bounded size, however long the log: every set in it has a limit in Layer 1, Section 3. The two things that grow with a log, the children it has acknowledged and the keys it has revoked, are held once, by the log, each with the position of its event; `childrenAt` and `revokedAt` give what a state had. A copy in each state would cost the square of the log's length to keep, which a hostile log of small events could turn into gigabytes.

### What is handed out is frozen

A verified log and a judged record are also what the book keeps. Both are frozen, with everything in them, so a caller cannot change a verdict that the next caller will be given.

### A tripwire on comparing a `created`

The lint rule ADR-0003 promised is in `eslint.config.js`: in the pure packages a comparison that involves a `created` is refused, except in `evidence.ts`, which holds the two formulas and the rule that a log's dates do not run backwards (Layer 1, 4.2), and in the one file of `@oip/core` with the rule that a proof is not dated before its record (core 5.7). The file that judges members' proofs is not exempt.

It is a tripwire and no more. It catches `proof.created < removed`, the first thing a tired author writes. It does not catch a renamed local, a subtraction, an equality or a helper that takes the value. What stands behind it is the review of every change to these packages, and the rule that the two formulas are the only code that reads a `created` for a decision about time.

## Consequences

- A caller must say how fresh each log is. There is no default, as there is no default for evidence: the vectors' convention (everything seen when it was made, every log known in full) is written out in the conformance adapter, and nowhere in the package.
- A book answers from memory after the first question. Holding or dropping a log forgets the answers that rested on it, and no others.
- A caller holds what `witnessLog` says to hold. The book judges whatever it holds, so a log held with an event that does not verify is refused until the caller holds another copy.
- The first failure of a member's proof is reported with its own reason, so a rejected collective says which member's log, key or timing was at fault.
- Members' logs are verified again in each book. A resolver that serves many verifiers keeps its own verified logs; that is M5's work.

## Alternatives

- **Pass logs as a parameter of every function.** Each function would repeat the nesting, the cycle check and the resolution of branches, and a caller could give two functions two different views of the same mind.
- **Compare `asOf` with the evaluation time.** It closes the window for future-dated proofs and makes a verifier wait up to 300 seconds before counting a proof from a signer whose clock runs fast. Handshakes are signed and checked live, so this was set aside.
- **Return a reason with every verdict.** The cheapest answer to "does it count?" does not need one, and the reasons differ by path (own key, threshold, delegation, role). A caller that wants to explain asks about the proof it cares about.
