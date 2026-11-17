# ADR-0008: The log book, and the time a log is known up to

**Status:** Accepted, 17 November 2026 (M2). It carries out [ADR-0003](0003-evidence-model.md) in `@oip/identity` and adds what building it showed.

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
- **What is remembered.** A log that verifies does so wherever it is asked from. One that fails may have failed for where it was asked from (the depth, or a mind being verified above it), so a failure is remembered only when the log was asked for directly.
- **Branches.** `holdBranch` adds a conflicting branch. The book resolves duplicity by the earlier evidence at the point of divergence, and never by length (Layer 1, 7.3). When the evidence cannot separate the branches, the log it gives stops before that point and keeps the later events of every branch, so that their removals and compromise declarations all apply.
- It is plain data in memory. It fetches nothing and reads no clock; the client and the services fill it.

`verifyLog` is the function underneath, for one log and a way to obtain a member's verified log. Most callers want the book.

### A log is held with the time it is known up to

`book.hold(events, asOf)`. `asOf` is when a witness the verifier trusts served the log, or the present for a verifier that follows the log itself. Key validity compares it with the evidence for the proof: a proof first seen after `asOf` does not count until the log is refreshed, because the log may lack the event that removed the key. A member's proof on a collective's event is held to the same rule, with the evidence for the event.

The comparison is with the evidence, `τ`, as core 9.4 says, and not with the evaluation time, which is later when a proof is dated up to 300 seconds ahead of the clock that received it. A verifier can therefore count a proof it has just received, whatever the signer's clock says. OEP-0002 records the narrow window this leaves as an open question.

### A record is judged once

`judgeRecord` validates a record and verifies every proof on it, and returns a `JudgedRecord`: the validated copy and the proofs that verified. Every question about who signed takes that, so nothing is validated or verified twice, and nothing can be asked about a record that was not validated.

### Verdicts are times

Whether a record counts for a mind is the question "from when?". `ownSignedTime` answers with the earliest evaluation time at which the mind's own authority signed the record, or `undefined`: one of its valid operational keys, or for a collective its threshold. `@oip/delegation` adds the times a delegation or a charter role gives, and the earliest of them all is the answer. Expiry (core 9.6) is applied to each time.

A verdict of `undefined` carries no reason. `operationalProofTime` judges one proof and says why it does not count.

### A verified log is one list

A `VerifiedLog` holds its events as entries, each with the state after it and its evaluation time. It has at least its genesis, by its type. A version identifier is looked up with `entryAt`.

### Nothing compares a `created`

The lint rule ADR-0003 promised is in `eslint.config.js`: in the pure packages a comparison that involves a `created` is refused, except in the two formulas, in the rule that a log's dates do not run backwards (Layer 1, 4.2), and in the rule that a proof is not dated before its record (core 5.7).

## Consequences

- A caller must say how fresh each log is. There is no default, as there is no default for evidence: the vectors' convention (everything seen when it was made, every log known in full) is written out in the conformance adapter, and nowhere in the package.
- A book answers from memory after the first question. Holding a new log for any mind forgets every answer, because any log may be a member of another.
- The first failure of a member's proof is reported with its own reason, so a rejected collective says which member's log, key or timing was at fault.
- Members' logs are verified again in each book. A resolver that serves many verifiers keeps its own verified logs; that is M5's work.

## Alternatives

- **Pass logs as a parameter of every function.** Each function would repeat the nesting, the cycle check and the resolution of branches, and a caller could give two functions two different views of the same mind.
- **Compare `asOf` with the evaluation time.** It closes the window for future-dated proofs and makes a verifier wait up to 300 seconds before counting a proof from a signer whose clock runs fast. Handshakes are signed and checked live, so this was set aside.
- **Return a reason with every verdict.** The cheapest answer to "does it count?" does not need one, and the reasons differ by path (own key, threshold, delegation, role). A caller that wants to explain asks about the proof it cares about.
