# ADR-0003: The evidence model in code

**Status:** Accepted, 17 November 2026 (M0). Implemented in M2.

## Context

OIP judges every rule about time on evidence of when a signature existed, never on the signer's own `created` (core Section 9). A stolen or removed key can write any date it likes. This is the part of the protocol that is easiest to get subtly wrong: one function that compares against `created`, or against the verifier's own late first sight of an event, reopens the backdating attacks the specification closes.

[BUILD.md](../../BUILD.md), Section 3.3, sets the design. This record fixes it as an interface before any verification code exists, so that every package is written against the same one.

## Decision

### One interface answers "when did this exist?"

```ts
/** What a verifier can show about when things existed (core 9.4). */
interface EvidenceView {
  /** The earliest time the verifier can show this proof existed, by proof digest. */
  proofSeen(digest: ProofDigest): Instant | undefined;
  /** The earliest time the verifier can show this identity event existed with valid proofs, by content ID. */
  eventSeen(contentId: ContentId): Instant | undefined;
}
```

- A proof is keyed by its digest, `"sha256:" + hex(SHA-256(JCS(proof)))`. Evidence for a record never covers a proof added to it later (core 9.4).
- An identity event is keyed by its content ID (core 9.5).
- `undefined` means the verifier holds no evidence. It never means "assume `created`".
- The answers come from the verifier's own first-seen store, the witnesses it trusts, anchored checkpoints and acknowledgements. Combining those sources is the caller's work; the pure packages only read the view.

### Time is a parameter

Every verification function takes `now` and an `EvidenceView`. No pure package reads the clock (enforced: [ADR-0001](0001-tooling.md)). A verifier that receives a proof live records its receipt time in its store first, and then verifies with a view that includes it.

### The two formulas exist once

`@oip/identity` implements, and every other package calls:

```
t(p)         = max(p.created, τ(p))                        core 9.3
eventTime(e) = max(e.created, τ(e), eventTime(prev))       core 9.5
```

- A proof whose `created` is more than 300 seconds after `τ(p)` counts for nothing (core 9.3). The same holds for an event (core 9.5).
- No other package compares a `created` with anything. A lint rule or a review check for stray comparisons is added with M2.

### Instants are exact

Timestamps carry up to nine fractional digits (core 1.4) and are compared as instants at full precision. An `Instant` is a `bigint` of nanoseconds since the epoch, behind a branded type, so that it cannot be mixed with a number of milliseconds. `Date` is not used: it has millisecond precision and reads the local environment.

### Holding the signer's log

Before counting a proof by a key of mind `X`, a verifier holds `X`'s log as a witness it trusts served it, with that witness's first-seen times (core 9.4). In code:

- log verification takes the log together with the evidence for its events, and returns a state that remembers each event's evaluation time;
- key validity (Layer 1, 6.1) takes that state, so it cannot be asked about a log whose times are unknown;
- the client fetches both from a resolver when it resolves, and never substitutes its own later first sight.

### The vectors use the same model

A case's `seen` map is an `EvidenceView`. A case with no `seen` uses the default convention: each proof and event was seen at its own `created`, as a witness that followed every log from the start would have. The conformance adapter passes `seen` through unchanged (`VerifierView.seen`), with `undefined` for the default.

### Services keep evidence append-only

Resolvers and indexers store first-seen times in append-only tables and serve them as `firstSeen` (Layer 1, 13.1 and 17.2). They never rewrite or lose them. M5 tests that restarts and lock contention lose none.

## Consequences

- Pure functions of `(records, evidence, now)` are deterministic, so they can be property-tested and compared with the Python checker case by case.
- Callers must build an `EvidenceView` before they can verify anything. That is deliberate: there is no convenient way to verify without saying what evidence is held.
- A verifier with no evidence for an old record can count its proofs only from now (core 9.7). The client makes this visible instead of hiding it.
