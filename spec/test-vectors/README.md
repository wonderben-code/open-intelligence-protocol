# OIP Test Vectors

**Revision 2026-11-17 · Status: Draft**

`vectors.json` contains deterministic records for the scenario used throughout the papers: Amina (a person) and her assistant agent, Lexis Ltd (an institution), the Lexis translation agent and two forks of it, a research agent, a 2-of-3 collective, and an institution with a 2-of-3 pre-rotation. It includes identity logs and DID documents, three delegations (two forming a chain), a `Lineage` record, a location record, a Participant profile, two feed entries and a checkpoint, a session, a context packet, its `Ack`, a `Hello`, and Intent, Offer, Commitment, Receipt and Collective records, with expected Layer 2 statuses at given times.

`oip_vectors.py` is a dependency-light Python implementation of the core algorithms. It generates the vectors and checks them:

```
python3 oip_vectors.py           # regenerate vectors.json and check it
python3 oip_vectors.py --check   # check the existing vectors.json
```

It needs only the `cryptography` package.

## What is checked

**Positive cases:** address derivation and canonical content IDs; identity logs with pre-rotation, a 2-of-3 rotation, forks, invocation keys and a collective; DID documents, current and versioned; lineage acknowledged by a `Fork` event and by a `Lineage` record; signatures with proof purposes and key validity; feed entries committing to the proofs of what they publish, and a checkpoint's Merkle root; a packet that opens its session, and its `Ack`; co-signing without changing a content ID; two agents signing one commitment for their principals, each carrying its delegation in its own proof; delegation policy (120 and 500 USD within the agent's authority, 500.01 and 900 not); a two-step delegation chain; collective signing by threshold and by a charter role; Layer 2 status (`satisfied`, `withdrawn`, `superseded`, `open`, `expired`, `proposed`, `accepted`, `overdue`, `fulfilled`); and JCS canonicalisation.

**Must-accept cases** (`valid`): records that look suspicious but are valid: a collective's log after a member's backdated compromise claim, a receipt after a backdated key removal, and a commitment after a backdated revocation.

**Negative cases** (`negative`): 36 records or logs that every implementation must reject, each with the reason. They cover duplicate control keys, forged rotations, zero and minority thresholds, a missing founder, collective events signed with operational keys, events after `Retire`, the reserved `Merge` and `recovery`, a non-canonical content ID, a revoked key added again, wrong proof purposes, a delegate's key that is not in its log, delegations listed outside the proof, delegates signing delegations, reserved blanket commands, policy bypasses (currency, negative and non-decimal amounts, a counterparty outside the policy), backdated proofs by removed and compromised keys, an expired and a revoked delegation, a removed collective member, proofs from the future and after a record's expiry, an outsider closing someone else's Intent, a compromise claim that turns a commitment `disputed`, and a short packet nonce.

Each case has a `kind`, evaluated with the positive logs and records plus any `extraLogs` (which replace the logs of the same minds), `extraRecords` and `seen` times:
- `log`: the identity log in `log` must verify (must-accept) or fail verification (negative);
- `countsFor`: `record` must count for `mind` (must-accept) or must not (negative);
- `status`: the status of `of`, given `records` at time `at`, must be `expect`;
- `record`: `record` is malformed.

## Evaluation times

Time rules use evidence, not the signer's own `created` (core, Section 9). Unless a case gives `seen` times (content ID → time at which the verifier first obtained the record), a verifier is taken to have obtained each proof at that proof's `created` time. The time-based negative cases set `seen` later than `created`; the checker also confirms that each of them passes when first seen in time, so it fails only for the reason given.

## Conformance

Implementations claiming conformance must reproduce every value here that falls within the profiles they claim, accept every must-accept case and reject every negative case within those profiles.

**All keys are derived from public seeds**: Ed25519 keys from `SHA-256("oip-test-vector:" + label)` and X25519 keys from `SHA-256("oip-test-vector-x25519:" + label)`, both listed in `keys`. They are for testing only and must never be used for anything real.

Vectors for sealing (HPKE), sessions with resumption and Ed25519 edge cases will be added by the reference implementation, in both this generator and the TypeScript tests.
