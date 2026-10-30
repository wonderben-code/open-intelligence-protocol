# OIP Test Vectors

**Revision 2026-10-31 · Status: Draft**

`vectors.json` contains deterministic records for the scenario used throughout the papers: Amina (a person), Lexis Ltd (an institution), the Lexis translation agent and two forks of it, a research agent, a 2-of-3 collective, and an institution with a 2-of-3 pre-rotation. It includes identity logs, two delegations forming a chain, a `Lineage` record, a location record, a Participant profile, a feed entry, a session and a context packet, and Intent, Offer, Commitment, Receipt and Collective records, with expected Layer 2 statuses at given times.

`oip_vectors.py` is a dependency-light Python implementation of the core algorithms. It generates the vectors and checks them:

```
python3 oip_vectors.py           # regenerate vectors.json and check it
python3 oip_vectors.py --check   # check the existing vectors.json
```

It needs only the `cryptography` package.

## What is checked

**Positive cases:** address derivation; identity logs with pre-rotation, a 2-of-3 rotation, a fork and a collective; lineage acknowledged by a `Fork` event and by a `Lineage` record; signatures with proof purposes and key validity; a feed entry committing to the proofs of what it publishes; co-signing without changing a content ID; delegation policy (120 and 500 USD within the agent's authority, 500.01 and 900 not); a two-step delegation chain; collective signing by threshold and by a charter role; revocations taking effect from their evidence rather than their date; Layer 2 status (`satisfied`, `open`, `expired`, `proposed`, `accepted`, `overdue`, `fulfilled`); and JCS canonicalisation.

**Negative cases** (`negative` in `vectors.json`): 29 records or logs that every implementation must reject, each with the reason. They cover duplicate control keys, forged rotations, zero and minority thresholds, a missing founder, events after `Retire`, the reserved `Merge` and `recovery`, wrong proof purposes, a delegate's key that is not in its log, delegates signing delegations, reserved blanket commands, policy bypasses (currency, negative and non-decimal amounts), backdated proofs by removed and compromised keys, an expired and a revoked delegation, a removed collective member, a proof from the future, an outsider closing someone else's Intent, and a short packet nonce.

Each negative case has a `kind`:
- `log`: the identity log in `log` must fail verification;
- `countsFor`: `record` must not count for `mind`, given the positive logs and records, any `extraLogs` (which replace the logs of the same minds), any `extraRecords`, and any `seen` times;
- `status`: the status of `of`, given `records` at time `at`, must be `expect`;
- `record`: `record` is malformed.

## Evaluation times

Time rules use evidence, not the signer's own `created` (core, Section 9). Unless a case gives `seen` times (content ID → time at which the verifier first obtained the record), a verifier is taken to have obtained each proof at that proof's `created` time. The time-based negative cases set `seen` later than `created`; the checker also confirms that each of them passes when first seen in time, so it fails only for the reason given.

## Conformance

Implementations claiming conformance must reproduce every value here that falls within the profiles they claim, and reject every negative case within those profiles.

**All keys are derived from public seeds** (`SHA-256("oip-test-vector:" + label)`). They are for testing only and must never be used for anything real.

Vectors for sealing (HPKE), checkpoints, sessions with resumption, DID documents and Ed25519 edge cases will be added by the reference implementation, in both this generator and the TypeScript tests.
