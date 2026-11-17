# OIP Test Vectors

**Revision 2026-11-17 · Status: Draft**

`vectors.json` contains deterministic records for the scenario used throughout the papers: Amina (a person) and her assistant agent, Lexis Ltd (an institution), the Lexis translation agent and two forks of it, a research agent, a 2-of-3 collective, an institution with a 2-of-3 pre-rotation, and a gateway with an MCP server it bridges. It includes identity logs and DID documents, four delegations (two forming a chain, one for sending packets), a `Lineage` record, a location record, Participant profiles, feed entries and a checkpoint, a session, context packets (one sent on Amina's behalf), an `Ack`, a `Hello`, and Intent, Offer, Commitment, Receipt and Collective records, with expected Layer 2 statuses at given times.

`oip_vectors.py` is a dependency-light Python implementation of the core algorithms. It generates the vectors and checks them:

```
python3 oip_vectors.py           # regenerate vectors.json and check it
python3 oip_vectors.py --check   # check the existing vectors.json
python3 oip_vectors.py --judge   # judge cases given on standard input (see "Judging other cases")
```

It needs only the `cryptography` package. It applies core 4.4 itself (it decodes every key and signature point and requires order exactly L) before calling OpenSSL, which on its own accepts small-order and mixed-order points.

## What is checked

**Positive cases:** address derivation and canonical content IDs; identity logs with pre-rotation, a 2-of-3 rotation, forks, invocation keys and a collective; DID documents, current and versioned; lineage acknowledged by a `Fork` event and by a `Lineage` record; signatures with proof purposes and key validity; feed entries committing to the proofs of what they publish, and a checkpoint's Merkle root; a packet that opens its session, and its `Ack`; a packet sent on Amina's behalf under a `/oip/send` delegation; co-signing without changing a content ID; two agents signing one commitment for their principals, each carrying its delegation in its own proof; delegation policy (120 and 500 USD within the agent's authority, 500.01 and 900 not); a two-step delegation chain; collective signing by threshold and by a charter role; a mind bridged by its gateway; Layer 2 status (every state of Intents, Offers and Commitments: `open`, `satisfied`, `withdrawn`, `superseded`, `expired`, `exhausted`, `proposed`, `accepted`, `claimed-fulfilled`, `fulfilled`, `overdue`, `broken`, `disputed`, `cancelled`); and JCS canonicalisation.

**Must-accept cases** (`valid`): 15 cases that look suspicious but are valid:

- a collective's log after a member's backdated compromise claim, a receipt after a backdated key removal, a commitment after a backdated revocation, a duplicity resolved by first-seen evidence, and a record pinned before an unresolved duplicity;
- five records: one of a type an extension defines, listed in `critical`; one dated in year 0000; a rating of `-0`; one that nests exactly 64 deep; and a page of a log that carries an event nesting exactly 64 deep, so that the page nests 66 deep;
- five JSON texts: integers written with a fraction or an exponent, an integer written with 5,000 digits, escaped characters, one member name in different objects, and nesting exactly 64 deep.

**Negative cases** (`negative`): 72 records, logs or texts that every implementation must reject, each with the reason. They cover:
- identity logs: duplicate control keys, forged rotations, zero and minority thresholds, a missing founder, collective events signed with operational keys, events after `Retire`, the reserved `Merge` and `recovery`, a non-canonical content ID, a revoked key added again, a collective takeover with removed invocation keys, a collective genesis first seen after a founder removed its key, and a collective joining one that is not tall enough;
- Ed25519: the identity point as a key, a mixed-order key, `S` not reduced, `R` the identity point, and `R` with a small-order component;
- signatures and delegation: wrong proof purposes, a delegate's key that is not in its log, delegations listed outside the proof, delegates signing delegations, reserved blanket commands, a chain listed out of order, a delegation to oneself, policy bypasses (currency, negative and non-decimal amounts, a counterparty outside the policy, the firm paying instead of being paid, the agent dealing with itself, a negated comparison on a missing member), a charter role used without naming the charter, a packet claiming to be sent on someone's behalf without a delegation, and a key reference whose position wraps around in 64 bits;
- time: backdated proofs by removed and compromised keys, a backdated co-signature added to a record seen earlier, an expired and a revoked delegation, a removed collective member, proofs from the future and after a record's expiry, and a collective's location record after a member left;
- Layer 2 and the bridge: an outsider closing someone else's Intent, a compromise claim that turns a commitment `disputed`, a commitment whose author is not a party, an unresolved duplicity, a self-attested bridged mind, and a short packet nonce;
- the form of a record: an entry of `proof` that is not an object, an extension block whose name is not a namespace, a type no revision defines with no critical extension, nesting 65 deep, and a page that carries an event nesting 65 deep;
- the JSON profile (core Section 1): numbers with a fractional part, integers outside the safe range, an unpaired surrogate, a noncharacter in a string and in a member name, nesting 65 deep, and text that is not JSON. Duplicate member names are not among them, because core 1.1 says receivers SHOULD reject those.

**Controls** (`controls`): 22 negative cases, each changed only in the respect its reason names, which must be accepted. They show that each fails for its stated reason and nothing else: for example, the backdated proofs pass when first seen in time, the collective takeover passes when evidence shows it came before the key removals, the collective joining passes when the collective was founded tall enough, and each record with a signature that breaks core 4.4 counts when it carries an honest signature instead.

Each case has a `kind`, evaluated with the **baseline** (the identity logs and records that `baseline` names among the positive cases: `baseline.logs` and `baseline.records`) plus any `extraLogs` (which replace the logs of the same minds), `branches` (further, conflicting branches of a mind's log), `extraRecords` and `seen` times:
- `log`: the identity log in `log` must verify (must-accept, control) or fail verification (negative);
- `countsFor`: `record` must count for `mind` (must-accept, control) or must not (negative);
- `sentFor`: the packet in `record` must not count as sent on `mind`'s behalf (negative);
- `status`: the status of `of`, given `records` at time `at`, must be `expect`;
- `assurance`: the assurance level (Layer 0, 1.3) of the profile in `record` must be `expect`;
- `record`: `record` is well formed (must-accept, control) or malformed (negative). Whether its proofs verify is not the question;
- `json`: the text in `text` is JSON within the profile of core Section 1 (must-accept) or is not (negative). It needs no baseline. The text is given as a string because what it tests is lost on parsing: how a number is written, an escape, a depth of nesting.

## Judging other cases

`--judge` gives this implementation's verdict on any case in the format above, so that another implementation can compare its own verdicts with it on cases it generates (differential testing). Cases are judged against the existing `vectors.json`.

```
python3 oip_vectors.py --judge < case.json           # one case, or an array of cases
python3 oip_vectors.py --judge --lines < cases.jsonl  # one case per line; one verdict per line, as each is reached
```

Each verdict is one line of JSON:

```json
{"name": "delegation-to-self", "kind": "record", "holds": false}
```

- `holds` says whether the case's claim holds: the log verifies, the record counts for (or was sent for) the mind, the status or assurance is `expect`, the record is well formed, or the text is JSON within the profile.
- For `status` and `assurance` cases, `value` is the result computed, and `expect` may be left out.
- Input this implementation cannot process at all gives `"holds": false` with an `error`. An error is never an acceptance.

`record` cases use this generator's structural checks, which are the ones it relies on and not a full schema. The JSON Schemas in [`../schemas/`](../schemas/) check more. `json` cases are judged in full: the checker has its own parser for the profile (`read_json`), which shares nothing with the reference implementation's.

## Evaluation times

Time rules use evidence, not the signer's own `created` (core, Section 9). `seen` maps evidence to the earliest time the verifier can show, whether from itself, a witness it trusts or an anchor: a proof's digest (`"sha256:"` + hex of SHA-256 of the proof's canonical form) for a proof on a record, and the content ID for an identity event. Evidence for a record therefore never covers a proof added to it later. Unless a case gives `seen` times, a verifier is taken to have obtained each proof and identity event at its own `created` time, as a witness that has followed every log from the start would (core 9.4). A `seen` map is partial: it names only the evidence that differs, and every proof and event it does not name keeps that default. The time-based negative cases set `seen` later than `created`, and their controls set it in time.

## Conformance

Implementations claiming conformance must reproduce every value here that falls within the profiles they claim, accept every must-accept case and control, and reject every negative case within those profiles.

**All keys are derived from public seeds**: Ed25519 keys from `SHA-256("oip-test-vector:" + label)` and X25519 keys from `SHA-256("oip-test-vector-x25519:" + label)`, both listed in `keys`. They are for testing only and must never be used for anything real.

Vectors for sealing (HPKE) and sessions with resumption will be added by the reference implementation, in both this generator and the TypeScript tests.
