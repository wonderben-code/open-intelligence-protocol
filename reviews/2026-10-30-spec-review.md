# OIP specification review: revision 2026-10-30

**Status: IN PROGRESS.** This file is being written incrementally. The final verdict is at the end once complete.

Scope: `spec/README.md`, `spec/core.md`, `spec/layer-1-mind-network.md` (L1), `spec/layer-2-mind-web.md` (L2), `spec/layer-0-bridge.md` (L0), checked against `spec/test-vectors/vectors.json` and `oip_vectors.py`. Read from the position of an engineer who must implement the protocol exactly from the text.

## Critical (findings so far)

**C1. Rules keyed to a self-asserted `created` can be bypassed by backdating.** Affects L1 6.1, 6.3, 9.4 and 11.4 (items 5 and 7), and core 9.2.
- *Thief:* someone holding a stolen operational key signs a Commitment, Delegation or Packet. They pin an old `versionId` and set the proof `created` before `compromisedSince`. Under L1 6.1 the proof is valid. Revocation only protects the L1 6.2 record types.
- *Delegate:* L1 11.4 items 5 and 7 check expiry, `notBefore` and revocation against `r.created`. The delegate writes `r.created`, so expired or revoked delegations keep working. L1 11.5 calls short expiry "the primary defence", but it defends nothing.
- *Removed key:* under L1 6.3, a key removed without `compromisedSince` stays valid forever for proofs pinned to older versions. After an L0 6 custody handover, the gateway can keep signing as the person. A former employee's device key can keep signing for the institution.
- *Repudiation:* a signer can publish an `Update` that revokes its own key with a backdated `compromisedSince`. Its proof on an accepted Commitment then stops counting, and the status falls back to `proposed`. If that key signed a collective's genesis or a later event, the collective's log fails L1 4.1/4.4, and the collective and everything it signed become invalid.
- *Fix:* see the final version below.

**C2. A delegation policy can be bypassed with non-decimal strings.** Affects L1 11.3 and L2 5.1.

**C3. Any third party can change the status of another mind's Intent or Offer.** Affects L2 8.1 and 8.2.

**C4. The test-vector packet is invalid under the spec**, yet `spec/README.md` requires implementations to reproduce it.

**C5. L1 6.2 invalidates a mind's feed history, checkpoints and Acks on every routine key rotation.**

(Details, evidence and fixes are being written; see the final version below.)
