---
"@oip/core": minor
---

- A signature that verified is remembered. `verifyEd25519` checks a signature once: a yes is kept under the signature, the message and the key together, and given at once when the same three come again. A no is never kept. So a log, a record or a request that is read a second time costs its reading and its hashing, and not its signatures again. A resolver verified each published log four to five times over, and in full again when the same bundle was published once more; it now verifies each signature once.
- `SIGNATURE_CACHE_SIZE`: how many signatures are remembered, 16,384. The least recently used are forgotten.
- `forgetVerifiedSignatures`: forgets them all. Nothing but time depends on what is remembered, so only a measurement needs it.
