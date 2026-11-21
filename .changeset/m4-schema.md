---
"@oip/schema": minor
---

An `Ack` may carry `proofs`: at most 256 digests of the proofs the packet carried on itself when it was received (Layer 1, 13.2; OEP-0004). An `Ack` without it is as valid as before.
