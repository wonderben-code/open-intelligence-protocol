---
"@oip/net": minor
---

First version: the Mind Network (Layer 1, Sections 10 and 12 to 16).

- `merkleTreeHash`, `checkpointRoot`: the Merkle Tree Hash of RFC 9162 and the root a checkpoint signs over a feed's entries (Layer 1, 10.5).
- `verifyFeed`, `verifyCheckpoint`, `committedProofs`: a mind's public feed verified from the entries held, with feed equivocation reported and the entries of a compromised key left out; a checkpoint verified against the feed, with the proofs it commits to (Layer 1, 10.1 to 10.5).
