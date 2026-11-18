---
"@oip/net": minor
---

First version: the Mind Network (Layer 1, Sections 10 and 12 to 16).

- `merkleTreeHash`, `checkpointRoot`: the Merkle Tree Hash of RFC 9162 and the root a checkpoint signs over a feed's entries (Layer 1, 10.5).
- `verifyFeed`, `verifyCheckpoint`, `committedProofs`: a mind's public feed verified from the entries held, with feed equivocation reported and the entries of a compromised key left out; a checkpoint verified against the feed, with the proofs it commits to (Layer 1, 10.1 to 10.5).
- `currentLocation`, `isStale`, `endpointsToTry`, `postUrl`, `webSocketUrl`: the current location record of a mind under the current-state rule, when it goes stale, and its endpoints in the order a sender tries them (Layer 1, Section 15).
- `verifyParticipant`, `currentParticipant`: whether a profile counts for the mind it describes, and which profile is current (Layer 1, Section 16).
