# @oip/net

The Mind Network of the [Open Intelligence Protocol](../../README.md): feeds and checkpoints, locations and profiles, packets, sessions and sealing (Layer 1, Sections 10 and 12 to 16).

The package is pure. It does no I/O and never reads the clock: the time and the evidence are parameters.

It is being built in milestone M4, one part at a time. What is here is finished and tested; the rest of the list in [BUILD.md](../../BUILD.md) follows.

## What it exports

| Export                                    | What it does                                                                                                                                                                                                            |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `verifyFeed`, `VerifiedFeed`, `FeedEntry` | Verifies the entries held of a mind's feed: each signed by its author's own authority, from `seq` 0, each naming the one before. Reports feed equivocation, and what was given that is no entry (Layer 1, 10.1 to 10.4) |
| `verifyCheckpoint`, `CoveredFeed`         | Verifies a checkpoint against its author's feed, and gives the entries it covers and the proofs they commit to (Layer 1, 10.5)                                                                                          |
| `committedProofs`                         | The proofs on a record that a feed entry commits to (Layer 1, 10.1)                                                                                                                                                     |
| `merkleTreeHash`, `checkpointRoot`        | The Merkle Tree Hash of RFC 9162, 2.1.1, and the `root` a checkpoint signs over the entries of a feed, from their content IDs (Layer 1, 10.5)                                                                           |

## Feeds

- **A feed is verified from what is held.** Give `verifyFeed` every value you hold as an entry of the feed, in any order and in as many copies as you have. The same entry with other proofs is one entry, judged with all of them.
- **An entry counts from evidence.** Its time is the evaluation time of its author's signature (core 9.3), never the date written in it. An entry whose proof you have no evidence for is not signed, and the feed ends before it.
- **Equivocation stops the feed.** Two valid entries at one `seq` are both returned in `equivocation`, in the order of their content IDs, and the feed is verified up to the entry before them. Nothing in the entries tells which the mind stands by. After the mind declares the signing key compromised, the entries that key signed from that time on are no entries, and the feed goes on (Layer 1, 10.4).
- **A checkpoint is evidence of time only with a time.** `verifyCheckpoint` says which proofs a checkpoint commits to. Something else must show when the checkpoint existed, such as an anchor's attestation (Layer 1, 10.6). How an attestation is carried is not specified yet, so this package reads none.
