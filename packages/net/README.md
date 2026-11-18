# @oip/net

The Mind Network of the [Open Intelligence Protocol](../../README.md): feeds and checkpoints, locations and profiles, packets, sessions and sealing (Layer 1, Sections 10 and 12 to 16).

The package is pure. It does no I/O and never reads the clock: the time and the evidence are parameters.

It is being built in milestone M4, one part at a time. What is here is finished and tested; the rest of the list in [BUILD.md](../../BUILD.md) follows.

## What it exports

| Export                                                                         | What it does                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `verifyFeed`, `VerifiedFeed`, `FeedEntry`                                      | Verifies the entries held of a mind's feed: each signed by its author's own authority, from `seq` 0, each naming the one before. Reports feed equivocation, and what was given that is no entry (Layer 1, 10.1 to 10.4) |
| `verifyCheckpoint`, `CoveredFeed`                                              | Verifies a checkpoint against its author's feed, and gives the entries it covers and the proofs they commit to (Layer 1, 10.5)                                                                                          |
| `committedProofs`                                                              | The proofs on a record that a feed entry commits to (Layer 1, 10.1)                                                                                                                                                     |
| `currentLocation`, `HeldLocation`, `isStale`                                   | The current location record of a mind among those held, under the current-state rule, and whether a record is stale at a time the caller gives (Layer 1, 15.2)                                                          |
| `endpointsToTry`, `postUrl`, `webSocketUrl`, `KnownEndpoint`, `Binding`        | The endpoints of a location record in the order a sender tries them, and the URL each binding means (Layer 1, 15.1, 15.3)                                                                                               |
| `verifyParticipant`, `currentParticipant`, `HeldParticipant`, `ProfileSources` | Whether a profile counts for the mind it describes, and which of a mind's profiles is current (Layer 1, 16.1, 16.4)                                                                                                     |
| `merkleTreeHash`, `checkpointRoot`                                             | The Merkle Tree Hash of RFC 9162, 2.1.1, and the `root` a checkpoint signs over the entries of a feed, from their content IDs (Layer 1, 10.5)                                                                           |

## Feeds

- **A feed is verified from what is held.** Give `verifyFeed` every value you hold as an entry of the feed, in any order and in as many copies as you have. The same entry with other proofs is one entry, judged with all of them.
- **An entry counts from evidence.** Its time is the evaluation time of its author's signature (core 9.3), never the date written in it. An entry whose proof you have no evidence for is not signed, and the feed ends before it.
- **Equivocation stops the feed.** Two valid entries at one `seq` are both returned in `equivocation`, in the order of their content IDs, and the feed is verified up to the entry before them. Nothing in the entries tells which the mind stands by. After the mind declares the signing key compromised, the entries that key signed from that time on are no entries, and the feed goes on (Layer 1, 10.4).
- **A checkpoint is evidence of time only with a time.** `verifyCheckpoint` says which proofs a checkpoint commits to. Something else must show when the checkpoint existed, such as an anchor's attestation (Layer 1, 10.6). How an attestation is carried is not specified yet, so this package reads none.

## Locations and profiles

- **The current location record is the one with the highest `seq` that still counts.** A record signed with a key the mind has since removed counts no longer, however high its `seq`: nobody who once held a key can lock the mind out (Layer 1, 15.2, 15.4).
- **Staleness is the record's own claim.** `isStale` compares the time you give with the record's `created` plus its `ttl`. A stale record may still be used as a hint.
- **Mailboxes come last.** `endpointsToTry` puts them after the other endpoints, whatever their priority, and returns only them while the mind is `paused`. Endpoints with a binding this revision gives no meaning to are left out.
- **An `https` endpoint's `url` is a base.** `postUrl` adds `/inbox` and `webSocketUrl` adds `/ws` under the `wss` scheme, whether or not the base ends with a slash. A base with a query or a fragment is no base, and has no URL.
- **The current profile is named, not guessed.** It is the one the current location record names, and failing that the most recent one the mind's feed publishes that counts. A profile you hold that neither names is not current.
