# @oip/net

The Mind Network of the [Open Intelligence Protocol](../../README.md): feeds and checkpoints, locations and profiles, packets, sessions and sealing (Layer 1, Sections 10 and 12 to 16).

The package is pure. It does no I/O and never reads the clock: the time and the evidence are parameters.

It is being built in milestone M4, one part at a time. What is here is finished and tested; the rest of the list in [BUILD.md](../../BUILD.md) follows.

## What it exports

| Export                                                                                                         | What it does                                                                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `verifyFeed`, `VerifiedFeed`, `FeedEntry`                                                                      | Verifies the entries held of a mind's feed: each signed by its author's own authority, from `seq` 0, each naming the one before. Reports feed equivocation, and what was given that is no entry (Layer 1, 10.1 to 10.4) |
| `verifyCheckpoint`, `CoveredFeed`                                                                              | Verifies a checkpoint against its author's feed, and gives the entries it covers and the proofs they commit to (Layer 1, 10.5)                                                                                          |
| `committedProofs`                                                                                              | The proofs on a record that a feed entry commits to (Layer 1, 10.1)                                                                                                                                                     |
| `currentLocation`, `HeldLocation`, `isStale`                                                                   | The current location record of a mind among those held, under the current-state rule, and whether a record is stale at a time the caller gives (Layer 1, 15.2)                                                          |
| `endpointsToTry`, `postUrl`, `webSocketUrl`, `KnownEndpoint`, `Binding`                                        | The endpoints of a location record in the order a sender tries them, and the URL each binding means (Layer 1, 15.1, 15.3)                                                                                               |
| `verifyParticipant`, `currentParticipant`, `HeldParticipant`, `ProfileSources`                                 | Whether a profile counts for the mind it describes, and which of a mind's profiles is current (Layer 1, 16.1, 16.4)                                                                                                     |
| `merkleTreeHash`, `checkpointRoot`                                                                             | The Merkle Tree Hash of RFC 9162, 2.1.1, and the `root` a checkpoint signs over the entries of a feed, from their content IDs (Layer 1, 10.5)                                                                           |
| `receivePacket`, `Receiver`, `ReceivedPacket`, `packetDates`, `PacketClock`                                    | Judges a packet that has arrived, or a `Forwarded` record that carries one: addressed to the receiver, within its dates, signed by its sender, and whether it was accepted before (Layer 1, 12.4)                       |
| `AcceptedPackets`                                                                                              | The packets a receiver has accepted, each remembered until it can no longer be accepted (Layer 1, 12.4)                                                                                                                 |
| `Sessions`, `Placed`, `ChainEquivocation`, `SessionLimits`, `DEFAULT_SESSION_LIMITS`, `SendingChain`           | The sessions a receiver follows: each sender's packets in order, duplicates, gaps and equivocation, and the `Resume` that says where each chain stands (Layer 1, 14.2 to 14.4)                                          |
| `sessionCarried`, `recordsCarried`                                                                             | The `Session` record a packet carries for its session, and the records of one type among its content (Layer 1, 12.2, 14.2)                                                                                              |
| `lacking`, `OwnChain`                                                                                          | Which of a mind's own packets the sender of a `Resume` lacks (Layer 1, 14.4)                                                                                                                                            |
| `verifyBranch`, `ProposedBranch`                                                                               | Judges a fork's proposal to go on from one of its parent's sessions (Layer 1, 14.5)                                                                                                                                     |
| `sealPacket`, `receiveSealed`, `SealDraft`, `SealedReceiver`, `ReceivedSealed`                                 | Seals a signed packet to one of its recipient's agreement keys, and opens a `Sealed` record to a packet that is then judged as any other (Layer 1, 12.6)                                                                |
| `draftAck`, `verifyAck`, `acknowledges`, `ackEvidence`, `VerifiedAck`, `AckEvidence`, `AckDraft`, `AckContext` | Writes the `Ack` for a packet received, judges one, and says which proofs it is evidence for (Layer 1, 13.2; core 9.4)                                                                                                  |
| `verifyHello`, `HelloServer`, `Authenticated`, `Challenges`, `IssuedChallenges`                                | Judges the `Hello` a client sends in answer to a server's challenge, and remembers the challenges a server has issued (Layer 1, 13.3)                                                                                   |

## Feeds

- **A feed is verified from what is held.** Give `verifyFeed` every value you hold as an entry of the feed, in any order and in as many copies as you have. The same entry with other proofs is one entry, judged with all of them.
- **An entry counts from evidence.** Its time is the evaluation time of its author's signature (core 9.3), never the date written in it. An entry whose proof you have no evidence for is not signed, and the feed ends before it.
- **Equivocation stops the feed.** Two valid entries at one `seq` are both returned in `equivocation`, in the order of their content IDs, and the feed is verified up to the entry before them. Nothing in the entries tells which the mind stands by. After the mind declares the signing key compromised, the entries that key signed from that time on are no entries, and the feed goes on (Layer 1, 10.4).
- **A checkpoint is evidence of time only with a time.** `verifyCheckpoint` says which proofs a checkpoint commits to. Something else must show when the checkpoint existed, such as an anchor's attestation (Layer 1, 10.6). How an attestation is carried is not specified yet, so this package reads none.

## Packets

- **`receivePacket` is the gate.** Give it what arrived, as parsed, and a `Receiver`: your address, your clock's reading, the logs you hold, and what you remember. It answers with the packet, or with the reason it is rejected. It checks, in order: the form, the address, the dates, the sender's signature, and last whether you accepted the packet before.
- **The sender's signature counts on your evidence.** Pass your own record of first sight as `seen`, and the gate records the packet's proofs as seen now, once the address and the dates have passed. A packet for somebody else, or one that is too old, adds nothing to what you keep. Leave `seen` out and you record first sight yourself: with no evidence for a proof, no packet counts (core 9.3).
- **A sender that is a collective signs by its threshold** (Layer 1, 9.5), as for any record of its own.
- **A duplicate is an answer, not a rejection.** `duplicate` is `true` for a packet you accepted before. Discard it: do not act on it again. You may acknowledge it again. A copy with a broken proof has the same content ID as the genuine packet, and is rejected for its proof, so it can never stand in for it.
- **Remember what you accept.** Call `accepted.record(received)` before you act on a packet. `AcceptedPackets` keeps each until `forgetAfter`: 300 seconds after its `expires`, or its `created` plus your window for a packet that states no `expires`. Call `forget(now)` as your clock moves. It grows with the packets you accept, so limit how many you take from one sender.
- **A packet addressed to a query comes through a broker.** It is accepted only inside a `Forwarded` record that is addressed to you and signed by its broker, from a broker the packet lists when it lists any, and for an hour at most after it was made. A packet addressed by a list stands by its own proof however it arrived.
- **What a packet carries is data** (Layer 1, 12.5). The gate reads nothing in `content`. A record carried there has the standing its own proofs give it, and none from the packet.

## Sessions

- **A `Sessions` is one participant's.** Make it with your own address: `new Sessions(me)`. It follows the sessions you are a participant of. Every packet of a session is addressed to every participant, so a participant can hold each chain whole; a recipient that is no participant cannot, and its `Sessions` follows nothing of that session.
- **Give `Sessions.take` every session packet the gate accepted**, duplicates too. It answers `in order` with the packets to deliver (this one, and any that had waited on it), `duplicate`, `waiting` when there is a gap before it, or `equivocation`.
- **A chain is judged as a feed is.** A packet has a place only as a link: at `seq` 0 with no `prev`, or after the link its `prev` names. So the order packets arrive in does not change the chain. A packet that names another `prev` is rejected, wherever it claims to stand.
- **Two links at one place stop the chain.** The answer names both by content ID, in order, and every later packet of that chain gets the same answer. What was delivered before it was found stays delivered.
- **A gap is for a `Resume` to fill.** `sessions.resume(id, lastSent, created)` writes one. `lacking(resume, own)` tells the mind that receives one which of its own packets to send again, and refuses a `Resume` that names a packet the chain does not have at that place. `sessions.against(resume, from)` says how its sender's own claim stands against what you hold.
- **The `Session` record comes with the first packet.** A packet of a session you do not hold is rejected unless it carries the record (Layer 1, 14.2). Once you hold it, a packet that leaves it out is taken.
- **An old session packet is told by its chain.** Pass `sessions.holdsChain` to the gate as `holdsChain`. A packet that states no `expires` and is older than your window is then accepted while you hold its chain, and `take` answers `duplicate` for it.
- **A fork proposes, and sends nothing in its parent's sessions.** A fork has an address of its own, so it is no participant of them, and `take` gives its packets no place. `verifyBranch` judges the `Branch` record it may send instead: the session is one you hold, the parent is a participant, `fork` names the parent's `Fork` event for the sender, and the lineage is acknowledged (Layer 1, 8.2). Whether you then open a new session with the fork is yours to decide.
- **Bounds.** By default a `Sessions` holds at most 1,024 sessions, 16 chains for one sender in a session (one for each `instance` it names) and 256 waiting packets for a chain. Past a limit a packet is rejected with the clause `implementation limit`. For each chain it keeps one content ID for each packet in order, until you `drop` the session. Anyone whose packets you accept can name you in a new session: `drop` the ones you want no part of.

## Sealing

- **`sealPacket` seals a signed packet to its recipient.** It takes the recipient's agreement keys from the latest state of the log you hold, and seals to the first that can be sealed to: a key that is a point of small order cannot (RFC 9180, 7.1.4). The record it gives is unsigned, and shows only whom it is for.
- **The randomness is yours to give**: 32 bytes from a cryptographically secure random source, for one record and never again. This package draws none. Used twice for one recipient, the same bytes reveal both packets to anyone who sees both records.
- **`receiveSealed` opens and judges in one step.** Give it what arrived and a receiver that says which agreement keys it holds (`agreementKey`). It opens the record, and judges the packet inside exactly as `receivePacket` does. Nothing of a packet that does not pass is returned.
- **A record opens only as itself.** The recipient's address is bound into the encryption, so a record put under another recipient's name does not open, though that recipient holds the key. It opens only to the canonical form of a `Packet`: no other record, and no other writing of the same packet.
- **The `Ack` names both.** `received.sealed` is the content ID of the `Sealed` record: pass it to `draftAck`, which names the packet inside as well (Layer 1, 13.2).
- **What sealing does not give.** Neither forward secrecy nor protection against a quantum computer: whoever later holds the agreement key reads what was sealed to it (Layer 1, 12.6). Minds rotate their agreement keys.

## Acknowledgements

- **`draftAck` writes the `Ack` for a packet the gate accepted.** It names the packet by content ID, says when you received it, and lists the digests of the proofs on the packet that verified. Sign it with `createProof` of `@oip/core`. Answer a duplicate with the acknowledgement you made the first time.
- **`verifyAck` judges one**: a well-formed `Ack` signed by its author's own authority. `acknowledges(ack, packet)` then says whether it is for that packet, from one of its recipients.
- **An `Ack` is evidence of time for exactly the proofs it covers** (core 9.4, item 4). `ackEvidence` lists them: the proofs that verify on the records the packet carries in its `content`, which the content ID covers, and the packet's own proofs that the `Ack` lists. A proof added to the packet afterwards has the same content ID, and is not among them.
- **Whose word on time you take is yours to decide.** An `Ack` is evidence only to a verifier that trusts its author for this. Nothing here decides that: record what `ackEvidence` gives in your `FirstSeen` only for such a recipient.

## Authentication

- **`verifyHello` is the server's check.** Give it what the client sent and a `HelloServer`: your origin, your clock's reading, the challenges you have issued, and the logs you hold. It answers with the mind that authenticated, or with the reason it did not.
- **The proof is over your challenge and your origin.** `domain` must be your origin exactly, as your clients connect to it. A client sets it from where it connected, so a server that relays your challenge gets a proof it cannot use with you.
- **A challenge is good once, for 300 seconds.** Make each from at least 16 random bytes (Layer 1, 13.4): this package makes none. `Challenges` remembers them. A `Hello` that passes uses its challenge up, and one that fails leaves it open.
- **The key must be current.** A `Hello` describes the mind's present state, so its key is among the keys of the latest state you know, and the mind is not retired (Layer 1, 6.1). Hold the mind's log as it stands before you ask.

## Locations and profiles

- **The current location record is the one with the highest `seq` that still counts.** A record signed with a key the mind has since removed counts no longer, however high its `seq`: nobody who once held a key can lock the mind out (Layer 1, 15.2, 15.4).
- **Staleness is the record's own claim.** `isStale` compares the time you give with the record's `created` plus its `ttl`. A stale record may still be used as a hint.
- **Mailboxes come last.** `endpointsToTry` puts them after the other endpoints, whatever their priority, and returns only them while the mind is `paused`. Endpoints with a binding this revision gives no meaning to are left out.
- **An `https` endpoint's `url` is a base.** `postUrl` adds `/inbox` and `webSocketUrl` adds `/ws` under the `wss` scheme, whether or not the base ends with a slash. A base with a query or a fragment is no base, and has no URL.
- **The current profile is named, not guessed.** It is the one the current location record names, and failing that the most recent one the mind's feed publishes that counts. A profile you hold that neither names is not current.

## Results and errors

- **A function that judges returns a result, and does not throw on what arrives from outside**: the value given to `receivePacket` or `verifyHello`, the entries given to `verifyFeed`. The arguments a caller builds itself are another matter: a time that is no time, a limit below one, a view that throws is a mistake in the calling program, and is not hidden ([ADR-0007](../../docs/adr/0007-programming-errors.md)).
- **A check that was cut short is refused, and nothing is kept of it** ([ADR-0004](../../docs/adr/0004-error-model.md)). With the call stack all but spent, or in a process where nothing can be serialised, a check cannot be made. Every judge here then refuses with the clause `implementation limit`, and a function that answers with what it found finds nothing. No feed is answered in part, no older location record is taken for the current one, a `Sessions` gives the packet no place, and a `Hello` uses no challenge up. Ask again and each judges afresh.
- **A `Sessions` decides first and records last.** A packet is marked as taken by the last thing `take` does. If anything fails before that, the packet is taken when it comes again, and it is delivered once.
