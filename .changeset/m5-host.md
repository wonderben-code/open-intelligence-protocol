---
"@oip/host": minor
---

First version: the host of Layer 1, Section 13.

- `start`, and the command `oip-host`: the host as a service, set up from `OIP_HOST_` variables. It takes on the minds its operator names, or any mind up to a number when it is open.
- `hostApp`: a mind's well-known resources (its `Bundle`, `LogPage`, `FeedPage` and the records its feed lists), its inbox and its mailbox, with a rate limit for each address and problem details for every error (core 10.2). The mailbox is drained and emptied by requests the mind signs (13.3).
- `Host`: what is done with a record. An inbox judges a packet as its recipient would (12.4) before it keeps it, and records the first sight of its proofs only then. The same packet again gets the same answer. A host that is given a key of the mind answers with the mind's `Ack`; one that is not answers `{ "stored": true }`.
- How a mind brings what the host serves is this host's own: signed `PUT`s of its `Bundle` and of records, and a signed `POST` of feed entries. The host holds one feed entry at each position (10.3), and lets the feed go on from the last valid entry after a key is declared compromised (10.4).
- `Sockets`, `attachSockets`: the WebSocket binding of 13.4. The host challenges, a `Hello` authenticates, and each message after is one record. A mind's own instance is sent its mail, which stays in the mailbox until the mind acknowledges it.
- `Lookup`: the host asks the resolvers it is given for the log of a sender it has not met, and judges the packet again.
