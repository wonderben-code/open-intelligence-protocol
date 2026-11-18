---
"@oip/conformance": minor
---

Eight kinds of case for the Mind Network (Layer 1, Sections 10 and 12 to 16): `feed`, `checkpoint`, `receive`, `chain`, `hello`, `ack`, `location` and `participant`. An adapter answers each with `{ holds, value }`: whether the case's claim holds, and what it worked out on the way. The vectors hold 87 such cases: 13 that must be accepted, 37 that must be rejected and a control for each of those.

The reference adapter answers them with `@oip/net`, and the two positive checks of the network records run: a feed's entries commit to the proofs of what they publish and its checkpoint covers them, and a packet opens its session and is acknowledged.

Differential testing against the Python checker covers the Mind Network: generated feeds, checkpoints, arrivals of a packet, sessions, `Hello` records, acknowledgements, sets of location records and profiles, with the two verdicts and the two accounts of what was found compared. `pnpm test:differential:network` runs it.
