---
"@oip/client": minor
---

First version, in parts as M6 builds them.

- `Lookup`: resolves a mind from the resolvers the client trusts, with the witness rule of core 9.4 applied: each event's time comes from a resolver's record of first sight, and each resolver's copy of a log is verified before it is held. Two resolvers that hold different events for one position show the mind's duplicity. A collective's log is verified with its members' logs, fetched first.
- `exchange`, `askRecord`, `askJson`, `TransportError`: one request to a service over HTTPS, bounded in size and in time, with no redirect followed. A problem of core 10.2 is thrown as an `OipError` with the service's code.
- `Mind`: a mind of one's own, with its keys in a keystore. `create` and `open`; `sign`; and the identity changes `update`, `addKey`, `revokeKey`, `fork` and `retire`, each made in an order that survives a process that stops: the control keys are bound to the event, the event is signed and verified before it leaves, published, read back from a resolver, and only then are the keys that signed it destroyed (Layer 1, 3.11 and 7.4).
- `Mind.publishLocation`, `publishProfile`, `publishRecord`, `bringHomes`: what a mind publishes of itself. A location record (Layer 1, Section 15) and a profile (16) go to every resolver and every home, with requests the mind signs (13.3); a record is put on the mind's feed at its homes (10). An entry is remembered before it leaves, so that a mind signs one entry for a position. `publications` says what each service answered. Every identity event is brought to the mind's homes, the event that retires it among them.
- `Lookup.feed`: reads a mind's feed from every home it names and verifies it; `Resolved` has the mind's current location record, whether it is stale, and its current profile.
- `MindOptions.memory`: where the client remembers its own work between runs, in a storage of `@oip/keystore`.
