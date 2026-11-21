---
"@oip/client": minor
---

Reading without a key.

- `Reader` holds records and judges them with a `Lookup` and a clock, and no key: `countsFor(record, mind)` and `status(record)`, by the records and the logs alone (Layer 2, Sections 7 and 8). A stranger works out what the parties to a deal work out, from what they published.
- `Mind` reads as before. It is a `Reader` that signs, and that takes records in as they are made.
- A `Reader` reads history unless it is made `"live"`. It holds every proof as of its latest look, so its verdict does not depend on the order in which it fetched what it read: a Revocation it holds counts against a signature under the delegation it takes back, whichever was read first. `holdRevocations` and `delegationsStand` are the reader's.
- The record held is the one with every proof seen of it that verifies. A lesser copy takes none away. `Mind.records()` gives the same.
- The logs that decide whether a record counts are asked for first. A record that rests on more than 64 logs is refused with `too-large`, where before some were left unasked and nothing was said.
- `ReadingContext` is a `Lookup`. The reader reads the lookup's clock: `Lookup.clock`. `Lookup.witnessed` is the evidence of the resolvers alone.
- `sentFor` and `holdCarried` take what is no packet and no content as nothing, and do not throw.
