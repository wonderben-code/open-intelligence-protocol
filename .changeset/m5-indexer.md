---
"@oip/indexer": minor
---

First version: the indexer of Layer 1, Section 18.

- `start`, and the command `oip-indexer`: the indexer as a service, set up from `OIP_INDEXER_` variables. It is a mind: it is started with its own `Bundle` and an operational key of that mind, read from a file only its owner can read.
- `indexerApp`: `POST /oip/v1/submit`, `POST /oip/v1/query` and `POST /oip/v1/inbox`, with a rate limit for each address and problem details for every error (core 10.2). It serves the `Bundle` of its own mind.
- `Indexer`: a `Participant`, an `Offer` or an `Intent` is listed if its author's own authority signed it, by a log the indexer holds. A capability query is matched with SQLite's FTS5 and by tags, and answered with a `QueryResult` the indexer signs. A score is a decimal worked out in whole numbers. A query that asks for `constraints` or `evidence` finds nothing: the indexer claims no match it did not check.
- `Broker`: a packet addressed to a query is forwarded once, to at most as many minds as it says and never more than fifty, each time in a `Forwarded` record the indexer signs (18.5). A packet that names its brokers and not this indexer is refused.
- `init`, and the command `oip-indexer init <directory>`: makes the indexer's own mind, once. It writes the mind's `Bundle`, its operational key and the control key for its next event, the keys in files that only their owner can read, and writes over nothing.
