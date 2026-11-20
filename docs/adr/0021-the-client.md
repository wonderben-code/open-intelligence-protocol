# ADR-0021: The client

**Status:** Accepted, 20 November 2026 (M6).

## Context

[BUILD.md](../../BUILD.md), M6, asks for `@oip/client`: the library applications use to make and manage a mind, publish, resolve, find, send and receive, and deal. One sentence of it decides most of the design: everything received is verified before it is returned.

The packages below it judge and do no I/O. `@oip/identity` verifies a log, `@oip/net` judges a packet, `@oip/web` computes a status, each from what it is handed: the records, the evidence of time, and the present. The client is the first package that talks to anyone. So it is where three things have to be got right that no judge can get right for it:

- **What is fetched from whom.** Every service is a stranger, and so is every mind.
- **What evidence the judges are handed.** A proof counts by the log of its signer as a trusted witness served it, no earlier than the proof was first seen (core 9.4). A client that judges by a log it fetched an hour ago believes a key that was removed since.
- **What a mind must never say twice.** Two identity events for one position are duplicity (Layer 1, Section 7), and two feed entries for one position are equivocation (10.3). Neither can be taken back, and a client that stops half-way and starts again is how they happen by accident.

## Decision

1. **Two classes.** `Lookup` is what a client knows of other minds. `Mind` is a mind of one's own: its keys in a keystore ([ADR-0017](0017-the-keystore.md)), and everything it does. A `Mind` has a `Lookup`.

2. **The client judges nothing itself.** Every verdict is a judge's of a pure package: `verifyLog`, `ownSignedTime`, `receivePacket`, `verifyFeed`, `verifyAck`, `countsFor`, `status`. The client fetches, bounds, holds the evidence and puts the steps in order. A rule of the protocol is implemented once, below, where the conformance vectors test it.

3. **See, fetch, judge.** This is the witness rule of core 9.4, applied in one way everywhere:
   - The time of an identity event comes from a resolver the client trusts, never from the event's own date and never from the client's own first look. A client that met a log late would otherwise date a removal late, and believe what the removed key signed before then.
   - Anything else is first seen by the client when it arrives: a packet, a feed entry, an acknowledgement, an indexer's answer, a record it is given to hold.
   - Before a proof is judged, the log of its signer is fetched again from the resolvers. The first sight comes first and the fetch after it, so the log is always known up to the proof.
   - So judging a record costs a request to each resolver for each mind the record names. Nothing is judged by a log from a cache.

4. **A service is a stranger.** Only HTTPS is asked. No redirect is followed: a service that has moved says so in a record, which is signed. An answer is bounded in bytes and in time before it is read, and read as a record or as JSON before anything is made of it. A URL a stranger chose, such as a mind's home, is asked as any other.

5. **Three kinds of failure, and no fourth.** A service that speaks the protocol and refuses is an `OipError` with the service's code (core 10.2). A service that cannot be asked, or answers something else, is a `TransportError`. A keystore's failure is a `KeystoreError`, passed through. Anything else is a fault of the program, the client's or the caller's, and reaches the caller as it is: it is never taken for a service that failed.

6. **Several services, and what each said.** A mind publishes to every resolver it trusts and to every home it names. A call succeeds when enough of them took what was published, and `publications` says what each answered. Likewise `sources` for what was read, and `deliveries` for what was sent. A partial failure is reported, and is not thrown.

7. **What must not be said twice is written down before it is said.**
   - An identity event: the keystore binds the control keys to it, it is signed and verified here as any verifier would, published, and read back from a resolver. Only then are the keys destroyed. A process that stops finds the event in the keystore and goes on with the same one (ADR-0017).
   - A feed entry, the number of a location record, and the packets accepted are kept in the client's **memory**: a storage the application gives it, separate from the keystore, with nothing secret in it. An entry is written there before it leaves, and a call that failed is finished by the next with the same entry.
   - Every write to the memory names the version it replaces. Two processes that act as one mind find each other out there, before either has published.
   - A client with no memory, on a new device, asks the services where things stand. It refuses to go on where they cannot tell it: where no home answers, or the homes serve less of a feed than the mind's own location record says there is.

8. **Private unless told otherwise.** A packet is sealed to its recipient unless the sender says not to. A packet that cannot be sealed is not sent in the clear in its place: the delivery fails.

9. **An indexer is asked, and not believed.** Its answer is taken only as its own: a `QueryResult` to the query asked, signed by a mind the resolvers hold. Each record it names is fetched from the homes its author's own log names and verified as its author's (Layer 1, 18.4). An indexer's `hints` are not followed.

10. **A home is brought its mind's records by the reference host's own interface.** Layer 1 says what a host serves, and leaves open how a mind brings it. The client speaks the interface of `@oip/host`: signed `PUT`s of a bundle and of records, and a signed `POST` of feed entries. A home is brought every identity event, since it judges the mind's requests by the log it holds.

11. **The clock, the randomness and the network are given.** `clock`, `randomness` and `fetch` are options, with the platform's as defaults. The client reads none of them any other way, and its tests give their own.

12. **It imports the pure packages and the keystore, and no service.** Its tests run against the real resolver, host and indexer, in the test's own process, through a `fetch` that finds a service by its origin. No socket is opened. A stand-in takes a service's place only to play one that lies or fails.

## Consequences

- **Verification is not optional, and not the caller's.** There is no method that returns what a service said without judging it, except `exchange` and its kin, which return bytes.
- **Round trips.** Judging one record fetches the log of each mind it names from each resolver. A mailbox of a hundred packets from one sender fetches that sender's log once: everything in a batch is first seen at one reading of the clock.
- **A feed is read whole.** `verifyFeed` wants every entry from the first, so reading a feed, and carrying one to a new home, costs a request for each page and each record. `Lookup.feed` reads 10 000 entries of one feed at most.
- **Records are held while the mind is open.** What the mind signs and what its packets carry is held in memory, to judge by. It is not written anywhere: an application keeps what matters and holds it again. Storing records is a decision about retention that is the application's.
- **The owner's interface of a host is not in the specification.** Another host has to offer the same interface for a mind to keep its records there with this client. That is a candidate for an OEP once a second host exists.
- **A client fetches where strangers say.** In a browser that is what a link does. On a server inside a private network, the application gives the client a `fetch` that reaches only public addresses, as the services of M5 have.
- **Not here yet, and coming in M6:** sessions with resume (Layer 1, Section 14), the WebSocket binding with a client that reconnects (13.4), an outbox for when no endpoint answers, and collectives.

## Alternatives

- **Hold logs for a time and judge by them.** It would save most of the round trips. It is exactly what core 9.4 forbids: for as long as the log is held, a removed key is believed.
- **Return an indexer's results as they come.** Faster, and Layer 1, 18.4 says a client MUST fetch and verify what a result names before acting on it. A caller that had to remember to do so would forget.
- **Send in the clear when sealing fails.** A message that the sender believes is private would then sometimes not be, with no sign of it.
- **Keep the client's memory in the keystore.** The keystore's documents are sealed, and are unlocked only for signing. Where a feed stands is public, is read on every append, and is no key.
- **Throw when any service fails.** A mind with two resolvers and one of them down could then do nothing. What each service said is in the result.
- **Mock the services in the client's tests.** A mock answers what its author expects. Tests against the real resolver, host and indexer found that a mind could not publish its own retirement where publication must be signed, which no mock would have refused.
