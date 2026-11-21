# ADR-0024: The client's socket to its host

**Status:** Accepted, 20 November 2026 (M6).

## Context

A mind reads its mailbox when its client asks (Layer 1, 13.5). Layer 1, 13.4 also lets the mind's own instance hold a WebSocket open to its host: the host sends what it keeps for the mind and what arrives, and removes a record once the mind says it has it. BUILD.md asks the client for this, with a connection that is opened again when it ends.

The reference host implements the binding ([ADR-0012](0012-service-stack.md)). The client already judges the items of a mailbox, keeps sessions in order and remembers what it accepted ([ADR-0021](0021-the-client.md), [ADR-0023](0023-sessions-in-the-client.md)).

## Decision

1. **What a socket brings is judged by the code that judges a mailbox.** `Mind.listen` hands each record to the same path `receive` uses: first sight, the sender's log fetched afresh, the verdict, the place in a session. `received` is called with what `receive` would have returned. There is one judge, and nothing is trusted more for having come over a socket.

2. **Readings are taken one at a time.** A reading of a socket and a reading of a mailbox may be asked for at once, and both change what the client remembers. They run one after another, in the order they were asked for.

3. **The mind says it has a record with its own `Ack`, over the socket** (13.4), signed with an operational key. It is sent after what was accepted is written to the client's memory. A record ahead of a gap in its session is not acknowledged: it stays with the host, as it stays in a mailbox.

4. **What is refused is removed by reading the mailbox over HTTP.** The binding has no way to tell a host that a record is no packet for the mind. After a batch in which something was refused, the mailbox is read once, which removes it. What that reading refuses again is not told again.

5. **The `Hello` is signed for the origin the client connected to**, taken from the URL it opened and never from the host's challenge (13.3). A host that relays the answer to another finds it refused there.

6. **A connection that ends is opened again after a wait that doubles**, from one second to one minute, and starts at one second again once a host has welcomed the mind. Each wait is shortened at random by up to half, so that the clients of a host that restarts do not return together. The sockets the mind's location names are tried in the order of their priority, one after another.

7. **Only the application's own failure ends the listening.** What `received` throws, and a failure that is nobody's answer, reject `closed`. A connection that drops, a host that does not keep to the binding, a resolver that cannot be asked or serves what does not hold, and a memory another process wrote first all end the connection, and another is opened.

8. **The socket and the timer are the platform's, behind two options.** `webSocket` defaults to the global `WebSocket`, which browsers have and Node.js has from version 22. `sleep` defaults to `setTimeout`. Tests give both.

9. **A failed write leaves nothing half-remembered.** A reading keeps what it accepted in the process while it judges, and writes it down before anything is removed or told. If the write fails, what the process holds is dropped and read again from the memory. Before this, a packet judged in a reading that could not be written was taken for a duplicate by the next reading, and removed without ever having been returned.

10. **The list of packets accepted is merged where two processes wrote it.** It only grows, so two lists can always be made one. A process that finds another wrote first reads that list, adds its own and writes again. A packet both had judged is returned by the one that wrote first.

## Consequences

- **A packet arrives when it is sent**, where the host and the network allow, and at the next connection where they do not.
- **The mind signs once for each record it receives over a socket.** Over HTTP it signs one request for each record it removes, so the cost is the same.
- **A host learns nothing new.** It already holds the records and knows when the mind reads them.
- **`send` does not use sockets.** A recipient whose location names only a `wss` endpoint takes no packet from this client. Every host that offers a socket by the `https` binding offers an inbox too.
- **A client that listens holds its operational key unlocked**, as any open mind does.

## Alternatives

- **Use the socket as a signal, and read the mailbox over HTTP whenever something arrives.** It needs no acknowledgement over the socket, and sends every record twice.
- **Remove what is refused with an `Ack`.** An `Ack` says the mind has a packet. It would be signing that it received what it refused.
- **End the listening when the mind's own log cannot be resolved.** The resolvers are other people's services, and they come back.
- **A fixed wait between connections.** A host that restarts would be met by all its clients at once, again and again.
