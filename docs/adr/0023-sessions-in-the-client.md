# ADR-0023: Sessions in the client

**Status:** Accepted, 20 November 2026 (M6).

## Context

Layer 1, Section 14 puts the packets of each sender in a session in order: a chain for each sender, numbered from 0, each packet naming the one before. `@oip/net` judges chains, with `Sessions`. It keeps nothing between runs, reads no clock and sends nothing.

A client has to do the rest. It signs its own chain, so it must never sign two packets for one place. It has to send a packet again when a participant asks (14.4), so it must still have it. It reads packets from a mailbox, where they arrive in any order, some of them twice and some not at all.

## Decision

1. **A packet of a session has its place before it leaves.** `send` signs it, writes it to the client's memory, writes the chain with it in its place, and only then posts it. A process that stops after the second write holds a packet nobody received. That is a gap for the other participants, which a `Resume` repairs with the same packet. A process that stops before it holds nothing that names the packet.

2. **The memory has one document for each session and one for each packet sent.** A session's document holds its `Session` record, the content IDs of the mind's own chain, and what `Sessions.held` gives of the other chains. A packet's document holds the packet. Both are named by 105 bits of a content ID. Sending rewrites one small document, however long the session.

3. **Every write names the version it replaces**, as the rest of the client's memory does ([ADR-0021](0021-the-client.md)). Two processes that share a memory are one instance: the one that is behind is told `changed` before its packet leaves, and reads the memory again.

4. **`receive` returns a chain's packets in order, and a packet ahead of a gap stays in the mailbox.** It is neither returned nor removed until the packets before it have come. The mailbox is where it waits, so a process that stops loses nothing, and the client's memory holds content IDs only. When the gap is filled, the packets that waited are returned after the one that filled it.

5. **A gap is asked about once, by `receive` itself.** It sends one `Resume` for a session with a gap it has not asked about. `Mind.resume` asks again. Layer 1 says a receiver SHOULD send one (14.3), and an application that had to remember to would mostly not.

6. **A participant's `Resume` is answered by `receive`**: what it lacks of this mind's chain is sent to it again, as it was signed, and to it alone. A `Resume` that names a packet this mind did not send at that place is not answered.

7. **A packet of a session states no `expires`**, unless the application gives one. It can then be sent again for as long as the session lasts. Layer 1 lets a receiver take such a packet only within its own window, or while it holds the packet's chain (12.4).

8. **The client's window is seven days**, the longest any packet may be delivered. It was an hour. A client reads a mailbox when its application runs, and a mind that looks once a day would have refused every session opened with it since the day before.

9. **A packet is not refused for a session the client does not hold until the memory has been asked.** Another process may have followed the session since this one read. If the memory has it, the reading stops with `changed`, nothing is removed, and the next reading judges the packet by what is written. Every other way of being behind ends in a write, which fails.

10. **What a session asks for is done after the packets are safe, and its failure is told, not thrown.** By the time a `Resume` is sent or answered, the packets that arrived are remembered and removed from the mailbox. An error then would lose them for the application. `Inbox.sessions` says what was found and done, and what failed.

11. **A chain keeps the instance it was started as.** `MindOptions.instance` names a client among several of one mind. A session's document records the name its chain began with.

## Consequences

- **A memory that is lost breaks the mind's sessions.** The mind would begin its chain again from 0, and every participant would hold two packets for one place. That is equivocation, and it is what they would call it. The README says to keep the memory as carefully as the keystore.
- **A session's packets are kept until the mind leaves it.** `leaveSession` removes them. The client follows 1,024 sessions at most, the bound of `Sessions`.
- **A sender that never sends a missing packet again leaves the later ones in the mailbox**, until the host that keeps the mailbox drops them or the mind leaves the session.
- **The first packet of a chain must be seen.** A later one is refused if the client holds no `Session` record for it and it carries none (14.2). The sender sees that its first packet was not taken. Sending it again is the outbox's work.
- **A `Resume` makes a mind send.** One small packet asks for a whole chain. It is a packet of the session, signed by a participant and taken once, so a stranger cannot ask, and a participant can ask once for each packet it sends.
- **A packet document can be left with nothing naming it**, if a process stops between the two writes of decision 1, or loses to another process. It is small, and nothing reads it.

## Alternatives

- **Keep the packets that wait in the client's memory.** The mailbox already keeps them, and removing them before they can be returned would make the memory the only copy.
- **Return packets as they arrive, and let the application order them.** Then every application writes Section 14 again.
- **Leave the `Resume` to the application.** See decision 5. An application that wants to decide can still call `resume`, and nothing is sent twice for one gap.
- **One document for all sessions.** Every packet sent would rewrite what the client knows of every session.
- **State an `expires` on session packets, as on any other.** A packet could then not be sent again after it, and a gap older than that could never be filled.
