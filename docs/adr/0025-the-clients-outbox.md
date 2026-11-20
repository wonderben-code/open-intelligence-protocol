# ADR-0025: The client's outbox

**Status:** Accepted, 20 November 2026 (M6).

## Context

`send` posts a packet to the first endpoint of a recipient that takes it (Layer 1, 15.3), and says what became of it for each recipient. A recipient whose host is down, or that has not yet published where it is, takes nothing. Until now the application was told, and the packet was gone unless the application kept it and sent again. BUILD.md asks the client for an outbox.

A session makes this sharper. The first packet of a chain carries the `Session` record, and a receiver that has never seen the record refuses every later packet of the session (14.2, [ADR-0023](0023-sessions-in-the-client.md)). A first packet that does not arrive has to be sent again by its sender: no `Resume` will ask for it.

## Decision

1. **A packet that did not arrive is kept for the recipients it still owes, where the reason may pass.** Those reasons are: the service could not be reached, did not answer in time, or answered as no service of the protocol does; it asked for patience (`rate-limited`); it cannot yet judge the sender (`stale-version`); or the recipient or its location is not known (`not-found`). Any other refusal is of the packet itself, and sending it again would change nothing.

2. **What is kept is the packet as it was signed**, with the recipients it owes and whether it goes sealed. It is sealed anew for each try. One document for each packet, named by its content ID, in the client's memory.

3. **A packet is tried again when the mind next reads, if it is due, and at once when asked.** `receive` and the opening of a socket are when the client knows the network is there. The first wait is 30 seconds, and it doubles to an hour. The schedule is in the document, by the client's clock, so it survives a restart. `Mind.retry` ignores it.

4. **A try ends in one of three ways for each recipient**: the packet arrived; it did not, for a reason that may pass, and waits on; or it is now refused for what it is, and is given up for that recipient.

5. **A packet that has expired is dropped unsent**, 300 seconds after its `expires`, when no receiver may accept it (12.4). A packet of a session states no `expires` and waits until it arrives, until the mind leaves the session, or until `abandon`.

6. **Keeping is the default.** `queue: false` sends once. A packet addressed to a query is never kept.

7. **The outbox holds 1,000 packets.** Past that a packet that does not arrive is reported as before, and not kept.

8. **A reading judges the packets of one sending chain in the order of the chain.** With an outbox, the first packet of a chain often arrives after the ones that followed it. Judged in the order they arrived, those were refused for a session not yet known, and the first then stood alone. The items of one reading are now put in chain order before they are placed. Nothing else moves.

9. **Two processes that try one packet at once do not both tell of it.** A write names the version it replaces. The one that loses says nothing of that packet, which the other reports.

## Consequences

- **A mind can send while its recipient is away**, and to a mind that has not yet said where it is.
- **A packet may arrive twice**, when a try succeeded and the client could not write that down. A receiver discards a duplicate (12.4).
- **The default expiry of an hour bounds how long a packet waits.** The README says to give a longer one to what should outlast a long silence.
- **The outbox reveals nothing new.** It is in the client's memory, which already holds what the mind sent in its sessions.
- **A recipient that never appears costs a try at each due time**, at most one an hour, until the packet expires.

## Alternatives

- **Leave retrying to the application.** Every application would write the same loop, and most would not handle the first packet of a session.
- **A timer in the client that tries again by itself.** A library that wakes by itself keeps a process alive and acts when its application does not expect it. The client acts when it is called, or while it is listening because it was asked to.
- **Keep every packet until it is acknowledged.** A host that holds no key of the recipient acknowledges nothing (13.2), so most packets would wait for ever. An endpoint that took the packet is where the sender's part ends.
