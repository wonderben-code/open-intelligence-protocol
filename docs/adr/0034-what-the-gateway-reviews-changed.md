# ADR-0034: What the reviews of the gateways changed

**Status:** Accepted, 21 November 2026 (M9).

It replaces decision 5 of [ADR-0029](0029-the-a2a-gateway.md), and part of decision 12 of [ADR-0031](0031-the-mcp-gateway.md). It adds to both.

## Context

M9 built two gateways: `@oip/bridge-a2a` ([ADR-0029](0029-the-a2a-gateway.md)) and `@oip/bridge-mcp` ([ADR-0031](0031-the-mcp-gateway.md)), with a driver for DID resolvers ([ADR-0030](0030-the-did-resolver-drivers.md)).

Two independent reviews followed, each given the repository, the specification and the diff. Their reports are in [reviews/build/M9-bridge.md](../../reviews/build/M9-bridge.md). Between them they found nine things of High severity. Both gateways acted twice where two processes ran, and published more than a requester asked for. The MCP gateway called a tool for a delegate whose delegation had been revoked, and passed an operator's credential on to a requester when a server echoed it.

The findings share causes. So the fixes are decided once, here, for both gateways.

Where a fix changed what the specification says, [OEP-0006](../../oeps/oep-0006-bridge-clarifications.md) has it (items 7 to 10).

## Decision

### For both gateways

1. **One process at a time, by a hold.** A hold is a file that is made only if it is not there (`hold` of `@oip/local`). Its holder touches it every 5 seconds. A hold untouched for 30 seconds was left by a process that ended, and is taken over. `serve` holds the gateway's directory (`serve.hold`). The MCP gateway also holds a bridged mind's directory for each pass (`relay.hold`), since a call made twice is a thing done twice. The age of the last touch decides, not a process number: two containers that share a volume each have a process 1.

2. **A hold that is lost stops the work.** A process that stood still for half a minute may have lost its hold. A pass asks before each packet whether it may go on, and the MCP gateway asks once more just before it writes down that it is calling.

3. **A packet is written down before the client forgets it.** A mailbox gives a packet once. `Mind.receive` takes a `keep` function, which is called with the accepted packets before the client notes them as received. `Arrivals` of `@oip/local` writes each packet to its `pending` store there. A process that stops at any moment finds the packet in the mailbox or in the store.

4. **What is written is on the disk.** `Store.put` syncs the file and its directory before it returns. A note that says "I am about to do this once" must be there after a loss of power.

5. **The gateway's minds ask under the guard.** A bridged mind sends answers where a requester's records say, and reads feeds where their authors' records say. Strangers chose those URLs. Both gateways give their minds the guarded fetcher of `@oip/server`: public addresses only, no redirect followed. A network on this machine is reached by its routes (`guardedReach`). `OIP_BRIDGE_FETCH_ALLOW` names further ranges for a test network.

6. **A pass has a budget, and servers are relayed for side by side.** Under `serve`, one pass for one agent or server takes 30 seconds at most, and eight are relayed for at a time. A slow one holds up nobody else. What a pass leaves undone waits for the next. A call that is under way is not cut short.

7. **Nothing waits for ever.** A request is not acted on past its own `expires`, with the 300 seconds a receiver allows for two clocks, or after a day where it names no time. The requester is told. An agent or server that cannot be reached is asked once in a pass.

8. **A stranger's text is made text a record holds, and quoted where the gateway speaks.** `recordText` replaces half a pair of surrogates and noncharacters, and cuts between characters. Where a gateway's own sentence holds a stranger's words, they are a string of JSON in ASCII (`asciiJson`): no text ends it early, turns it round or dresses it up. Names and summaries in a profile are made text a record holds, and no more. A reader makes them safe to show, as of every profile.

9. **A Receipt about no Commitment is not published.** The A2A gateway signs a Receipt for every task that ends, about the request. It brings the Receipt to the requester and does not put it in the bridged mind's feed, where it would say for good who asked what of whom. The MCP gateway signs Receipts about Commitments only, and publishes those, once each (OEP-0006, item 10).

### For the A2A gateway

10. **A Receipt says what the gateway saw, and the agent's words are content.** This replaces decision 5 of ADR-0029. The statement is the gateway's own sentence with the task's ID as a string of JSON. What the agent said of the task's end is carried as content of the packet, with an evidence item of kind `hash` for each part (`a2a:task/<id>/status/part/<n>`). The agent's words are no part of what the gateway signs as its own statement.

11. **A task's end is gathered once, and written down before it is signed.** The content and the evidence of a task that ended are gathered, with each file fetched once, and written to the task's record. The Receipt is signed from that record, and the record says when the Receipt is settled. An answer is written to an `answers` store before the packet it answers is done with. A pass that stops anywhere finds what the one before it had.

12. **The served side is bounded.** Tasks are kept for each mind apart, 4,096 at most, and forgotten 30 days after they last changed. A context that is idle for a day with no task is swept, and its session is left. A request must be `application/json`. The versions spoken are `1.0` and its patch versions, and nothing that only begins so. Headers have 10 seconds, a request 30, and 256 connections are taken. A card has 8 signatures at most, and a key set 4 keys of one name.

### For the MCP gateway

13. **A delegation must stand when the gateway acts.** A proof is judged as of when it was made (core 9), which is right for what a record binds its principal to. Whether to act for a delegate now is another question. Before it calls a tool for a request that was sent for another mind, the gateway reads the feeds of the delegations' authors for Revocations (`Mind.holdRevocations`), and calls only if the delegations stand (`Mind.delegationsStand`). Where a feed cannot be read, the request waits.

14. **A server's words are searched for the credentials.** This adds to decision 16 of ADR-0031, and replaces part of decision 12, by which whatever a failed call said was quoted. A server may say back what it was sent. In the words of a server's error, each credential is replaced. A result that repeats a credential is not passed on. Nothing a transport says of a failure is passed on at all: it may be the server's whole answer. The search covers each value, each word of a value, what `Basic` hides, and each of these in base64 and URL encoding. It does not catch a credential that a server transforms first.

15. **An error names nothing of the credentials file.** A member that is wrong is named by its place. A file with a name and its value the wrong way round has a secret for a name.

16. **A URL with a query is refused.** This adds to decision 3 of ADR-0031. The URL is in the bridged mind's `Genesis` and profile, published for good. What a server wants in its query is in the credentials file, under `query`. A URL that is refused is not said back.

17. **A Receipt has outcome `progress`.** Decision 13 of ADR-0031 did not give the outcome, and the gateway as first built said `fulfilled`. The gateway saw a result. It does not know what was promised, so it does not say `fulfilled`. The Commitment stands as it stood, and each call under it gets a Receipt. A Receipt is written to the mind's records when it is signed, and the feed is asked before it is published a second time.

18. **The evidence names the request.** Decision 15 of ADR-0031 stands, and the specification now says it: `ref` is the request, and the digest is of the body returned for it. The Receipt is carried in the answer, so the answer's content ID is not known when the Receipt is signed.

19. **Eight references are looked at.** A request may name a thousand things. The gateway looks at the first eight entries of `context.refs`, looks each up by content ID in an index made once in a pass, and takes the first Commitment that qualifies.

20. **JSON is carried as the parser for records read it.** A value is written as text and read back by `parseJson`, and what was read is what is carried and digested. Before, the value that was handed in was carried, and it could say something its text did not: an infinity is written as `null`. A value with a number that is not finite is not carried. JSON text of a requester's in which an object has a member name twice is no call.

21. **Sizes are of canonical bytes, and a profile has a budget.** A result is measured as the packet will hold it, where a text is a JSON string and each quotation mark is two bytes. Everything a server wrote takes 224 KiB of a profile at most: schemas are left out first, from the last tool backwards, then summaries are cut to 256 characters, then tools are left out from the end.

22. **What the MCP client library does by itself is said, and bounded where it can be.** The library walks the pages of a list itself: the gateway sets its bound to 32 pages, and a list that has not ended by then is none. The library leaves out a tool whose header declarations it finds wrong, before the gateway sees the tool. It writes a server's words to the console: while a server is connected, the console prints as any stranger's text is printed. It sends `tools/call` a second time after a header-mismatch error, which a server that keeps to MCP sends before it runs a tool. "At most once" is of the gateway's own calls.

### For the DID resolver and the client

23. **`deactivated` is of the mind.** A resolver says `deactivated: true` of every version of a mind that has retired, and the HTTP binding answers 410 for each (OEP-0006, item 7).

24. **A driver refuses what it cannot answer.** A DID that is not written as DID Core writes one, and `versionTime`, are refused with `invalidDid` and `invalidDidUrl`.

25. **An assurance level is read page by page.** `Lookup.assurance` reads the gateway's feed until it has the entry the profile names, and stops there. It reads the block of the `Genesis` as well as the profile's (OEP-0006, items 3 and 8).

## Consequences

- An operator runs one `serve` for a gateway's directory. A second is refused with a sentence that says why. A gateway that is killed leaves its hold, and the next start waits 30 seconds at most.
- A gateway on a private network reaches no requester there, unless the operator allows the range.
- A requester gets a Receipt of an A2A task in the answer, and no feed lists it.
- A Commitment a bridged MCP mind owes under is never settled by the gateway. Its operator, or the creditor, says when the promise is kept.
- A request that rests on a delegation costs a read of each author's feed before a tool is called. Where that feed is down, the request waits, and expires in a day.
- A result that happens to hold a credential's text is refused, though the server meant nothing by it. Texts shorter than 8 characters are not searched for, so a short credential is not protected by the search.
- `@oip/bridge-mcp` depends on `@oip/server`, for the guarded fetcher.
- A profile of a server with very many tools loses schemas, then the length of its summaries, then tools. `bridge` says which.

## Alternatives

- **A lock by process number.** A process number says nothing across containers, and a number is reused. A hold that is touched says only that its holder was alive seconds ago, which is what is asked.
- **`flock`.** Node has none without a native module, and an advisory lock over a network file system is not to be relied on.
- **Judge a delegation on arrival, as a proof is judged.** See OEP-0006, item 9. An author that has revoked and published has done all that Layer 1, 11.5 asks.
- **`fulfilled` where the Commitment names the tool.** It needs a convention for promises a gateway can check. OEP-0006, open question 2, leaves it for a later proposal.
- **Publish every Receipt, as Layer 2, 10.2 says a party should.** See OEP-0006, item 10.
- **Pass on a transport's error, scrubbed.** A scrubbed text is safe only if the search found everything. Nothing is lost by saying nothing: the requester cannot act on a transport's words.
- **Strip control characters from names in a profile.** A reader cannot rely on a writer having done it, since any mind writes its own profile. One rule for readers is simpler than one for readers and another for some writers.
- **Read the pages of a tools list ourselves.** The library offers no single page without a cursor of its own. Its bound is set, and tested through the library.
