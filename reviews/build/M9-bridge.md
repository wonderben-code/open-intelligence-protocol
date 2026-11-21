# M9 review: the gateways, the DID resolver and assurance levels

**Reviewed:** 21 November 2026 · **Diff:** `fab9c29..6291f45` on `m9-bridge`, then the fixes (`6291f45..HEAD`) · **Specification revision:** 2026-11-17, with [OEP-0001](../../oeps/oep-0001-core-clarifications.md) to [OEP-0006](../../oeps/oep-0006-bridge-clarifications.md)

[BUILD.md](../../BUILD.md), Section 7, asks for a fresh review at the end of each milestone, by an agent whose only context is the repository, the specification and the milestone's diff. M9 had two, run in parallel, each with its own part:

- **Review A: the A2A gateway, the DID resolver and assurance levels.** `@oip/bridge-a2a`, `@oip/did-resolver`, `assuranceOf` and its vectors, the client and fetcher changes, the TCK script, the CI jobs and the two container images. It planted 53 faults, one at a time.
- **Review B: the gateway for MCP servers, and what the two gateways share.** `@oip/bridge-mcp`, `withBridged`, `Arrivals` and `Store` of `@oip/local`, the two client fixes, OEP-0006 items 4 to 6 with `Capability.ext`, the testkit's flags. It planted 68 faults.

Both were read-only. Each proved its findings with probes it ran, and says of every claim whether it ran it or read it. This file records every finding and what was done about it. Nothing was waived: a finding is **fixed**, or it is **queued** with where it goes, or it is **left open** and said to be in a threat model.

The fixes are large, and some change what a gateway promises. A review of the fixes is owed before the milestone closes, as M2's rounds were: see [Still owed](#still-owed).

## Verdicts

- **Review A:** "Not ready to merge. The pure rules are sound: assurance levels agree with the specification and with the Python checker on every case I could build, card signatures are verified without a hand-written primitive and I found no way round the key-set rule, the readers of a stranger's JSON did not crash, and whose-task checks hold on both sides. What is not ready is the gateway as a program that runs unattended and reads what strangers send."
- **Review B:** "Not ready to merge. The code is careful where its tests look, and most of what I planted was caught (54 of 68 faults). But the two promises the gateway makes about a tool are not kept outside the one-process, one-clock, well-behaved-server case the tests run in."

## What the fixes decided

Three decisions run through the fixes. [ADR-0034](../../docs/adr/0034-what-the-gateway-reviews-changed.md) has them all.

1. **One process at a time, by a hold that is touched.** Both gateways acted twice where two processes ran.
2. **A Receipt about no Commitment is not published.** The A2A gateway's Receipts told a public feed who asked what of whom. They are brought to the requester (OEP-0006, item 10).
3. **A delegation must stand when a gateway acts.** A proof is judged as of when it was made. Whether to act for a delegate is asked of now, after the author's feed was read for Revocations (OEP-0006, item 9).

## Review A

| ID | Severity | Finding | What was done |
| --- | --- | --- | --- |
| A1 | High | The gateway's minds post to URLs a stranger chose, through the client's plain `fetch` | **Fixed.** `GuardedFetcher.fetch` in `@oip/server`, and `guardedReach` in `@oip/local`: the minds of both gateways ask under the guard, with no redirect followed. `OIP_BRIDGE_FETCH_ALLOW` widens it for a test network. Tests in both programs' `main.test.ts` |
| A2 | High | Text of an agent's that a record cannot hold loses an answer, or leaves a task that is never settled and fetches its files on every pass | **Fixed.** `recordText` after every cut. Sizes are of canonical bytes. An answer is written down before its packet is done with. What a task ended with is gathered once, with each file fetched once, and written down. Where a packet or a Receipt still cannot be made, the requester is told in the gateway's own words |
| A3 | High | A Receipt on the public feed discloses the task's ID, the agent's words, the file URLs and who asked | **Fixed.** Receipts are brought to the requester and not published. The statement holds the task's ID, quoted, and none of the agent's words, which are content of the packet |
| A4 | High | A packet the agent cannot be sent is tried for ever, and one silent agent holds up the rest | **Fixed.** A request expires by its own time or after a day, and the requester is told. An agent that cannot be reached is asked once in a pass. A pass takes 30 seconds at most, and eight agents are relayed for side by side |
| A5 | Medium | Nothing keeps two processes from relaying for one directory | **Fixed.** `hold` of `@oip/local`: `serve` holds the gateway's directory, and ends if it loses the hold |
| A6 | Medium | Served side: an answer read before the task is written down is dropped | **Fixed.** Sends that are under way are awaited before answers are applied |
| A7 | Medium | A feed of more than 10,000 entries cannot be read: Receipts, new bridging and assurance levels all stop | **Fixed** for the gateways and for `Lookup.assurance`, which reads page by page until it has the entry. A gateway notes what it attested, and attests again where its feed cannot be read. A way to ask a home for one entry is **queued** as open question 3 of OEP-0006 |
| A8 | Medium | The statement's quoting stops at ASCII | **Fixed.** The agent's words are no longer in a statement. What is quoted is a string of JSON in ASCII (`asciiJson`), and `printable` escapes every format character |
| A9 | Medium | The served side keeps tasks, contexts and sessions without end, and a listing reads every task | **Fixed.** Tasks are kept for each mind apart, 4,096 at most, and forgotten 30 days after they last changed. An idle context is swept after a day and its session left |
| A10 | Medium | A retired mind resolves with 200 and `deactivated: false` at an earlier version | **Fixed**, in the specification too: `deactivated` is of the mind (OEP-0006, item 7), with a vector |
| A11 | Medium | The `assurance` vectors do not hold four of the rules of 1.3 | **Fixed.** Five negative cases, each with a control |
| A12 | Medium | A packet is written down only after the client has removed it from the mailbox | **Fixed.** `Mind.receive({ keep })`, which `Arrivals` uses |
| A25 | Medium | Five threat-model rows, and ADR-0029 item 8, rest on checks no test holds | **Fixed.** A test for each: a task found only under its own mind, a Receipt by another author, a mind that lists another card, a packet brought twice, a context for each requester, the operator's key before the origin's |
| A13 | Low | A second requester whose request the agent answers with the first's task is told nothing | **Fixed.** It is told, and the task is followed for the first alone |
| A14 | Low | A card with 256 signatures costs ten minutes | **Fixed.** Eight signatures are verified, and four keys of one name are tried |
| A15 | Low | `bridge` attests a mind before it finds that the card's texts cannot be held | **Fixed.** A card's texts are made text a record holds before anything is signed |
| A16 | Low | HTTP front: `raw` in the URL alphabet, a client's text answered as an internal error, `text/plain` taken | **Fixed.** `raw` is normalised, such text is the client's error, and a request must be `application/json` |
| A17 | Low | DID resolver: parameters ignored, a bad path is a 500, an earlier version untested | **Fixed.** `versionTime` is refused, a bad path is a 400, and a test holds the document of an earlier version |
| A18 | Low | Nothing checks that the profile's block is "the same block" as the genesis's | **Fixed.** `Lookup.assurance` reports the block of the `Genesis`, and `withBridged` refuses a directory whose `Genesis` names another gateway |
| A19 | Low | `assuranceOf` answers `native` without the mind's log | **Documented** on the function: a caller that has no log cannot be told of a genesis's block |
| A20 | Low | `Front.cancel` signs a Receipt afresh if the send fails | **Fixed.** The Receipt is kept on the task and used again |
| A21 | Low | Parts of a status message that are no text are dropped | **Fixed.** They are carried |
| A22 | Low | README: a dead link, and what `--keys` does not do | **Fixed** |
| A26 | Low | "The Receipt has their digests" is said of parts a Receipt has no evidence of | **Fixed.** The packet says of a Receipt what the Receipt holds |
| A23 | Note | The interface a card names may be at any public origin | **Left open**, and said so in the threat model |
| A24 | Note | A gateway that is a collective is `bridged` | **Queued** as open question 4 of OEP-0006 |

**Survivors of the planted faults (15 of 53).** Eleven changed an answer a caller can reach. Each has a test now: `d02`, `f01`, `f03`, `f06`, `f07`, `f09`, `k05`, `n02`, `r02`, `t02`, `v01`. The test for `v01` found a real fault: `A2A-Version: 1.0.` was served. Four change no reachable answer (`d04`, `g02`, `k02`, `s03`).

## Review B

| ID | Severity | Finding | What was done |
| --- | --- | --- | --- |
| B1 | High | Two relays for one server call a tool twice | **Fixed.** A pass holds the bridged mind's directory, `serve` holds the gateway's, and a pass asks once more whether it may go on before it writes down that it is calling |
| B2 | High | A tool is called under a delegation its author revoked and published | **Fixed.** `Mind.holdRevocations` and `Mind.delegationsStand`. The gateway reads the authors' feeds before every call for a request sent for another mind. The specification says so (OEP-0006, item 9) |
| B3 | High | A credential reaches a packet and the log when a server repeats it | **Fixed.** A server's words are searched for each credential, a result that repeats one is not passed on, and nothing a transport says of a failure is passed on. What the search cannot find is **left open** in the threat model |
| B4 | High | A `fulfilled` Receipt for one call of any tool, against Layer 0, 1.4 | **Fixed.** The outcome is `progress`, and the specification says so |
| B5 | High | One request costs 29 seconds: every reference hashes every held record | **Fixed** for the cost: the first eight references are looked at, each looked up in an index made once in a pass. That a mind holds every record a packet carried, for good, is **queued** for the performance pass of M12 |
| B6 | Medium | A request is lost between the mailbox and the `pending` store, or to another program that reads the mailbox | **Fixed** (A12). The README says that a bridged mind's mailbox is the gateway's to read |
| B7 | Medium | The sweep deletes the note of a call whose `pending` file could not be read, and nothing is durable | **Fixed.** The sweep asks whether the file is there, not whether it could be read. `Store.put` syncs |
| B8 | Medium | `Infinity` in a result is delivered as `null` | **Fixed.** What is carried is what the parser for records read, and a number that is not finite is not carried |
| B9 | Medium | Packets and profiles larger than every implementation accepts, and a half-made mind | **Fixed.** Sizes are of canonical bytes, and a profile has a budget for all a server wrote |
| B10 | Medium | The records one packet carries are held at one reading each | **Fixed.** One reading for all of them |
| B11 | Medium | A key in the query of a server's URL is published for good | **Fixed.** A URL with a query is refused, and the credentials have `query` |
| B12 | Medium | Threat-model rows whose test does not hold the defence | **Fixed.** Tests for F10, F12 and F16, and the paging is tested through the real client. Every row names a test, or says that nothing stops the threat |
| B13 | Medium | The specification and the code disagree in seven places | **Fixed** in the specification (OEP-0006, item 9) |
| B14 | Medium | Python says `bridged`, TypeScript says `claimed` | **Fixed.** A profile that is no record shows nothing (OEP-0006, item 8), with a vector and a campaign of the differential tests |
| B15 | Medium | A second `fulfilled` Receipt after a pass that was killed | **Fixed.** A Receipt is written to the mind's records when it is signed. With outcome `progress`, each call has a Receipt of its own in any case |
| B16 | Low | The gateway's sentences say more than it saw | **Fixed.** "Answered with an error, and gave no result", and after a result every failure says that the tool ran |
| B17 | Low | What the MCP client library does by itself | **Fixed** where it can be: the console is guarded while a server is connected, and the paging has the gateway's bound. The rest is said in ADR-0034, the README and the threat model |
| B18 | Low | An error quotes a member's name of the credentials file. A command can read the passphrase from `/proc` | **Fixed** for the first: a member is named by its place. The second is **left open**, and the threat model's row now says "not stopped". The copy of a credentials file is still taken before the server is asked: no mind is made for a server that cannot be asked, and the comment now says that |
| B19 | Low | `Store`: two keys that differ in a lone surrogate share a file, and `.partial` files stay | **Fixed** |
| B20 | Low | What the first client fix changes besides: a packet first seen long before its date never counts, and the rule is in two places | **Queued** for the review of M6's client in the closure round. Nothing is wrong by core 9.3 as written. No test holds it |
| B21 | Low | `withBridged` trusts the directory, and a long feed stops new bridging | **Fixed** (with A7 and A18) |
| B22 | Low | `--name ""`, a server's name, a server that is down, answers counted as sent | **Fixed.** An empty name is refused, a name is made text a record holds, a server that is away is asked once in a pass, and `Relayed.lost` names the answers that no endpoint took |
| B23 | Low | JSON text with a member name twice is read as its last | **Fixed**, and the specification says so (OEP-0006, item 9) |
| B24 | Note | The testkit's flags hide a true thing about functions that "never throw" | **Queued** for the closure round: a sentence in the documentation of those functions |
| B25 | Note | The MCP client library is Apache-2.0 with parts still MIT | **Noted** in ADR-0034 |

**Survivors of the planted faults (14 of 68).** Eight changed an answer. Each has a test now: `F10` (the note is on the disk when the server is asked), `F12` (a packet that only names a mind), `F16` (a Receipt published once), `F48` (the log names what failed), `F49` (a tool that asks for input), `L08` (the order of a pass), `L10` (a request that could not be written down), `L15` (a file left half written). `L12` is held by the tests of B7. Five change no answer, or one only for whoever can write the gateway's directory (`L04`, `L05`, `L06`, `F38`, `F46`).

## Found while the fixes were tested

The first full run of the checks on the fixes failed on the coverage of two files: `hold.ts` of `@oip/local` and `dealings.ts` of `@oip/client`. The tests that closed the gaps found three things, and each is fixed.

| Finding | Severity | What it was | What was done |
| --- | --- | --- | --- |
| T1 | High | The fix for B2 could be got round. `holdRevocations` left a Revocation unfetched if a record of its content ID was held. A delegate that read its Revocation on the author's feed could send the gateway the same record under a signature that is nobody's. The copy was held, counted for nobody, and kept the author's own from being fetched: the delegation stood for good | **Fixed.** A Revocation on a feed is left unfetched only if the copy held counts for its author. A test sends the forged copy first, and the delegation stands no more once the feed is read |
| T2 | Low | `delegationsStand` took a string in `authority` that is no reference as it takes a charter: as nothing a Revocation takes back. No record that verifies has one | **Fixed.** A reference that is none names nothing that is held, and the delegations do not stand |
| T3 | Low | `delegationsStand` took a delegation with no `expires` that can be read as one that never ends. No record that verifies has one | **Fixed.** It does not stand (Layer 1, 11.1) |

The races of a hold have tests now, with another process's acts planted between two steps (`hold.faults.test.ts`): a holder that lets go between two looks, a take-over that another process finished first, a process that has just started and made the file first, and a file system that fails.

## What the fixes changed in the specification

[OEP-0006](../../oeps/oep-0006-bridge-clarifications.md) gained four items, with the changelog, the Python checker, the vectors and the technical paper in the same changes:

- Item 7: `deactivated` is of the mind as its log stands (Layer 1, 5.2).
- Item 8: a profile that is not a well-formed record shows nothing (Layer 0, 1.3).
- Item 9: a call, its checks and its Receipt (Layer 0, 2.1).
- Item 10: a Receipt about no Commitment need not be published (Layer 0, 1.4).

And two open questions: a way to fetch one entry of a feed, and a gateway that is a collective.

## What neither review reached

- The A2A TCK and the container images, which run on GitHub and not where this is built.
- Windows, a real stream that drops and resumes, real TLS, a command that dies in the middle of a call, a loss of power.
- Mutation testing and `pnpm run ci`, which the reviewers were told not to run.

## Still owed

- **A review of the fixes**, by a fresh agent given the two reports and the diff of the fixes.
- **The mutation score** of the M9 packages (85% or more).
- **The A2A TCK and the `containers` job** green on GitHub, after the first push of the branch.
