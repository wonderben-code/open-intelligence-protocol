# M10 review: the demo network, and a reader that holds no key

**Reviewed:** 21 November 2026 · **Diff:** `d107d62..00cb436` on `m10-demo`, then the fixes (`00cb436..HEAD`) · **Specification revision:** 2026-11-17, with [OEP-0001](../../oeps/oep-0001-core-clarifications.md) to [OEP-0006](../../oeps/oep-0006-bridge-clarifications.md)

[BUILD.md](../../BUILD.md), Section 7, asks for a fresh review at the end of each milestone, by an agent whose only context is the repository, the specification and the milestone's diff. M10 had one. It was read-only, ran a probe for each finding, and planted 32 faults, one at a time.

This file records every finding and what was done about it. Nothing was waived: a finding is **fixed**, or it is **queued** with where it goes, or it is **noted** where a reader will find it.

## Verdict

"Not ready to merge. The demo runs from a clean checkout in ten seconds and prints what its README shows, the secrets hold, and the two `witnessProofs` fixes are right and needed. But five things stand in the way." They were K1 to K5 below.

## What the fixes decided

1. **A reader of history holds what it holds as of its latest look.** A `Reader` took each record's proofs as first seen at the moment it happened to fetch them. So the order of its own loop decided whether a Revocation came "before" the signature it bears on. A reader has no evidence of its own for the order in which things were made. It now has one time for all it holds, and fails towards "not bound" (core 9.7). A mind, which takes records in as they are made, notes when it first obtained each proof as before: that is evidence (core 9.4, item 1).
2. **The telling says what it checked, and no more.** Each `verified:` line has the check its words describe. What a mind judges, signs and publishes is the copy that reached it over the network.
3. **`pnpm demo` ends on every path, and leaves nothing behind.** It has an exit code for a thing that was not so, for a network that could not be used, and for being interrupted.

## Findings

| ID | Severity | Finding | What was done |
| --- | --- | --- | --- |
| K1 | High | `Reader` says a Commitment binds a firm that had revoked the delegation, if the agent's feed is read before the firm's | **Fixed.** Decision 1. `holdRevocations` and `delegationsStand` are the reader's, and read the feed of each delegation's author (Layer 1, 11.5). The telling's stranger reads the firm's feed. Tests read the two feeds in both orders (`reader.test.ts`) |
| K2 | Medium | Step 4 reads the agent's mailbox once, straight after the indexer took the packet: the first telling on a fresh network fails | **Fixed.** A receiver reads until the packet it waits for is there, for ten seconds. A test tells the whole story with every POST held back |
| K3 | Medium | The Receipt's evidence is the digest of the empty string | **Fixed.** The digest is of the text that arrived, which is a part of the session's first packet. A `verified:` line holds it to the text sent |
| K4 | Medium | The coverage threshold fails for three files of the example | **Fixed.** `main.ts`, `stage.ts` and `story.ts` are above it, each with tests of its own paths. `record.ts` is gone: `--record` is an option of the one program |
| K5 | Medium | "It found 4 records there, each signed" counts fetches, and checks no signature | **Fixed.** Three records in four entries, and each is asked whether it counts for its author |
| K6 | Medium | `held()` and `sightings()` give the last copy handed in, and not the copy with every proof seen | **Fixed.** The record held has every proof that verifies, of every copy seen. A lesser copy takes none away. `Mind.records()` gives the same, so a mind that keeps its records keeps the signatures |
| K7 | Medium | A record that names more than 64 minds before its parties counts for nobody | **Fixed.** The logs that decide are asked for first: the author's, the parties', the signers' and those of the authors of delegations. A record that rests on more than 64 is refused with `too-large` |
| K8 | Medium | The Offer is the firm's, under a second delegation the telling never mentions | **Fixed.** One delegation, as the paper has it. The Offer is the agent's own |
| K9 | Low | Lines of step 10 give reasons no check establishes | **Fixed.** The lines say what is checked. A Commitment within the limits stands beside the one outside them, and Amina signs both |
| K10 | Low | The story hands records from mind to mind inside the process | **Fixed.** Each mind judges, signs and publishes the copy it received in a packet |
| K11 | Low | A stale or damaged `network.json` gives a stack trace and exit code 1 | **Fixed.** The description of a network is checked when it is read. Exit code 3 and one line for a network that cannot be used, with tests of each exit |
| K12 | Low | Ctrl-C leaves the telling's directory behind, with key files | **Fixed.** A signal ends the telling, the stage is closed, and the program exits with 130. A test holds `close()` to removing the directory |
| K13 | Low | Thirty-one days on, a stranger finds the Commitment `proposed`: "anyone can check it" has a limit that nobody states | **Noted** in the demo's README and in the client's: a reader that comes after a delegation has run out has no evidence that a signature under it was made in time. Anchored checkpoints give that evidence (core 9.7), and reading them is M12's |
| K14 | Low | `ReadingContext` takes a clock beside the lookup's own | **Fixed.** A reader reads the clock of its `Lookup` |
| K15 | Low | `sentFor(null)` and `holdCarried(null)` throw `TypeError`; a question holds the record it asks about; no test runs the README's `Reader` example | **Fixed.** Both take what is no packet as nothing. The documentation of `countsFor` says that it holds. `examples/read.ts` is run by a test, as every example is, and every method of `Reader` has a runnable example |
| K16 | Low | README: `oip` does not exist in a clean checkout; the root README never mentions the demo; BUILD.md's wording; the compose stack has other origins | **Fixed.** Each says what is so |
| K17 | Note | One question about one record makes 64 requests, one after another, each time it is asked | **Queued** for M12, with the client's other costs: a client that resolves a mind once for a reading |
| K18 | Note | On `--network`, each telling leaves minds nobody can retire | **Noted** in the demo's README, under what stays on a network |
| K19 | Note | Smaller gaps between lines and checks at steps 3, 4 and 7; a test whose name says more than it asserts | **Fixed.** Step 3 checks that the listing is the agent's current profile, step 4 says a broker forwarded, step 7 checks the session, and the test is named for what it asserts |

**Survivors of the planted faults (12 of 32).** Each has a test or a check of the telling now, and each was planted again where the telling is what holds it:

- In the telling: a record with a spoiled signature (F02), the translation as a part (F03), the Commitment outside the limits signed under another delegation (F05), an Offer that answers nothing (F15), the copy Amina lists without her signature (F18), and the three packets that were never sent (F19, F20, F21). Step 5 checks that the Offer answers the Intent. Step 9 judges the copy each feed serves by itself, for the signature of the mind that lists it.
- In the client: a `held()` that keeps the first copy (C10), a kept sighting later than now that is believed (C05), a body of any media type held as a record (C08), and the minds of a Receipt's proof left unasked (C09).

## What the review did not reach

- `pnpm run ci`, the benchmarks, Stryker and the differential campaigns, which the reviewer was told not to run.
- The recording as a browser draws it.

## Still owed

- **A review of the fixes**, by a fresh agent given the report and the diff of the fixes.
- Nothing for the mutation score of the example, which is no package of the stack. The client's score covers `Reader`.
