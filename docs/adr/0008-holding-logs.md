# ADR-0008: The log book, and the time a log is known up to

**Status:** Accepted, 17 November 2026 (M2). It carries out [ADR-0003](0003-evidence-model.md) in `@oip/identity` and adds what building it, and four independent reviews of it, showed.

## Context

ADR-0003 fixed how time enters verification: an `EvidenceView`, two formulas, and the rule that a verifier holds a signer's log with its first-seen times before it counts a proof. Writing `@oip/identity` raised four questions it had left open.

1. **Who holds the logs?** Verifying a collective's log needs its members' logs, to four levels (Layer 1, 4.7). A member may have two conflicting logs (Layer 1, 7). Something must hold them, bound the nesting and resolve the conflict.
2. **How does the code know a log is fresh enough?** core 9.4 asks for the signer's log "as a witness it trusts served it at some time no earlier than `τ(p)`". A function that takes only a log and a proof cannot tell.
3. **How often is a record validated?** Whether a record counts for a mind is asked once for each party, each signer and each link of a delegation. Each answer starts from the same validated record and the same verified proofs.
4. **What does a verdict look like to the layers above?** `@oip/delegation` adds two more ways for a record to count for a mind, and must compose them with the ones here.

## Decision

### One object holds the logs and the evidence

`LogBook` holds, for each mind, one log or several conflicting branches, and the `EvidenceView` they are judged against. `log(mind)` verifies when first asked and remembers the answer.

- **Nesting.** A member's log is verified one level down, and no log is verified more than four levels below the one asked for. A mind that is already being verified is not verified again inside itself: no collective is a member of itself, directly or indirectly.
- **A log verifies only if every member's log it asks for does.** Every member signs the event that makes it one (Layer 1, 4.1, 4.4), so a log is asked for first by an event that cannot stand without it. Verification asks for each member's log once and stops at the first that does not verify. That bounds the work of a hostile set of logs to one failing log at each level, where judging every proof against a failing log cost the fourth power of the number of proofs.
- **What is remembered.** A log that verifies is the same log wherever it is asked from, and that verdict is kept: no event of it rests on a log that was refused, because an event that does is one the verifier cannot judge, and stops the log. A refusal may be for where the log was asked from: a log below it nests too deep there, or is a mind already under verification above. That refusal is kept only when the log was asked for directly, where it is the log's own.
- **For how long.** A verdict stands until a log it rests on is held anew or dropped. The book notes which logs each verdict asked for, and forgets only those verdicts. It cannot see its evidence change, so `forget()` clears every verdict; a caller that takes in earlier first-seen times calls it.
- **Its own copy.** The book copies the events it is given, and takes a mind's address from the copy it will verify. What a caller does to its array afterwards changes nothing, and a value that reads differently the second time cannot be held under one address and verified as another.
- **What the book has been shown, it keeps** (Layer 1, 4.9). Everything held of a mind's log is one tree of events from its genesis. An event is told by its content ID, which names the event before it, so the same event in two copies is one place in the tree. Its proofs are kept apart from the tree, under its content ID, so the proofs of every copy count for the event wherever it stands (Layer 1, 7.1; core 5.5). Only a well-formed copy of an event adds proofs: a content ID does not cover `proof`, so anyone can make a copy of any event with an entry in `proof` that is no object, and that entry, kept with the others, would make the event a record that is not well formed. Such a copy adds nothing and keeps its place, so what follows it in its copy is held. A value has a place if, apart from its `proof`, it is a JSON object within core Section 1, of at most 1 MiB: that much must be read to find its content ID and no more, and every verifier has to draw the line in the same place. A line drawn at the whole value let a fraction inside a `proof` end a copy, and cost the removal after it. Any other value ends its copy. If the verifier cannot read it, it is held where it stands as an event that cannot be judged, by the reason it cannot be read; every other such value at one place is held as one, which is no event. A value that could not be sorted at all, because reading it failed in a way nothing foresaw, is held as one that cannot be judged: what goes wrong with one value never costs a copy the events before it. The size of the proofs held for an event is counted as they are added and never written out, and a verdict is forgotten before what it rests on changes, so that nothing a copy does to `hold` leaves a verdict standing. `hold` adds a copy's events and proofs to what is held. It judges nothing and discards nothing, so it does not matter in which order copies arrive, or what the verifier could verify when each did. `drop` is how a caller says a copy was wrong.
- **It judges when it is asked** (Layer 1, 7.3). `log` walks the tree from the genesis. At each position it judges every event held there, each from the same state:
  - one that is invalid is no event, and nothing after it is looked at;
  - one that the verifier cannot judge stops the log with that refusal, whatever else is held at the position: it may be the mind's own;
  - one that verifies carries the log on;
  - where several verify, the one with strictly the earliest evidence has the position, never the longer branch or the later copy. What follows an event that lost is not judged at all;
  - where the evidence cannot separate them, the log it gives stops before that position, and every event held after each of them is judged, so that the removals and compromise declarations of every branch apply.
- **The time a log is known up to** is the latest time given with a copy that ended where the log ends, an invalid event after it or not. A copy that ended earlier says nothing of a log that goes on.
- **Bounds.** A tree has no limit on its ends. Each event held is judged at most once when the log is asked for, each from the state before it, so the work grows with the copies that were given and no faster; and a limit that fails closed would let nine copies that end in junk stop a mind. An event has at most the proofs that one record carries: 256, and 1 MiB with the event. Shown more than that for one event, the book says so and answers for that mind no longer, until the mind is dropped: what it holds is then not all it was shown.
- It is plain data in memory. It fetches nothing and reads no clock; the client and the services fill it.

`verifyLog` is the function underneath, for one log and a way to obtain a member's verified log. Most callers want the book.

### A log is held with the time it is known up to

`book.hold(events, asOf)`. `asOf` is when a witness the verifier trusts served the log, or the present for a verifier that follows the log itself. Key validity compares it with the evidence for the proof: a proof first seen after `asOf` does not count until the log is refreshed, because the log may lack the event that removed the key. Every log that decides whether a proof counts is held to that rule (core 9.4, as OEP-0002 extends it):

- the log of the mind whose key signed, against the evidence for the proof;
- the log of a collective under whose threshold the proof is counted, against the same evidence: otherwise a member the collective has removed signs for it against a verifier's older copy;
- a member's log, for its proof on a collective's event, against the latest evidence among that event and the events before it. An event takes effect no earlier than the event before it (core 9.5), so the member's log must be known that far.

The comparison is with the evidence, `τ`, as core 9.4 says, and not with the evaluation time, which is later when a proof is dated up to 300 seconds ahead of the clock that received it. A verifier can therefore count a proof it has just received, whatever the signer's clock says. OEP-0002 records the narrow window this leaves as an open question.

**No function takes `now`.** ADR-0003 and BUILD.md 3.3 said that every verification function takes `now` and an `EvidenceView`. Building it showed that "now" is not one time: each log is known up to its own. So the functions that judge take the view and, for each log, `asOf`. The present enters in one place only, where a verifier records its own first sight.

### First sight is recorded only of what has verified

Evidence for an identity event is evidence that it existed with proofs that make it valid (core 9.5). An event's content ID does not cover its proofs. A verifier that recorded the time it first saw an event's content would judge a proof added later at that early time, and a thief holding a removed invocation key could then sign a collective's event that was shown to the verifier, unsigned, before the key was removed. That is the attack of Layer 1, 9.6.

`book.witness(events, now, seen)` is therefore the operation for a log that arrives. It holds the copy, verifies what is then held with `now` standing in for the first sight of each event not seen before, and records the events that verified. `witnessLog(events, now, seen)` does the same for one copy judged alone, and returns the events that verified with the reason the next event did not, if there is one. `witnessRecord` does the same for the proofs on a judged record. `FirstSeen.sawEvent` and `sawProof` stay, for times a trusted witness has given; they believe what they are told, and their documentation says so.

### An event that fails is invalid, or undecided

The second review's advice, "hold what `witnessLog` found to verify", was wrong, and the third review showed how. If the first event that fails is one the verifier cannot judge, the events before it are a state the mind may have left: the event may remove a key, and a verifier that held the shorter log as known up to now went on counting that key. Refusing every copy with a failing event is safe, and lets anyone who can append one junk event to a copy in transit deny a mind to the verifier that receives it.

Layer 1, 4.9 (OEP-0002, item 19) tells the two apart, and the code follows it.

- **What a verifier cannot read is undecided, whatever else is true of it**: an event of another version of the protocol, of a type this revision does not define, with the reserved member, or with a critical extension the verifier does not implement. That is asked first. An extension listed in `critical` may change what makes an event well formed, in its place or signed, which is what `critical` is for, so an unsigned event that names one is not known to be junk. Anybody can write such an event, as anybody can write an unsigned `Merge`; the cost is that a copy tampered with in transit is refused, and never that a removal is lost.
- **Invalid** is what is wrong for every verifier, in an event it can read, and can be seen in the log alone: the event is malformed, is not in its place, sets keys the log does not allow, or carries proofs that could not authorise it. For a key-controlled mind that last check is the whole rule, made with every proof that verifies and no evidence at all. For a collective it is only whether enough members have a proof on the event: what a member's proof is worth is read from the member's log, and a verifier's copy of another log is not a fact about the event. A first version called a collective's event invalid when a proof named a version the member's log did not have; a verifier with an older copy of that log then dropped an event another verifier accepted.
- **Undecided** is everything else, and so the default: no evidence for the event, or a date or an expiry that other evidence would judge otherwise; a member's proof that does not count, for the member's log, its key or its height as this verifier knows them; a log longer than the verifier reads. The unsafe mistake, taking for junk what may be real, needs a positive finding.
- The pure checks are all made before any that reads evidence, so the code calls invalid exactly what 4.9 does. The Python checker classes an event from the text of 4.9, apart from its own verification, and the differential tests compare the two on every generated log with an event that fails.

`witnessLog` reports it (`undecided`), for the copy judged alone. What a caller holds is the copy as it came, always. `witnessLog` once also said what to hold, the events before an invalid event among its answers, and a review found the two not the same: an event that is invalid by one copy's proofs, for the members whose proofs it lacks, verifies in a book that holds another copy with the rest (Layer 1, 7.1). There is one way in, and nothing chooses for the book what it is shown.

The review after that found what was left of the same fault. `witnessLog` judges a copy alone, so it recorded first sight of an event only when one copy carried enough proofs, which can be later than the moment the verifier first held the event whole; a proof by a key the event removed, seen in between, then counted. So first sight is recorded where the proofs are: `book.witness(events, now, seen)` holds the copy and records every event that verifies with all the proofs held, as core 9.5 means it ("once the event has verified").

The same holds for everything else an event verifies with, and a review of that fix found three more such things. So the book has two operations, and a verifier that is its own witness has a rule to keep:

- `book.witness(events, now, seen, { following })` takes one copy in. It looks at the copy's mind and at every mind that rests on it, and so on up, until nothing more is recorded. For that the book remembers, for each mind, the minds held whose logs have asked for its log. That record outlives the verdicts, which `forget` clears.
- `book.witnessHeld(now, seen, { following })` looks at everything held. It is for every change that is no single copy: several logs taken in at one reading of the clock, a log held from a trusted witness, that witness's times taken into the evidence.
- A collective's event verifies only when every log it rests on is known up to the time the event is seen (core 9.4). Copies taken in one at a time, each at its own reading of the clock, never verify a collective with two founders. The verifier reads its clock once, and the logs it follows are known up to that reading.
- The clock is a change too. An event dated more than 300 seconds ahead does not verify until the clock is within 300 seconds of its date. A verifier that looks at least every 300 seconds sees it in that window, and its evaluation time is then its date, whichever moment of the window it was seen in. The book cannot do this itself: it reads no clock.
- An event dated more than 300 seconds ahead is left alone until the verifier's clock is within 300 seconds of its date: an earlier sight would be a sight of the event at a time when it did not verify.
- Nothing is recorded of a mind the book answers for no longer (7.1: the log is not verified), and the events of a log too long for the book are recorded as far as the book reads.

The review after that followed the rule as the README gave it and still counted a removed key. Three things were wrong, and each is now the book's to do, not the caller's to remember:

- **A copy that arrives between two looks.** A collective's update, pushed alone and taken in with `witness`, did not verify: its members' logs were known only up to the last look. It was recorded at the next look, and a proof by the key it removed, first seen in between, counted. core 9.4 treats a log the verifier follows itself as known up to now, and nothing let the caller say so short of holding every log again. `witness` and `witnessHeld` now take `following`, the minds whose logs the verifier follows, and know each up to the reading they are given. `witness` then looks also at what rests on a log that moved.
- **A log held in two branches.** Holding a duplicitous member's log again moved one branch, and the log is known only up to the least of them. `following` moves every place a copy ended.
- **The verifier's own sight beside a witness's.** The rule above first read "an event the evidence already has a time for is left alone". Evidence can shrink: a witness is trusted no longer. The verifier that had recorded nothing of its own then saw the event late, and a removed key counted. Its own sight is now recorded whenever the evidence's time is not later than its clock, and the earlier time stands while it is held. For a resolver this is also what Layer 1, 7.2 requires: it records when it first saw each event.

The review after that one found the twin of the third. The book withheld the verifier's own sight wherever the evidence's time was later than its clock, also for an event that verified at its clock. A trusted witness whose clock ran ahead, later withdrawn, left the verifier's own record a look late, and a removed key counted. An event whose evidence is later than the reading, and of which the verifier has no record of its own, is now judged as seen at the reading, and recorded if it verifies so. Only an event dated ahead does not.

That review also found a verdict kept from a moment when no verdict could be reached: a book first asked for a log with the call stack all but spent kept the refusal. [ADR-0004](0004-error-model.md) has the rule that closes it, for every answer a book keeps.

A look verifies only logs that have an event the verifier has not recorded. For a log whose every event is recorded, the look costs a lookup for each event held and no signature. Two things cost more, and the README says so. A reading moves the time each followed log is known up to, which forgets the verdict on it: the next `log(mind)` verifies it again. And the shortcut never applies to a log that holds an event that does not verify, or one beyond `maxEvents`. A source whose copies the verifier takes in can add an event of the first kind to any log.

core 9.5 now says when first sight is recorded: as soon as the event verifies with everything the verifier holds. What follows one copy at a time, with a schedule for events dated ahead and work in proportion to what changed, is the resolver's (M5); this package gives it the two operations, and what it must say with each reading.

**Three designs, and why this one.** The first book held copies and judged each as it was: a copy with any failing event was a rejection, and the advice was to hold the part that verified. That part could be a state the mind had left. The second summed each copy up when it arrived (what verified, and whether the next event was invalid or undecided) and let a copy take the place of another that showed no more. But what a copy shows changes: a copy whose second event waits on a member's log shows little today and everything tomorrow. Summed up today, it gave way to a shorter copy, and the removal in its third event was gone. Three reviews in a row found a removed key counting again through some such sequence. The third design is the one above. It has no rule for comparing copies, because it never compares them.

A fourth review found one way left in which a copy could undo another: through the proofs. The book kept every entry of every copy's `proof` for an event, and one entry that was no object made the event invalid, so a removal the book held and had verified was passed over. The rule that closes it is the same in kind as the rest: what a copy adds to an event depends on that copy alone (is it well formed?), and never on what else is held.

**What this does not protect against.** Anyone can write an event that a verifier cannot read: an object of the type `Merge` is enough. Served by a source the verifier trusts for the whole log, it cannot be told from the mind's own event, and the mind is refused until the verifier can judge the event or the caller drops the mind. The invalid class protects against damage. It does not protect against a trusted source that serves such an event on purpose, and a verifier with several sources is worse off for it than if one of them had withheld the log.

`hold` is for a log from a source the verifier trusts to serve the whole of it. `asOf` asserts that the log lacked nothing at that time, and nothing in the log can show it.

### Extensions a verifier does not implement

core 8.3 forbids treating a record as valid for any decision when it lists, in `critical`, an extension the implementation does not understand. `verifyLog`, `LogBook` and `judgeRecord` take the namespaces the caller implements (`understood`), and refuse an event or a record that lists another. The default is none. For an identity event the decision is whether the log verifies, so such a log is rejected (Layer 1, 4.8).

### A record is judged once

`judgeRecord` validates a record and verifies every proof on it, and returns a `JudgedRecord`: the validated copy and the proofs that verified. Every question about who signed takes that, so nothing is validated or verified twice, and nothing can be asked about a record that was not validated.

### Verdicts are times

Whether a record counts for a mind is the question "from when?". `ownSignedTime` answers with the earliest evaluation time at which the mind's own authority signed the record, or `undefined`: one of its valid operational keys, or for a collective its threshold. `@oip/delegation` adds the times a delegation or a charter role gives, and the earliest of them all is the answer. Expiry (core 9.6) is applied to each time.

A verdict of `undefined` carries no reason. `operationalProofTime` judges one proof and says why it does not count.

### A verified log is one list

A `VerifiedLog` holds its events as entries, each with the state after it and its evaluation time. It has at least its genesis, by its type. A version identifier is looked up with `entryAt`.

A state is of bounded size, however long the log: every set in it has a limit in Layer 1, Section 3. The two things that grow with a log, the children it has acknowledged and the keys it has revoked, are held once, by the log, each with the position of its event; `childrenAt` and `revokedAt` give what a state had. A copy in each state would cost the square of the log's length to keep, which a hostile log of small events could turn into gigabytes.

### What is handed out is frozen

A verified log and a judged record are also what the book keeps. Both are frozen, with everything in them, so a caller cannot change a verdict that the next caller will be given.

### A tripwire on comparing a `created`

The lint rule ADR-0003 promised is in `eslint.config.js`: in the pure packages a comparison that involves a `created` is refused, except in `evidence.ts`, which holds the two formulas and the rule that a log's dates do not run backwards (Layer 1, 4.2), and in the one file of `@oip/core` with the rule that a proof is not dated before its record (core 5.7). The file that judges members' proofs is not exempt.

It is a tripwire and no more. It catches `proof.created < removed`, the first thing a tired author writes. It does not catch a renamed local, a subtraction, an equality or a helper that takes the value. What stands behind it is the review of every change to these packages, and the rule that the two formulas are the only code that reads a `created` for a decision about time.

## Consequences

- A caller must say how fresh each log is. There is no default, as there is no default for evidence: the vectors' convention (everything seen when it was made, every log known in full) is written out in the conformance adapter, and nowhere in the package.
- A book answers from memory after the first question. Holding or dropping a log forgets the answers that rested on it, and no others.
- A caller that keeps its own first sight takes a copy in with `book.witness`, which holds it and records first sight of what then verifies. The book answers from everything it has been shown.
- The first failure of a member's proof is reported with its own reason, so a rejected collective says which member's log, key or timing was at fault.
- Members' logs are verified again in each book. A resolver that serves many verifiers keeps its own verified logs; that is M5's work.

## Alternatives

- **Pass logs as a parameter of every function.** Each function would repeat the nesting, the cycle check and the resolution of branches, and a caller could give two functions two different views of the same mind.
- **Compare `asOf` with the evaluation time.** It closes the window for future-dated proofs and makes a verifier wait up to 300 seconds before counting a proof from a signer whose clock runs fast. Handshakes are signed and checked live, so this was set aside.
- **Let an event that cannot be judged take no part at its position.** It is what "a copy counts for the events it has that verify" first meant, and it keeps a mind usable when a copy is damaged. It also lets a rival event take the position by default, against the evidence, and lets a later copy without the event undo it. Both were found by review, with a removed key counting again in each.
- **Sum a copy up when it arrives, and let a later copy replace it.** By how many of its events verify, and then by which events it shows: both were tried. What a copy shows depends on what the verifier holds when it looks, so every summary was wrong for some order of arrival.
- **A budget of verifications for one question.** It bounded the work of logs that are verified again along every path to them. Not judging what follows a losing event removes those paths, and with them the budget and the answers it made depend on the order of questions.
- **Return a reason with every verdict.** The cheapest answer to "does it count?" does not need one, and the reasons differ by path (own key, threshold, delegation, role). A caller that wants to explain asks about the proof it cares about.
