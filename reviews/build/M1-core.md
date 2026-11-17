# M1 review: Core

**Reviewed:** 17 November 2026 · **Diff:** `24a14b1..c3fcfbb`, then the fixes (`c3fcfbb..949ec9c`), then the fixes to those · **Specification revision:** 2026-11-17, with [OEP-0001](../../oeps/oep-0001-core-clarifications.md)

[BUILD.md](../../BUILD.md), Section 7, asks for a fresh review at the end of each milestone, by an agent whose only context is the repository, the specification and the milestone's diff. M1 had two, run in parallel, each with its own area:

- **Review A: conformance and test quality.** Every rule of core Sections 1 to 8 and 10 against the code; the specification change of OEP-0001 against the Python checker and the vectors; whether each test can fail, and whether the acceptance criteria of BUILD.md have evidence.
- **Review B: security.** Forgery, replay and second spellings of proofs; keys and signatures against core 4.4; the parser against hostile text; resource exhaustion; values that are not plain data; secrets; the supply chain.

The fixes were large, so they were reviewed in turn:

- **Review C: the fixes.** Is each of the first 27 findings really closed, and did closing them break anything?
- **Review D: one mechanism.** The fix for Review C's main finding lets a record the parser has just built be validated without a second copy. That is a shortcut past a safeguard, so it had a review of its own.

All four were read-only. Each proved its findings with probes it ran. This file records every finding and what was done about it. Nothing was waived: a finding is **fixed**, or it is **queued** as a question with the milestone that needs the answer, or it is **for Eks**.

## Verdicts

- **Review A:** "The implementation is careful and the vectors reproduce, but I found one High problem in the specification change and six Medium ones, mostly in the Python checker, the parser oracle and the evidence for two acceptance criteria."
- **Review B:** "One Medium, a memory denial of service in the parser that a single request triggers. With ordinary byte arrays and text from the network I could not forge, replay or respell a proof, get a key or signature past core 4.4, or make the parser accept a text two readers would read differently."

- **Review C:** "The fixes are real and mostly complete. I could not forge, replay or mislabel a proof, get a key or signature past core 4.4, or make a validator return anything but a fresh plain copy. Below the implementation's own limits, `parseJson` and the Python checker agreed on all 450,000 generated texts. Two problems are worth fixing before the merge."
- **Review D:** "The shortcut is sound in an unmodified runtime. No caller outside the parser path gets a value validated without the copy, the parser meets every postcondition the copy set, and validation in place changes nothing. The problems are in the limits, not in the trust." No Critical or High finding.

The High finding was a mistake in a rule this milestone had itself added to the specification. It was caught before anything was merged, which is what the review is for. The milestone was not merged until every item below was closed.

## Review A: conformance and test quality

| # | Severity | Finding | Disposition |
|---|---|---|---|
| A1 | High | The depth limit added as core 1.9 applied to a container as a whole. A record nesting 64 deep is valid alone, and a `LogPage` adds two levels, so it could not be carried. Anyone can bring an event to that depth by adding an entry to its `proof`, which never counts and which nobody signs: one such entry would have stopped a log from being served. | **Fixed, as one change.** core 1.9, 1.6 and 12 now say that for a container the limits on size and depth apply to each record it carries, counted from that record, and to the container without them. `@oip/schema` takes a container apart (`containerParts`) and applies the limit part by part; `parseRecord` reads to the depth a container can have, 67; `canonicalize` and `contentId` accept it. The Python checker does the same (`profile_ok`). Two vectors and a control: a page carrying an event that nests 64 deep must be accepted, and 65 rejected. OEP-0001 gives the reasoning. |
| A2 | Medium | `parseJson` accepted a text that is not valid Unicode: half a surrogate pair written raw beside an escape for the other half. Such a text has no UTF-8 form. The campaign's oracle had the same blind spot, and the differential test filtered such texts out. | **Fixed.** The text itself is checked. The oracle refuses it too, by the platform's own test. The filter is gone: the Python checker is now asked about these texts and agrees. |
| A3 | Medium | Most of the specification change never reached the Python generator or the vectors: `record_ok` did not check that `proof` entries are objects or that `ext` names are namespaces, `verify_log` did not apply core 1 to events, and no vector exercised the new rules. | **Fixed.** `record_ok` and `verify_log` check them. Ten `record` cases were added (five to accept, five to reject), with controls. Cases of kind `record` may now be must-accept cases. |
| A4 | Medium | The Python checker rejected a safe integer written with more than 4,300 digits, because Python refuses to convert a longer run of digits. core 1.2 judges a number by its value. | **Fixed.** `_integer` reads the digits as text and never converts more than 18. A vector, `json-integer-written-at-length`, and differential cases at 5,000 digits. |
| A5 | Medium | I-JSON forbids noncharacters (RFC 7493, 2.1). core 1.1 says a record is I-JSON and names only two of its three rules. Both implementations accepted them. | **Fixed: they are forbidden.** core 1.1 names the rule. Both implementations reject them, in strings and in member names, written as themselves or as escapes. Two vectors with controls. The reason is in OEP-0001. |
| A6 | Medium | The mutation criterion had no evidence at the reviewed commit: the only report predated the source. Of the reviewer's own 59 mutants, three survived for want of a test: the order-check memory keyed by half a key (two variants), and a proof's `created` cut to milliseconds. | **Fixed.** Tests for both, each shown to fail on the mutant. Final scores are under [Mutation testing](#mutation-testing). |
| A7 | Medium | Both starting budgets of BUILD.md 3.8 are missed about twofold, and the gates that replaced them were loose. | **Gates fixed; the budgets are for Eks** (E12). The ratio to the bare library is now gated at 2.0 (measured 1.8), and two more ratios gate the budgets themselves (4.6 for a record with two proofs, measured 4.0; 2.3 for an identity event, measured 2.0). ADR-0006 now says plainly that the budgets are missed threefold in the portable implementation and how M5 meets them. |
| A8 | Low | `verifyProofs` enforced half of core 5.1: it gave an entry of `proof` that is not an object a verdict of its own, and a test of core 5.5 asserted that. | **Fixed.** An array that holds anything but objects is not a proof set: nothing is judged, and `issues` says why. The test was rewritten. |
| A9 | Low | Tests that could not fail, or asserted less than their names: the cache-key test, "never throws", "every reference" (which checked three), core 5.7 (which compared strings), an oracle built on `Date.parse`, and coverage claimed for core 4.3, 6.2 and 1.8. | **Fixed**, each one. The reference test now accounts for all 269 strings of the form of a content ID in the vectors. core 5.7 compares instants. A proof's `created` is checked to the nanosecond against literals. core 4.3 is cited by a proof test with keys of other types, core 1.8 by a test through `parseRecord`. core 6.2 is owed by M2 in `plan.json`: its first half needs an identity log. |
| A10 | Low | "Never throws" was false for some inputs, and some `@throws` notes were incomplete. | **Fixed.** Every function that judges catches what reading its input can throw. See B2 for the cause. |
| A11 | Low | API that is easy to misuse: `createProof` signed a malformed record; `withProofs` worked on unsigned types; `verifyProofs` returned a result whose `ok` meant only "the proof set was read"; core 5.7 could not be overridden though it is a SHOULD. | **Fixed.** `createProof` checks the record, as it will stand with the proof on it, before the signer is asked for anything. `withProofs` refuses unsigned types. `verifyProofs` returns `{ verified, rejected, issues }` with no `ok`. `earlierThanRecord: true` is the override. |
| A12 | Low | The Python checker compared a proof's `@context` with the record's by Python's own equality, which takes `true` for `1`, and a missing member for `null`. | **Fixed.** It compares canonical forms and requires the member. |
| A13 | Low | The limit on how many values a record holds was labelled core 1.6. | **Fixed**, at the second attempt. Relabelling it was not enough: a count over a whole container contradicts the rule of A1. See C-N1. |
| A14 | Low | No vector had an `R` with a small-order component other than the identity, and the Ed25519 negative cases had no controls. | **Fixed.** `signature-r-mixed-order`, and a control for each of the three signature cases. Also `key-reference-position-wraps-around`: position 2⁶⁴+1 with the content ID of the event at position 1, which a reader that keeps positions in 64 bits would accept. |
| — | Note | The CHANGELOG had a sentence cut short, and called a rule change a clarification. `parseRecord` and the reference adapter called every record of an extension-defined type malformed. | **Fixed.** `parseExtensionRecord` reads such records; the adapter judges them as core 7 says. |
| — | Note | OEP-0001 has status Review, and the normative text is already changed, so merging is Eks's decision on the OEP. | **For Eks** (E13). |

## Review B: security

| # | Severity | Finding | Disposition |
|---|---|---|---|
| B1 | Medium | One text of 8 MiB, `[[],[],…]`, made the parser allocate 730 MiB: four million arrays, built before any limit on the record applied. | **Fixed.** Each array was grown one element at a time and kept room for many more. Arrays are now cut at their exact size, and the parser spends on a text about what the platform's own parser does: reading that text as a record takes under 200 MiB and half a second. A test bounds the memory. (A cap on the number of values, added first, was removed again: C-N1.) |
| B2 | Low | A value could pass `validateJson` and then be serialised as something else: an object that answers differently the second time it is read. Judges could be made to throw by the same means. In-process only. | **Fixed at the root.** Every validator builds a plain copy from property descriptors, validates the copy and returns it. Nothing reads the original twice, and no getter or proxy trap for a member is ever called. |
| B3 | Low | `verifyEd25519` checked the order of `A` and `R` on one read of its inputs and verified on another. In-process only. | **Fixed.** Each input is copied once, and every check uses the copies. |
| B4 | Low | The 1 MiB rule did not bound a container's own members, and the allowance for `Sealed` was not tied to its ciphertext. | **Fixed** for containers, in the specification and the code (A1). For `Sealed` the implementation now bounds the ciphertext (1,398,123 characters: a packet of 1 MiB with the cipher's tag, in base64url) and the rest of the record (1 MiB) separately. The number is **queued for M4**, where sealing is built; OEP-0001 lists it as open. |
| B5 | Low | `withProofs` merged entries it had not validated and checked only their count. | **Fixed.** Each added entry must have the form of a proof, and the result is checked for size and depth. |
| B6 | Low | A `maxLength` that is not a number switched the limit on text off, and `parseJson(text, null)` threw. | **Fixed.** Anything but a non-negative safe integer leaves the default limit in force. |
| B7 | Low | Issue messages carried the record's `type`, and paths, raw: text from the input could pass for part of a log line. | **Fixed.** Both are quoted, control characters are escaped, and long ones are cut. |
| B8 | Low | `hexToBytes` repeated part of its argument in its error. | **Fixed.** The message is constant ([ADR-0007](../../docs/adr/0007-programming-errors.md)). |
| B9 | Note | Durations had no upper bound: a million digits was a valid duration. | **Fixed.** 64 characters, in core 1.5, the schema and `parseDuration`. |
| B10 | Note | 256 forged proofs cost about 0.9 s, not the half second ADR-0006 stated, and a proof repeated in a record was verified each time. | **Fixed.** A repeated proof is verified once. The ADR gives the measured cost and what bounds it. |
| B11 | Note | The Python checker rejects numbers that core 1.2 allows. | **Fixed** (A4). |
| B12 | Note | `createProof` asked the signer in cases that could not give a usable proof. | **Fixed** (A11). |
| B13 | Note | `parseJson` accepted a string that is not itself valid Unicode. | **Fixed** (A2). |

### What Review B tried and could not break

- **Ed25519.** `S+L` to `S+15L`, `S = L`, high bits set; all eight small-order points as `A` and as `R`; mixed-order `A` and `R` made with a known scalar; six non-canonical encodings and every candidate with `y < 19`; wrong lengths and types. All rejected. 5,682 encodings agree with the Python checker.
- **What ADR-0005 says of the library holds:** in strict mode it accepts a mixed-order `A`, and an `R` that is the identity, of small order or mixed; it rejects a small-order `A`; no point with `y < 19` has order L.
- **Proofs.** No second spelling of a `proofValue`. Reordered members give the same digest. Added members, `@context` tricks, and changes to purpose, method or `created` fail. A proof does not verify on another record or type. A record changed while a signer was signing is caught, and so is a hostile signer.
- **Parser and canonical form.** Duplicates in every disguise, prototype pollution, about 70 spellings of numbers, surrogates, a byte order mark, depth 65 and 100,000, invalid UTF-8. 6,000 generated texts agree with the Python checker on acceptance, canonical bytes, content IDs and digests.
- **Time.** Every regular expression is linear.
- **Secrets.** No key appears in `inspect`, in `JSON.stringify`, in a function's source or in any error. Verification reads neither the clock nor the random number generator.
- **Supply chain.** The four runtime dependencies are pinned exactly and their integrity matches the registry. The mutation workflow has read-only permissions and pinned actions.

Review A also changed two bits of every byte of all 49 signed records of the vectors, 102,656 changes: none left every proof standing.

### Left for later milestones

- **X25519 keys of low order** encode and decode as Multikeys, which core 4.2 permits. The HPKE layer must check for an all-zero shared secret. **Queued for M4** (Q26).
- **Timing side channels of signing in JavaScript** were not examined. Keys that matter belong in a keystore (M6), and the signer interface already keeps them out of this package.

## Review C: the fixes

Of the 27 findings and the four below under "mutation survivors", Review C found 26 closed, four partly closed and one closed in name only. The partly closed ones are closed now: A6 by the scores below, B7 by N6, S1 (which Review C knew as C1) by N4, A13 by N1. B4 stays as recorded: the number for `Sealed` is queued for M4.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| N1 | Medium | A container was still limited as a whole, by the count of values: 1,048,576 in one text or one value. Three events that are each well formed, each with a junk `proof` entry of 400,000 values, could not be carried in one page, though the Python checker read it. Raising `maxLength` did not lift it. | **Fixed.** The length of the text is the one limit on an input as a whole, and it is the reader's own. The parser has no cap on values. A record `parseRecord` has just parsed is validated as it is, without a second copy (`declareParsed`), so reading costs less than it did with the cap. A validator given a value from elsewhere reads 4,194,304 values, as many as 8 MiB of text holds, or what its caller allows. OEP-0001 says there is no limit on a container as a whole. |
| N2 | Medium | An extension-typed record with no `created` was accepted by `parseExtensionRecord` and the reference adapter. core 7 requires `created`, and the Python checker rejects it. The differential test had no extension-typed record to mutate, so it could not see this. | **Fixed.** The schema requires it. A negative vector with a control. The differential test now mutates extension-typed records, the containers at their deepest and a duration at its longest. |
| N3 | Low | The size half of the container rule and the limit on a duration were in neither the Python checker nor the vectors. core 1.6 did not say exactly which bytes of a container are its own. | **Fixed.** The checker applies both. core 1.6 and 1.9 name the members that are taken out. Two vectors for the duration. For size, a vector would add a megabyte to the file, so the two implementations are compared in the differential tests instead, at 1 MiB and one byte more, for a record, a carried record and a container's own part. How the vectors should carry cases too large to write out is **queued** (Q29). |
| N4 | Low | The regression test for S1 passed on the old code when its file ran whole: where the stack runs out depends on how warm the code is. | **Fixed.** The test has a file of its own, where the code is cold, and asserts that a check really was cut short. It fails on the old code in every run. |
| N5 | Low | The vectors could not tell an implementation that knew only part of the new rules: one kind of noncharacter of three, one kind of container of four. | **Fixed.** Vectors for U+FDD0 to U+FDEF, for the last plane and for a member name; for `DuplicityEvidence` at 67 deep, a `FeedPage`, a `Bundle`'s location, and a container's own part. |
| N6 | Low | Messages still carried U+0085, U+2028, U+2029, C1 controls, DEL and bidirectional controls from the input. | **Fixed.** Quoted input and paths escape them all. |
| N7 | Low | Nothing tested that `proof.ts` works on the validated copy: two mutants that used the caller's object survived. | **Fixed.** Tests with a proof that holds one thing and answers another. |
| — | Note | `createProof` read its options twice: an options object that answered differently the second time had the signer sign once before the refusal, or dated a proof before its record. | **Fixed.** Each option is read once. |
| — | Note | With `Object.prototype.toJSON` set by other code in the process, every record had the same canonical form and content ID. | **Fixed.** Nothing is serialised while every object or every array has a `toJSON`. |
| — | Note | A vector's reason named a problem type that does not exist; `vectors.json` held a raw noncharacter, so a strict reader could not load it; `verifyProofs` on a deep page gave depth as the reason and not that a page is unsigned; `unsupportedCritical` threw on a `critical` it could not read; the changeset claimed more than is true of proxies. | **Fixed**, each one. |
| — | Note | `firstSeen` counts in a container's own megabyte, which is about 11,000 first-seen times. | **Recorded** in OEP-0001: a longer log is served in pages. |
| — | Note | `canonicalize` and `contentId` take any value nesting up to 67 deep, not only containers. | **Documented** in the README: they compute, and `parseRecord` judges. Signing and verifying stop at 64. |

Review C also ran 37 mutants of its own on the new code (31 killed, one equivalent; the five survivors are N5, N7, S1 and one of no consequence), 120,054 spellings of numbers through the Python checker's new integer reader, and 90,000 mutated records through both implementations.

## Review D: the parser's fast path

Scope: the commit that fixed N1 (`949ec9c..24dfec9`), and in it the mechanism that lets `parseRecord` validate what it has just parsed without copying it.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| D1 | Medium | A copy cost several times what the original does: each copied array was grown one element at a time and kept room for seventeen, 185 bytes for an array of one. With the budget of N1 that was about 1 GB for one value of 8 MiB, and a shared structure of 1 kB ended a process with a 256 MB heap. `verifyProofs` looked twice at every value it refused. | **Fixed.** A copied array is made at exactly its size, from one read of the length: a copy now keeps what its original keeps, which a test measures. A value is looked at a second time only when it was refused for its depth. |
| D2 | Medium | One hostile text of 8 MiB cost `parseRecord` up to 640 MB and 2 s. About half was the size check, which wrote the whole value out to learn that it was over 1 MiB. | **Fixed.** A size is counted without writing anything, and no further than one byte past the limit. The count is compared with the serialiser on every generated value and every vector. Reading that text now takes about 175 MiB and half a second, close to what the platform's own parser needs. The README says what a character of text costs and that an endpoint for one record should set `maxLength` near the size limit. |
| D3 | Low | A container read with a raised `maxLength` could not then be hashed or written: `canonicalize` and `contentId` stopped at their own count of values. | **Fixed.** They take `limits`. |
| D4 | Low | The fast path was switched on by a declaration that any code could make for any value, and that took effect for whoever validated the value next. | **Fixed.** There is no declaration. `validateParsedRecord` and `validateParsedExtensionRecord` are what a parser calls, with the value and its depth; `validateRecord` always copies. |
| D5 | Low | The copy had been the second check on the parser's arrays. With `Array[Symbol.species]` changed by other code in the process, `splice` gave the parser arrays of another class. With `Array.prototype` cut off from `Object.prototype`, the guard against a `toJSON` saw nothing. | **Fixed.** The parser builds its arrays by hand. The guard looks at both prototypes. |
| D6 | Low | A record keeps its whole source text alive: the engine makes each string a slice of the text. Twenty records of 862 characters, each read from 8 MiB of white space, held 160 MB. Older than this milestone's fixes. | **Queued for M5**, where records are stored: a store keeps the canonical form, never the object read from the wire. The README says so now. |
| — | Note | Characters a renderer shows as nothing reached messages: zero-width characters, variation selectors, tag characters, which can carry text nobody sees into a log or a model's context. | **Fixed.** Everything that is not a visible character or a space is escaped. |
| — | Note | Limits were read through the prototype chain, so a changed `Object.prototype` could set one. An array at the root of a refused text stayed declared. The guard threw an error the documentation did not name. | **Fixed**: own members only; no declaration is left to stay; the documentation names the error. |

Review D also found the two implementations in agreement on 133 cases at the boundaries of size, depth and duration, and the parser in agreement with an independent audit on 4,000 generated texts.

The fixes for Review D were not reviewed a fifth time. Each has a test that fails without it, and the differential tests and the mutation run below cover them.

## Found after the reviews, while reading the mutation survivors

| # | Severity | Finding | Disposition |
|---|---|---|---|
| S1 | Low | The memory of order checks remembered every answer, a no as well as a yes. `encodesPointOfOrderL` answers no when anything in it throws, and anything throws when the call stack is spent. So one verification made from a deep stack marked an honest key as bad, and every later signature by that key was refused until the memory forgot it. It needs a caller that verifies from a nearly spent stack, which is why it is Low; but nothing in the package prevented it. Neither review found it; a test written to cover a `catch` that no test reached did. | **Fixed.** Only a yes is remembered. A no is worked out again each time, which costs a bad key's sender nothing an honest verification does not cost. A test runs the verifier at 200 depths of a nearly spent stack and checks that the key verifies afterwards (see N4 for how it was made reliable). |
| S2 | Low | Nothing tested that a function which promises never to throw keeps the promise when the stack is nearly spent. | **Fixed.** `test/stack.ts` runs a function at one depth after another near the end of the stack. `verifyProof`, `verifyProofs`, `recordRefMatches`, `parseRecord`, `parseExtensionRecord`, `unsupportedCritical`, `verifyEd25519` and `isEd25519PublicKey` are run that way: each answers from the moment it can be entered. |
| S3 | Low | The parsers of references are given `unknown`, and the guard that the value is a string had no test. A pattern's `test` turns its argument into a string, so without the guard an array holding one reference would have been read as that reference. | **Fixed**: tests with arrays, objects that print as references, and `String` objects. The code was right. |
| S4 | Note | Two pieces of code could not change any result: a shortcut in `withoutProof`, and a second check of the whole record in `withProofs` that the size check already implies. | **Removed.** |

## Mutation testing

`pnpm mutation` (Stryker, [stryker.config.mjs](../../stryker.config.mjs)); the threshold of BUILD.md is 85%.

| Package | What was mutated | Score | Killed | Timed out | Survived | Not covered |
|---|---|---|---|---|---|---|
| `@oip/core` | all of `src` | **98.5%** | 1,744 | 17 | 23 | 3 |
| `@oip/schema` | the four files M1 changed | **95.5%** | 617 | 4 | 26 | 3 |

A mutant that only times out is counted as detected.

### How the numbers were made, and what was wrong with the first ones

- **`@oip/core`** was run in full on commit `97356a8`: 97.9% (1,733 killed, 17 timed out, 26 survived, 11 not covered). Reading those 37 led to three tests (S5 to S7 below), and the lines they cover were run again on the final commit. The table shows the result.
- **`@oip/schema`**: the four files M1 changed (`validate.ts`, `containers.ts`, `text.ts`, `issue.ts`) first scored **75.3%**, below the threshold. Two things were wrong, and the number was one of them.
  - *The measurement.* Stryker works on a copy of the repository. In the copy a package reached its neighbours through `node_modules`, which leads back to the original, so a mutant in `@oip/schema` met the tests of `@oip/schema` only. Applied by hand, a mutant that Stryker reported as surviving failed a test of `@oip/core` at once; the report listed five tests as covering it, all from one file. Each package's tests now resolve the workspace packages by path from the configuration's own place ([scripts/lib/source-aliases.ts](../../scripts/lib/source-aliases.ts)), so a copy resolves to itself, and Stryker no longer puts a `@ts-nocheck` line at the head of the copied files, which broke a test that compares a file with what a README quotes of it.
  - *The tests.* Most of the survivors that were real had one cause: the tests of `@oip/schema` asserted that a value was refused, and not what the refusal said. A mutant that changed a message, a path or a clause, or that removed a check another check repeats, changed no verdict. [test/issues.test.ts](../../packages/schema/test/issues.test.ts) now reads the path, the message and the clause of each refusal (S8 below).
- The four files were then run again by file and line range, each run with the tests of every package counted, and the lines that later tests and S11 touched once more. The table shows the result.
- The rest of `@oip/schema` is M0's code and has not been through a run in which every package's tests count. The weekly workflow now runs each package as its own job, which will show it; it is on the list for M2.

### The survivors that remain

Each was read. None changes a verdict.

**`@oip/core`** (26):

- *A guard in front of a `try`* (9: `ed25519.ts` lines 60, 89 and 120). Without the guard the library is handed a value of the wrong length or kind, throws, and the `catch` gives the answer the guard gave.
- *The library's strict mode* (3: `ed25519.ts` lines 34 and 123). The wrapper's own checks of order decide first. No point of order L has a second encoding, and for points of order L the two verification equations agree, so no input tells the modes apart once the order is checked. The tests show the three things the library accepts on its own; these lines are the second lock.
- *A `catch` that returns nothing* (2: `ed25519.ts` line 36, `content-id.ts` line 117). Emptied, the function returns `undefined`, which its one caller reads as it reads `false`.
- *The length and prefix of a Multikey* (4: `multikey.ts` lines 54 and 55). The pattern checked before them fixes the length, and the two prefixes differ in a byte that is still compared.
- *The same result by another route* (5: `json.ts` lines 52, 123, 188 and 266; `proof.ts` line 142). An array made with or without its length, a depth assigned when it is equal, a limit that falls back to the default either way.
- *Not reached by any test* (3: `proof.ts` line 315; `record.ts` lines 143 and 146). Each is a last `catch` for a failure nothing is known to cause. They stay: the functions promise an answer.

**`@oip/schema`** (29):

- *The same result by another route* (10: `validate.ts` lines 76, 199, 217, 228, 257, 276 and 429; `containers.ts` lines 51 and 66; `issue.ts` line 45). The check after each one refuses the same values, or the value assigned is the one already there; `issue.ts` line 45 bounds work, not the result.
- *The clause of a syntax no record uses bare* (3: `validate.ts` lines 305 and 316). No record holds a decimal that is not an amount, and everything in a proof is given core 5.2 whether or not its pattern is found.
- *Reading the validator's errors* (8: `validate.ts` lines 333, 334, 341, 348, 351 and 354). The compiled validators always give `params`, a `message` and a list of errors, and never the remark about `anyOf` alone, so the fallbacks beside them are never taken.
- *The issue given when there is none to give* (8: `validate.ts` lines 388 to 392 and 400). `reject` takes a fallback for an empty list of issues. A validator that refuses always gives errors, and the rules are only called a failure when they gave issues, so the fallback is never used; the validator for every name exists.

None of these changes a verdict, a path, a message or a clause that anything can observe.

### Found while reading the survivors of the final run

| # | Severity | Finding | Disposition |
|---|---|---|---|
| S5 | Low | `contentIdIfAny` gave no content ID to a string or an array, and nothing tested it. Taken apart member by member, either looks like an object with numbered members, so without the check a reference to the object `{"0":"a","1":"b"}` would have matched the string `"ab"`. | **Tested.** The code was right. |
| S6 | Low | `formatKeyRef` and `formatControlKeyRef` refused a key with something before the Multikey, untested. | **Tested.** The code was right. |
| S7 | Low | `verifyProof` and `verifyProofs` promise an answer whatever state the process is in. With a `toJSON` on a prototype nothing can be serialised, and the two `catch` blocks that turn that into a rejection were reached by no test. | **Tested**: both answer with a rejection, and are right again once the prototype is clean. |
| S8 | Medium | The tests of `@oip/schema` did not read what a refusal says. A server answers a malformed record with the clause it breaks, and a person fixes it by the path and the message; a change that broke any of the three would have passed. Among what no test distinguished: a member that is hidden or an accessor, an element that is a hole, an array whose length is not a count, the budget of values at its boundary, the clause cited for each value syntax and for each member every record shares, the boundary of the depth limit on a container's own part, and the guard that cuts a path written mostly in escapes. | **Tested**, 28 tests. The code was right in each case. One check that could never decide anything was removed: whether what a parser built is an object was asked twice. |
| S9 | Medium | Mutation testing did not count the tests of other packages (above). Every score it had given for a package that others depend on was too low, and a real gap could hide among the false survivors. | **Fixed**, and the weekly workflow split into one job for each package: with every test counted, one package takes hours. |
| S10 | Low | Four small helpers had no test that read their answers: the depth of a value, which must count arrays and objects and nothing else; the records a `Bundle` carries, its location and participant only when it has them; the escaping of a JSON Pointer token; and the form of an escape at U+FFFF, where the short form ends. | **Tested**, 5 tests. The code was right. |
| S11 | Low | Issues are given deepest first. The line that measured depth survived being changed to measure the length of the path's text: the two agree on every set of errors the schemas give together today, and no test could tell them apart. | **Fixed**: the measure is a helper of its own, `pointerDepth`, with a test that a short deep path is deeper than a long shallow one. |

## The specification changed in this milestone

The reviews turned a list of clarifications into a slightly larger change, all of it in [OEP-0001](../../oeps/oep-0001-core-clarifications.md) and the [CHANGELOG](../../spec/CHANGELOG.md): containers are limited part by part and never as a whole (A1, B4, N1, N3), noncharacters are forbidden (A5), and a duration has a length (B9). The Python generator, the vectors and the technical paper changed with the text, in the same commit. `vectors.json` gained cases and lost none: every value that was there is byte for byte what it was.

## After the fixes

- `pnpm run ci` passes from a clean build: lint, formatting, layering and guards, the build, type checks, 1,060 tests with coverage, the generated files, the golden vectors, the differential tests against the Python checker, clause coverage, the API reports, the benchmarks and the documentation.
- The campaign of 1,000,000 generated inputs to the parser passes against the stricter oracle.
- The vectors hold 17 must-accept cases, 80 negative cases and 30 controls.
