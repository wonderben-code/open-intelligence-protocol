# ADR-0010: A check that could not be made is refused, and never kept

**Status:** Accepted, 18 November 2026 (M2). It adds to [ADR-0004](0004-error-model.md), after three reviews of `@oip/identity`.

## Context

A function that judges answers and does not throw (ADR-0004). So a failure inside it becomes a refusal, whatever failed. Two failures say nothing of the value judged:

- **The call stack was all but spent.** The engine fails whatever call came next, or refuses to compile a regular expression it had not used before.
- **The process can serialise nothing.** Other code has put a `toJSON` on every object, and the canonical form of every record would be the same.

A refusal reached so is true of the moment. A caller that asks again gets the right answer. Whatever keeps the answer keeps the wrong one, and three things did:

- A book first asked for a log from a deep stack kept the refusal, and the mind stayed refused until its log changed.
- A record judged in a process that could serialise nothing came back as a record that no proof had signed.
- A look for first sight that was cut short recorded nothing and reported nothing. The removal of a key was then seen one look late, and a proof by the removed key counted.

## Decision

### Noting

Every `catch` in the packages that turns a failure into an answer first calls `noteCutShort(error)` (`@oip/schema`), which counts the failure if it is one of the two. The count is read with `cutShortCount()`, only ever as a difference.

**A spent stack is told by the engine's own message, whole**: "Maximum call stack size exceeded" (V8, JavaScriptCore) and "too much recursion" (SpiderMonkey), and the `SyntaxError` V8 gives for a regular expression it could not compile there. The serialiser's guard throws `UnfitProcess`, which is counted by its class.

Nothing else counts. An earlier version counted every `RangeError`. The Ed25519 library throws one for a point whose y-coordinate is no field element, so a proof with such an `R`, which anyone can add to a copy of a record, made every verifier refuse that copy for want of room. A part of a message does not count either: a parser's message quotes the text it was given.

`noteCutShort` never throws and runs no code of what it is given. It reads the message as an own data property. A failure it cannot so much as look at, such as a revoked proxy, is counted.

### Refusing

**Every public function that judges and answers with a result refuses with the clause `implementation limit` if the count moved while it worked.** `judging(work)` does this, and `cutShort()` is the refusal: one frozen value, which says nothing of what was judged. So a rejection with any other clause is a verdict on the value, and may be kept.

`judging` also answers where the work itself fails for want of room, at whatever depth: a `catch` far below may find no room to answer in. A failure that is neither of the two is a mistake in the calling program or in ours, and is thrown on.

A function that answers with a value and not with a result cannot say why. It answers the lesser thing: `false`, `undefined`, an empty list (`finding(work)`). Among them are `verifyEd25519`, `isEd25519PublicKey`, `recordRefMatches`, `ownSignedTime`, `collectiveSignedTime`, `operationalProofs` and `parseSelector`. A caller that keeps such an answer reads the count around the call, or uses `finding`.

### Keeping

Whatever keeps state works out its answer first, compares the count, and only then records:

- `LogBook.hold` takes nothing in, `LogBook.log` gives and keeps no verdict, and a look records no first sight.
- `LogBook.witness` and `witnessHeld` **answer with the refusal**. The caller looks again, with the same reading: a look that ends a reading late records a removal late.
- `witnessLog` records nothing and says nothing of the log.
- A `LogBook` whose options could not be read is not made: the constructor throws.

### A `catch` we do not own

`@noble/curves` decodes the key and `R` and multiplies the base point inside a `try` of its own that answers `false` for whatever is thrown. That is how it applies the rules on points and on `S`. It is also what it answers when the stack runs out there, and then `false` says nothing of the signature. After a `false`, `verifyEd25519` takes the same three steps again, a few frames further down, where a spent stack is noted. Their results are not used: no part of the verification is done by us ([ADR-0005](0005-cryptography-libraries-as-adopted.md), decision 1, stands).

The other libraries were read for the same thing in the review that found this one. `@noble/hashes`, `@scure/base` and `canonicalize` have no `catch` on a path OIP calls.

## Consequences

- To refuse once more than was needed costs a second call. To keep one wrong answer costs a mind its signatures, or gives a removed key a look's worth of signing.
- The count is module state in `@oip/schema`. The pure packages have one other piece of it, the memory of Ed25519 keys that passed the order check in `@oip/core`, which never changes an answer. The count says nothing of any input and is no clock. Work that runs between two readings on other inputs can move it, for code that judges within callbacks of its own, or across an `await`: the answer is then refused once, and never wrong.
- **One copy of `@oip/schema` in a process.** A process that loads two has two counts, and a note made through one is not seen through the other. The packages of one release depend on one version of it. A check for a second copy is owed to the release milestone.
- Nothing that arrives from outside moves the count. Each package has a property test that gives its judges arbitrary data and requires the count to stay where it was.
- An engine that words a spent stack in another way is not recognised. A verifier there behaves as it did before this record: it answers, and a book may keep a refusal until the log changes.
- An engine compiles a function when it is first called, which takes room on the stack too. The functions that are called from a `catch` are called once when `@oip/schema` loads, so that they are ready. A function that cannot be entered at all throws to its caller: nothing can answer from there.

## How it is tested

- In the test runner, by noting a failure from inside the work, as the places that turn one into an answer do: for each judge, a refusal with `implementation limit`, nothing kept, and the right answer when asked again.
- With the stack really spent, in a Node.js process of its own for each script (`*.node.ts`): the runner reads a module's exports through getters that fail there. Those lines are outside the coverage report and outside mutation testing.
- Where what is called takes bytes or text, which cannot be made to throw, a spy stands in for the call that found no room: the engine's JSON parser for a selector, and its decoder for bytes read as text.
- The first signature a process checks is asked for at each of thirty-one depths near the end of the stack, each in a process of its own, once with its key already checked and once not: it is never called invalid without that being noted. The library's own calls cannot be replaced, so this is the test of the `catch` we do not own and of the check of a point's order.
- Seventy-eight faults were planted, one at a time: every note, every refusal, every comparison of the count, and each part of the rule that tells a spent stack. The tests find sixty-four. Ten of the other fourteen are guards that only a failure inside a `catch` reaches, with the stack spent at that one place. Four change how the signature check is gone over again, and no answer at the depths asked. [The review record](../../reviews/build/M2-identity.md) lists them.
