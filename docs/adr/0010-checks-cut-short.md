# ADR-0010: A check that could not be made is refused, and never kept

**Status:** Accepted, 18 November 2026 (M2). It adds to [ADR-0004](0004-error-model.md), after four reviews of `@oip/identity`.

## Context

A function that judges answers and does not throw (ADR-0004). So a failure inside it becomes a refusal, whatever failed. Two failures say nothing of the value judged:

- **The call stack was all but spent.** The engine fails whatever call came next, or reports a regular expression it had no room to parse or to compile as one that is in error.
- **The process can serialise nothing.** Other code has put a `toJSON` on every object, and the canonical form of every record would be the same.

A refusal reached so is true of the moment. A caller that asks again gets the right answer. Whatever keeps the answer keeps the wrong one, and three things did:

- A book first asked for a log from a deep stack kept the refusal, and the mind stayed refused until its log changed.
- A record judged in a process that could serialise nothing came back as a record that no proof had signed.
- A look for first sight that was cut short recorded nothing and reported nothing. The removal of a key was then seen one look late, and a proof by the removed key counted.

## Decision

### Noting

Every `catch` in the packages that turns a failure into an answer first calls `noteCutShort(error)` (`@oip/schema`), which counts the failure if it is one of the two. The count is read with `cutShortCount()`, only ever as a difference.

**A spent stack is told by the engine's own message, whole**: "Maximum call stack size exceeded" (V8, JavaScriptCore) and "too much recursion" (SpiderMonkey). V8 reports a regular expression it had no room for as a `SyntaxError` that names the expression and then gives the reason: "Stack overflow" where it could not compile it, and "Maximum call stack size exceeded" where it could not parse it. Such an error counts by how it begins and by that reason at its end, which is the engine's and comes after the expression.

The serialiser's guard throws `UnfitProcess`, which is counted by a mark it carries as an own property: a symbol from the registry that a whole process shares (`Symbol.for`), so that a copy of `@oip/schema` knows the error of another copy.

Nothing else counts. An earlier version counted every `RangeError`. The Ed25519 library throws one for a point whose y-coordinate is no field element, so a proof with such an `R`, which anyone can add to a copy of a record, made every verifier refuse that copy for want of room. A part of a message does not count either: a parser's message quotes the text it was given.

`noteCutShort` never throws and runs no code of what it is given. It reads the mark and the message as own data properties. A failure it cannot so much as look at, such as a revoked proxy, is counted.

### Refusing

**Every public function that judges and answers with a result refuses with the clause `implementation limit` if the count moved while it worked.** `judging(work)` does this, and `cutShort()` is the refusal: one frozen value, which says nothing of what was judged. So a rejection with any other clause is a verdict on the value, and may be kept.

`judging` also answers where the work itself fails for want of room, at whatever depth: a `catch` far below may find no room to answer in. A failure that is neither of the two is a mistake in the calling program or in ours, and is thrown on.

A function that answers with a value and not with a result cannot say why. It answers the lesser thing, the one that lets nothing count (`finding(work)` does this for a function that finds something or nothing):

| Function                                                                                           | Its answer where a check was cut short                                             |
| -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `verifyEd25519`, `isEd25519PublicKey`, `isEd25519Multikey`, `isX25519Multikey`, `recordRefMatches` | `false`                                                                            |
| `contentIdIfAny`, `parseSelector`, `ownSignedTime`, `collectiveSignedTime`                         | `undefined`                                                                        |
| `operationalProofs`                                                                                | an empty list                                                                      |
| `unsupportedCritical`                                                                              | `["critical"]`: the record names something nobody understands, and is not acted on |
| `understandsCritical`                                                                              | `false`                                                                            |
| `lineage`                                                                                          | `claimed` for a parent whose acknowledgement could not be judged                   |

A caller that keeps such an answer reads the count around the call, or uses `finding`.

### Keeping

Whatever keeps state works out its answer first, compares the count, and only then records:

- `LogBook.hold` takes nothing in, `LogBook.log` gives and keeps no verdict, and a look records no first sight.
- `LogBook.witness` and `witnessHeld` **answer with the refusal**. The caller looks again, with the same reading: a look that ends a reading late records a removal late.
- **A look made again finds what the first passed over.** A look that was cut short may already have moved the logs it follows to its reading. So `witness` looks at what rests on every log it follows, whether or not this call moved the log: the look made again with the same reading reaches what waited on those logs, as the first would have.
- `witnessLog` records nothing and says nothing of the log.
- A `LogBook` whose options could not be read is not made: the constructor throws.

### A `catch` we do not own

`@noble/curves` decodes the key and `R` and multiplies the base point inside a `try` of its own that answers `false` for whatever is thrown. That is how it applies the rules on points and on `S`. It is also what it answers when the stack runs out there, and then `false` says nothing of the signature. After a `false`, `verifyEd25519` takes the same three steps again, sixteen frames further down, where a spent stack is noted. Their results are not used: no part of the verification is done by us ([ADR-0005](0005-cryptography-libraries-as-adopted.md), decision 1, stands).

Depth is what makes this sound. The library takes the steps one frame below `verifyEd25519`. Taken again from no deeper, they find room wherever the library found it, and a failure of the library's goes unseen: so it was in a process that had verified often, at about one in three hundred of the depths asked near the end of the stack. One frame more was enough there. The size of a frame is the engine's affair and changes when it compiles a function again, so the margin is sixteen frames and not one. The steps are taken only after a `false`, and add about an eighth to what a signature that fails costs.

The other libraries were read for the same thing in the review that found this one. `@noble/hashes`, `@scure/base` and `canonicalize` have no `catch` on a path OIP calls.

## Consequences

- To refuse once more than was needed costs a second call. To keep one wrong answer costs a mind its signatures, or gives a removed key a look's worth of signing.
- The count is state of the process, kept by `@oip/schema`. The pure packages have one other piece of state, the memory of Ed25519 keys that passed the order check in `@oip/core`, which never changes an answer. The count says nothing of any input and is no clock. Work that runs between two readings on other inputs can move it, for code that judges within callbacks of its own, or across an `await`: the answer is then refused once, and never wrong.
- **Two copies of `@oip/schema` in a process share the count.** A program can end up with two, from two installed versions or two bundles, with `@oip/core` noting through one and `@oip/identity` comparing through the other. The count is therefore kept on the global object, under a symbol from the registry the process shares, and the first copy to load leaves it there for the rest. `UnfitProcess` is known across copies by its mark, for the same reason. The names of the two symbols end in a number, which changes if what they hold ever does. Where the global object takes no new property, or holds under the name something that is no count, a copy keeps a count of its own: one copy in such a process works as before, and two would not see each other's notes. Other code may freeze everything the global object holds after the count is there. A note that cannot be added to it is kept by the copy that made it, and a reading is the two together, so that noting still never throws and no note is lost to the copy that made it.
- **One file of the pure packages names the global object.** [ADR-0001](0001-tooling.md) keeps `globalThis` out of the pure packages, as a way to reach the clock or the environment under another name. `packages/schema/src/process-count.ts` names it, to read and write the one property that holds the count. The lint configuration makes that exception by file name, every other rule binds the file as before, and `scripts/check-guards.ts` fails if the file names the global object more than once or for anything else. A count kept in each copy was the alternative: it needs no exception, and it fails open, silently, in any program that installs two versions of these packages.
- Nothing that arrives from outside moves the count. Each package has a property test that gives its judges arbitrary data and requires the count to stay where it was.
- An engine that words a spent stack in another way is not recognised. A verifier there behaves as it did before this record: it answers, and a book may keep a refusal until the log changes.
- An engine compiles a function when it is first called, which takes room on the stack too. The functions that are called from a `catch` are called once when `@oip/schema` loads, so that they are ready. A function that cannot be entered at all throws to its caller: nothing can answer from there.

## How it is tested

- In the test runner, by noting a failure from inside the work, as the places that turn one into an answer do: for each judge, a refusal with `implementation limit`, nothing kept, and the right answer when asked again.
- With the stack really spent, in a Node.js process of its own for each script (`*.node.ts`): the runner reads a module's exports through getters that fail there. Those lines are outside the coverage report and outside mutation testing. The helper that spends the stack has a test of its own, which shows that it reports a function that throws after it has answered.
- A look refused for want of room is made again with room at the same reading, two hundred times with the stack really spent: the removal that waited on the logs followed is recorded at that reading every time.
- Where what is called takes bytes or text, which cannot be made to throw, a spy stands in for the call that found no room: the engine's JSON parser for a selector, and its decoder for bytes read as text.
- The first signature a process checks is asked for at each of thirty-one depths near the end of the stack, each in a process of its own, once with its key already checked and once not: it is never called invalid without that being noted. The script says which of the two it ran, and the test checks it. The library's own calls cannot be replaced, so this is the test of the `catch` we do not own and of the check of a point's order.
- The same is asked of a process that has verified often, whose frames are of other sizes, at sixty depths, each below sixteen offsets of a part of a frame. This is the test that fails when the steps are taken again from no deeper than the library took them.
- What the engine throws for a regular expression at the end of the stack is asked of the engine: one made there, and one made beforehand and first used there. Every error it throws is counted, and the test names the three messages, so that an engine with new words for one fails it.
- A second copy of the module is loaded in the runner: a note made through either is seen through the other, and each knows the other's `UnfitProcess`. A process whose global object takes no new property is asked in a process of its own.
- Faults are planted one at a time: every note, every refusal, every comparison of the count, each part of the rule that tells a spent stack, and each part of the steps taken again. [The review record](../../reviews/build/M2-identity.md) says how many, which of them the tests do not find, and why each of those changes no answer that can be reached.
