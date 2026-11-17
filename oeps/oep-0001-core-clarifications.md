---
oep: 1
title: Core clarifications found while building the reference implementation
authors:
  - Claude Code, building the reference implementation for Ekram Alam (@wonderben-code)
status: Review # Draft | Review | Accepted | Rejected | Withdrawn | Final
type: Core # Core | Layer 0 | Layer 1 | Layer 2 | Process
created: 2026-11-17
requires: []
replaces: []
discussion: # the pull request of milestone M1
revision: # the specification revision that adopted the change; empty until Final
---

# OEP-0001: Core clarifications found while building the reference implementation

## Summary

Writing `@oip/core`, the first package of the reference implementation that parses, hashes and verifies records, and the two independent reviews of it, showed thirteen places where OIP Core (revision 2026-11-17) allows two readings or sets no rule. This proposal settles each one. Most choose the reading that both existing implementations already follow or that the text already implies. Two are new limits: 64 on how deeply a record may nest, and 64 characters on a duration. No address, content ID or proof in the test vectors changes. It concerns anyone writing a parser or a verifier for OIP records.

## Motivation

Two conforming implementations must give the same verdict on every record. Each item below is a case where they might not.

1. **No limit on nesting.** core 1.6 bounds a record's size and says nothing of its depth. A record of 1 MiB can nest 500,000 arrays. One implementation overflows its stack and rejects, another accepts, and a recursive verifier can be crashed by a record that is otherwise valid.
2. **Does the size limit count proofs?** `proof` is outside every signature, so anyone relaying a record can add to it. If the limit did not cover proofs, a record could grow without bound in transit.
3. **What is a `proof` entry that is not an object?** core 5.1 says "an array of proof objects"; core 5.5 says an invalid proof does not invalidate a record. An entry such as `42` could be read either way.
4. **Is year `0000` a year?** RFC 3339 allows it. The Python checker rejected it, because its date library starts at year 1; the JSON Schemas accepted it.
5. **Is `"-0"` a decimal between 0 and 1?** The pattern of core 1.3 matches it, and decimals compare numerically.
6. **Must a key hash have the canonical form of a content ID?** core 3.4 gives the formula and not the form. A pre-rotation commitment in another spelling would never match a revealed key, so the question is only whether the record is malformed.
7. **A `seq` of any length.** The grammar of core 6.1 allows any run of digits in a `version-id`, and a position is an integer of a record, which core 1.2 bounds.
8. **Record types that extensions define.** core 7 says a `type` is "defined by this specification or by a critical extension", and does not say what a record of such a type must contain or what a reader does with it.
9. **Names in `ext`, and repeats in `critical`.** core 8.1 lists what a namespace is and does not say that another name is an error. core 8.3 does not say whether `critical` may name a namespace twice.
10. **An empty `kind`.** Layer 1, 3.6 allows "another string of at most 64 characters". Both implementations reject the empty string.
11. **Noncharacters.** core 1.1 says a record is an I-JSON message and names two of its rules: no duplicate member names and no unpaired surrogates. RFC 7493, Section 2.1 has a third: no noncharacters. A reader cannot tell whether the third was left out on purpose.
12. **A container and the limits.** core 1.6 says the size limit "applies to each record they contain, not to the container". Read literally, a container's own members are unbounded. The first draft of core 1.9 (item 1) gave containers no such rule for depth, so a record nesting 64 deep, valid alone, could not be carried in a `LogPage`, which adds two levels. Anyone can bring an event to that depth by adding an entry to its `proof`, which never counts (core 5.5) and which nobody signs: one such entry would stop the log from being served. The first independent review of `@oip/core` found this.
13. **A duration of any length.** The pattern of core 1.5 allows any run of digits, so a duration of a million digits is valid, and an implementation that computes with it does a million-digit multiplication for each one. Decimals already have a limit of 64 characters (core 1.3).

The extension mechanism (core 8) does not help: these are rules about what a record is, which every reader must share before it can read an extension at all.

## Specification

Written against revision 2026-11-17.

**core 1.1**, the rule for strings. Current: "every string MUST be valid Unicode (no unpaired surrogates)." Proposed:

> every string, member names included, MUST be valid Unicode with no noncharacter in it: no unpaired surrogate, no code point from U+FDD0 to U+FDEF, and no code point whose last sixteen bits are FFFE or FFFF (RFC 7493, Section 2.1).

**core 1.3**, add at the end:

> `"-0"`, with or without a fraction of zeros, is a decimal equal to `"0"`; it is not an amount, because an amount has no sign.

**core 1.4**, add before the last sentence:

> Years run from `0000` to `9999` of the proleptic Gregorian calendar, as in RFC 3339; year `0000` is a leap year.

**core 1.5**, add at the end:

> A duration string MUST NOT exceed 64 characters.

**core 1.6**, first sentence. Current: "The canonical form (Section 2) of a record MUST NOT exceed 1 MiB." Proposed:

> The canonical form (Section 2) of a record, with its `proof` member, MUST NOT exceed 1 MiB.

**core 1.6**, the sentence on containers. Current: "the limit applies to each record they contain, not to the container." Proposed:

> the limit applies to each record they contain, and to the container without those records. It does not apply to the two together.

**core 1.9**, new, after 1.8:

> **Depth.** The arrays and objects of a record MUST NOT nest more than 64 deep: the record itself is at depth 1, and a value that is neither an array nor an object adds no depth. A record that nests more deeply MUST be rejected. For a container (1.6), the limit applies to each record it contains, counted from that record, and to the container without those records, so that a container can carry any record that is valid alone. The rules of this section apply to the whole record, including every entry of `proof`.

**core 3.4**, add at the end:

> A key hash has the form of a content ID and MUST match the pattern of 3.2.

**core 5.1**, add after the first sentence:

> Every entry MUST be a JSON object. An entry that is an object but is not a valid proof does not count (5.5) and does not make the record malformed.

**core 6.1**, add after the grammar:

> `seq` is the position of an identity event in its log, which is an integer of a record (1.2): a `seq` greater than 2⁵³−1 names no event.

**core 7**, the row for `type`. Current: "REQUIRED in every record. A record type defined by this specification or by a critical extension." Proposed:

> REQUIRED in every record. A record type defined by this specification or by a critical extension: a record whose `type` this specification does not define MUST list in `critical` the namespace of the extension that defines it, and a reader that does not understand that extension treats the record as Section 8.3 says.

**core 8.1**, add after the list:

> A record whose `ext` has a member with any other name is malformed.

**core 8.3**, add after the first sentence:

> Naming a namespace more than once has the effect of naming it once.

**Layer 1, 3.6**, the row for `kind`: "another string" becomes "another non-empty string".

**core 12**, the first of the three essential rules gains a clause:

> and the limits on size and depth (1.6, 1.9) are applied to each record a container carries and never to the container as a whole, so an attacker cannot stop a log or a feed from being served by adding one;

**Layer 1, 19**: the row for record size names the rule for containers; new rows "Nesting of arrays and objects in a record | 64; for a container, each record it carries and the container without them (core 1.9)" and "Decimal string, and duration string | 64 characters each (core 1.3, 1.5)".

New names: none. New limits: 64, the depth of a record; 64 characters, the length of a duration.

**Test vectors.** A new kind of case, `json`, whose `text` member is a JSON text: it is within the profile of core Section 1 (must-accept) or is not (negative). The text is a string because what it tests does not survive parsing: the spelling of a number, an escape, a depth. Cases of kind `record` may now stand among the must-accept cases and the controls, where the record is well formed. 15 `json` cases and 12 other cases are added, with 11 controls; they are listed under Test vectors below.

## Rationale and alternatives

**Why 64.** The deepest structure the specifications define is a proof whose `authority` carries an inline `Delegation` with a policy nested to the limit of Layer 1, 11.3: about 25 levels. 64 leaves room for extensions and inline content, and is far below what any parser's stack holds. Limits in use elsewhere are of the same order (100 in several JSON libraries, 32 for JSON in some databases).

**Why a container is limited part by part.** A container exists to carry records that are valid alone. If its limits were on the whole, the deepest or largest valid record could not be carried, and since anyone can add an uncounted entry to a record's `proof`, anyone could make a record that way. If the container's own members had no limit, the limit would bound nothing: a `LogPage` could carry a gigabyte in a member no schema names. Limiting each part separately closes both. The whole container then nests at most 67 deep (a pair of events in `DuplicityEvidence` sits three levels down), which a reader can rely on before it has parsed anything.

**Why forbid noncharacters.** core 1.1 already says a record is an I-JSON message, and RFC 7493 forbids them. Unicode reserves these 66 code points for internal use and advises against interchanging them; some systems strip or replace them, which would change a record's bytes and break its proofs. Naming the rule removes the doubt. The alternative, allowing them, would mean that an OIP record is not I-JSON, and the sentence that says it is would have to go.

**Why 64 characters for a duration.** It is the limit decimals already have. The longest duration with a use, a count of seconds over thousands of years, has twelve digits.

**Why count proofs in the size.** A limit that part of the record escapes is not a limit. 256 proofs of ordinary size take about 100 KiB, so honest records are not constrained.

**Why a non-object `proof` entry is malformed.** core 5.1 already says "proof objects". The rule that a bad proof cannot invalidate a record (core 5.5, core 12) is about proofs that do not verify, which a reader can only discover by trying; a number in the array is malformed on its face. Someone who can add `42` to `proof` in transit can also truncate the record, so nothing is gained by tolerating it.

**Why year `0000`.** The text of core 1.4 already admits it: it matches the pattern and names a real date of the calendar RFC 3339 uses. The alternative, excluding it, would add a rule for no benefit.

**Why require `critical` for an unknown type.** A reader that does not know a type cannot know whether the record is signed, what its members mean, or whether acting on it is safe. core 8.3 already says what such a reader does with a critical extension it does not understand: store and forward, never act. Requiring the extension to be listed puts every unknown type under that rule. The alternative, treating any unknown type as malformed, would stop extensions from defining record types at all, which core 7 allows.

**Why allow repeats in `critical`.** A repeat is harmless and a rule against it would be one more way for a record to be malformed.

**Doing nothing** leaves each of these to the implementer, and the test vectors would then define the protocol by accident. **An extension** cannot settle them, as the Motivation says.

## Backwards compatibility

This is a **rule change** in one respect and a clarification in the others.

- Does any record valid today become invalid? Yes, in six narrow cases: a record nested more than 64 deep; a record of a type this specification does not define that lists no critical extension; a record whose `ext` has a member that is not a namespace; a record with a noncharacter in a string; a duration of more than 64 characters; a container whose own members exceed 1 MiB. No record in the test vectors, the papers or the reference implementation is affected. A timestamp in year `0000` becomes valid for implementations that rejected it.
- Does any golden value change? No. `vectors.json` gains 27 cases and 11 controls and loses none; every existing value is byte for byte what it was.
- What does an implementation of the earlier revision do? It may accept a record nested more than 64 deep, or crash on it. It should adopt the limit.
- What must existing minds and services do? Nothing, unless they emit such records. The specification is a Draft and no deployment exists.

## Security and privacy considerations

The depth limit removes a way to crash or stall a verifier with a small record. Counting proofs in the size limit removes a way to inflate a record in transit. Applying both limits to a container part by part removes a way to stop a log or a feed from being served: without it, one entry added to an event's `proof` by anyone at all would make every page that carries the event invalid. The limit on a duration's length removes a way to make a verifier compute with numbers of a million digits. Requiring `critical` for unknown types removes a way to have a reader act on a record whose rules it does not know. Nothing here gives an attacker a new capability, and nothing concerns privacy.

A limit that implementations apply differently is itself a risk: a record one accepts and another rejects can split a network's view. That is the reason to state the number in the specification.

## Test vectors

Added to `vectors.json` with `kind: "json"` and a `text`:

- must accept: `json-integers-however-written`, `json-integer-written-at-length`, `json-escapes-are-spellings`, `json-same-name-in-different-objects`, `json-nested-64-deep`;
- must reject: `json-number-with-fraction`, `json-number-with-negative-exponent`, `json-integer-beyond-safe-range`, `json-exponent-beyond-safe-range`, `json-unpaired-surrogate`, `json-noncharacter`, `json-noncharacter-in-a-member-name`, `json-nested-65-deep`, `json-trailing-comma`, `json-not-a-number`.

Duplicate member names are not among the negative cases, because core 1.1 says receivers SHOULD reject them, not MUST. Both implementations do reject them, and the differential tests compare them on such texts.

Added with `kind: "record"`:

- must accept: `extension-type-with-critical-extension`, `timestamp-in-year-0000`, `receipt-rating-of-minus-zero`, `record-nested-64-deep`, `container-carries-a-record-nested-64-deep`;
- must reject: `proof-entry-not-an-object`, `extension-name-not-a-namespace`, `unknown-type-without-critical-extension`, `record-nested-65-deep`, `container-carries-a-record-nested-65-deep`.

Added with `kind: "countsFor"`, both negative: `signature-r-mixed-order` (core 4.4: an `R` with a small-order component, which the vectors did not cover) and `key-reference-position-wraps-around` (core 6.1: position 2⁶⁴+1 with the content ID of the event at position 1).

Eleven controls are added: one for each new negative case that can have one, and one for each of the two earlier signature cases, `signature-s-not-reduced` and `signature-r-identity`, which had none.

## Reference implementation

- `spec/test-vectors/oip_vectors.py`: `read_json`, `values_ok`, `json_ok`, `_integer` (which reads a number of any length as text), the calendar in `ts`, and the checks in `record_ok`, `profile_ok` and `verify_log`.
- `@oip/core`: `parseJson` (the profile, with the depth limit), `parseRecord`, `checkSize`, `parseVersionId`, `parseDuration`.
- `@oip/schema`: `validateJson`, `MAX_DEPTH`, `MAX_CONTAINER_DEPTH`, `containerParts`, `textFault`, and the rule for extension-defined types in `validateExtensionRecord`.
- `@oip/conformance`: the `json` kind, and differential tests that compare the two parsers under the rule "same".

## Open questions

- **How much may a `Sealed` record exceed the size limit?** core 1.6 says "by its encoding overhead" and gives no number. The reference implementation reads it as two limits: `ciphertext` is at most 1,398,123 characters, which is a packet of 1 MiB with the cipher's 16-byte tag in base64url, and the record without `ciphertext` is at most 1 MiB. To be settled with sealing, in M4.
- **Should receivers be required to reject duplicate member names?** core 1.1 says SHOULD, and explains why a receiver that cannot is still safe. Both implementations reject. A MUST would let the vectors include the case.
- **Is there a limit on the text of a record, as distinct from its canonical form?** White space and escapes are unbounded. The reference implementation reads at most 8 MiB by default.

## Copyright

This document is licensed under the [Creative Commons Attribution 4.0 International Licence](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0).
