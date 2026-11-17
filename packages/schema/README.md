# @oip/schema

JSON Schemas, TypeScript types and compiled validators for every record of the [Open Intelligence Protocol](../../README.md).

It answers one question: **is this value a well-formed record?** That is the first step of "validate, verify, then use". It checks no signature, no identity log and no time. A validated record is not yet a verified one.

- A schema for every record type in [core Section 11](../../spec/core.md#11-record-types): 29 record types, plus `Proof`, `Policy` and `ExtensionRecord` (the common members of a record whose type an extension defines).
- The same schemas as JSON Schema 2020-12 documents in [`spec/schemas/`](../../spec/schemas/README.md), for implementations in any language.
- Validators compiled ahead of time. The package builds no code at run time, so it works under a strict Content Security Policy and in edge runtimes.
- Pure: no I/O, no clock, one dependency (`typebox`). It uses no Node.js API, so that it can run in browsers, Deno and Bun as well. CI tests it on Node.js today; the other runtimes join the CI matrix with the client (M6).

## Use

```ts
import { validateRecord } from "@oip/schema";

/** Says whether a JSON text is a well-formed OIP record and, if it is not, why. */
export function describeRecord(json: string): string {
  const result = validateRecord(JSON.parse(json));
  if (result.ok) {
    // `result.value` is typed: narrowing on `type` gives the record's own members.
    const record = result.value;
    return record.type === "Intent"
      ? `a well-formed Intent: ${record.want}`
      : `a well-formed ${record.type}`;
  }
  return result.issues.map((issue) => `${issue.clause} ${issue.path}: ${issue.message}`).join("\n");
}
```

This is [`examples/validate.ts`](examples/validate.ts); a test runs it and checks that this page shows it unchanged. For a delegation whose delegate is its own author, it returns:

```
L1 11.1 /delegate: a delegation's delegate must differ from its author
```

Every issue names a clause of the specification: the one that defines the syntax of the value at fault or the rule it breaks, and otherwise the one that defines the record type.

## What it exports

| Export                                                                                                           | What it is                                                                                  |
| ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `validateRecord(value)`                                                                                          | Validates any record this revision defines, choosing the schema by its `type`               |
| `validateRecordOfType(type, value)`                                                                              | Validates a record whose type you already know                                              |
| `validateProof(value)`                                                                                           | Validates one proof against core 5.2                                                        |
| `validateExtensionRecord(value)`                                                                                 | Validates the common members of a record whose type an extension defines (core 7)           |
| `Genesis`, `Delegation`, `Commitment`, …                                                                         | The TypeScript type of each record type                                                     |
| `OipRecord`, `RecordOf<"Offer">`, `RecordType`                                                                   | The union of all records, one by name, and the names                                        |
| `jsonSchemas`                                                                                                    | Every schema as a JSON Schema document, by name                                             |
| `patterns`                                                                                                       | The value syntaxes (content IDs, addresses, timestamps, decimals, …) as regular expressions |
| `parseSelector(selector)`                                                                                        | The selector grammar of the policy language (Layer 1, 11.3)                                 |
| `RECORD_TYPES`, `SIGNED_RECORD_TYPES`, `UNSIGNED_RECORD_TYPES`, `CONTAINER_RECORD_TYPES`, `IDENTITY_EVENT_TYPES` | The record types, grouped as core Section 11 groups them                                    |

The API report is [`etc/schema.api.md`](etc/schema.api.md).

## What validation covers

**The schema** of the record's type: required members, the type and syntax of each, lengths and counts, and the conditions JSON Schema can state (for example, `prev` is required when `seq` is greater than 0).

**Rules JSON Schema cannot state**, checked in code:

| Rule                                                                      | Clause   |
| ------------------------------------------------------------------------- | -------- |
| Thresholds are majorities: `2 × threshold > n`                            | L1 3.4   |
| After the genesis, a mind is not one of its own members                   | L1 3.4   |
| A key is in at most one of `keys` and `invocation`, and once in its set   | L1 3.5   |
| An event does not list a key it revokes in its own `keys` or `invocation` | L1 4.5   |
| A delegation's delegate differs from its author                           | L1 11.1  |
| Policy statements nest at most 8 deep; selectors follow the grammar       | L1 11.3  |
| Session participants are sorted by code point                             | L1 14.1  |
| Capability ids are unique within a profile                                | L1 16.2  |
| Each mind is a party once; payer and payee are two different parties      | L2 5.1   |
| Every critical namespace has an extension block                           | core 8.3 |
| Both keys of a control-key-ref are identical                              | core 6.2 |

**Limits on every value**, whatever the record type: every string and member name is valid Unicode (core 1.1), every number is a safe integer (core 1.2), and arrays and objects nest at most 64 deep. The last is a limit of this implementation; the specification sets none yet.

**Not covered here**, because it needs more than the parsed record in front of it:

| Check                                                                                                                                              | Where                                    |
| -------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| Duplicate member names, and the 1 MiB limit on the canonical form (core 1.1, 1.6)                                                                  | `@oip/core`, which parses the bytes (M1) |
| A Multikey decodes to the right prefix and length, and an Ed25519 key has order L (core 4.2, 4.4). The patterns here are necessary, not sufficient | `@oip/core` (M1)                         |
| A genesis's members do not include the mind itself, which needs its content ID (L1 3.4)                                                            | `@oip/identity` (M2)                     |
| A packet's `expires` is at most 7 days after `created`, or one hour for a query (L1 12.1)                                                          | `@oip/net` (M4)                          |

## Five things to know

1. **Unknown members are allowed.** A reader preserves and ignores members it does not recognise (core 1.7), so the record schemas are open. Proofs, controllers and key entries are closed.
2. **A proof that does not count does not make its record malformed.** A record's `proof` is an array of objects at this level. Each proof is validated on its own, with `validateProof`, when it is verified: a proof with the wrong members, the wrong purpose or a bad signature never counts, and the record stays valid (core 5.5). The limits on every value still apply to the whole record, proofs included: an entry of `proof` that is not an object, or that holds a fraction or nests too deeply, makes the record malformed. Whether those limits should apply to each proof separately is an open question for the specification ([PROGRESS.md](../../PROGRESS.md), specification feedback queue).
3. **A proof whose `authority` does not hold up is still a proof.** `validateProof` checks that `authority` has 1 to 8 entries, each a string or an object. What they refer to or contain is judged when the chain or charter is evaluated, because such a proof still counts for its signer's own mind (Layer 2, 7.1).
4. **The types describe validated records.** `Genesis` is the type of a value that passed `validateRecord`. Its `proof` is an array of objects, not of `Proof`, for the reason in item 2.
5. **Where the specification gives no limit, validation adds none.** An empty string, a negative `seq` in a location record and a hundred and one query results are all well formed. Another implementation that follows the text must not be rejected.

## Changing a schema

The schemas are TypeBox definitions in `src/`. After changing one, run:

```
pnpm schemas
```

This regenerates `spec/schemas/*.json` and `src/generated/validators.ts`. CI fails if they are out of date (`pnpm generated:check`). A change to a record format is a change to the protocol and needs an OEP ([GOVERNANCE.md](../../GOVERNANCE.md)).
