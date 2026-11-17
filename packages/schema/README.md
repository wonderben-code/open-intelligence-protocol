# @oip/schema

JSON Schemas, TypeScript types and compiled validators for every record of the [Open Intelligence Protocol](../../README.md).

It answers one question: **is this value a well-formed record?** That is the first step of "validate, verify, then use". It checks no signature, no identity log and no time. A validated record is not yet a verified one.

- A schema for every record type in [core Section 11](../../spec/core.md#11-record-types): 29 record types, plus `Proof` and `Policy`.
- The same schemas as JSON Schema 2020-12 documents in [`spec/schemas/`](../../spec/schemas/), for implementations in any language.
- Validators compiled ahead of time. The package builds no code at run time, so it works under a strict Content Security Policy and in edge runtimes.
- Pure: no I/O, no clock, one dependency (`typebox`). It runs in Node.js, browsers, Deno and Bun.

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

Every issue names the clause of the specification that the value breaks.

## What it exports

| Export                                                                                                           | What it is                                                                                  |
| ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `validateRecord(value)`                                                                                          | Validates any record, choosing the schema by its `type`                                     |
| `validateRecordOfType(type, value)`                                                                              | Validates a record whose type you already know                                              |
| `validateProof(value)`                                                                                           | Validates one proof against core 5.2                                                        |
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

| Rule                                                                    | Clause   |
| ----------------------------------------------------------------------- | -------- |
| Thresholds are majorities: `2 × threshold > n`                          | L1 3.4   |
| A key is in at most one of `keys` and `invocation`, and once in its set | L1 3.5   |
| A delegation's delegate differs from its author                         | L1 11.1  |
| Policy statements nest at most 8 deep; selectors follow the grammar     | L1 11.3  |
| Session participants are sorted by code point                           | L1 14.1  |
| Capability ids are unique within a profile                              | L1 16.2  |
| Each mind is a party once; payer and payee are two different parties    | L2 5.1   |
| Every critical namespace has an extension block                         | core 8.3 |
| Both keys of a control-key-ref are identical                            | core 6.2 |

**Limits on every value**, whatever the record type: every number is a safe integer (core 1.2), and arrays and objects nest at most 64 deep. The second is a limit of this implementation; the specification sets none yet.

## Three things to know

1. **Unknown members are allowed.** A reader preserves and ignores members it does not recognise (core 1.7), so the record schemas are open. Proofs, controllers and key entries are closed.
2. **A malformed proof does not make its record malformed.** A record's `proof` members are objects at this level. Each proof is validated on its own, with `validateProof`, when it is verified: a proof that fails never counts, but nobody can invalidate a record by adding a bad proof to it (core 5.5).
3. **The types describe validated records.** `Genesis` is the type of a value that passed `validateRecord`. Its `proof` is an array of objects, not of `Proof`, for the reason above.

## Changing a schema

The schemas are TypeBox definitions in `src/`. After changing one, run:

```
pnpm schemas
```

This regenerates `spec/schemas/*.json` and `src/generated/validators.ts`. CI fails if they are out of date (`pnpm generated:check`). A change to a record format is a change to the protocol and needs an OEP ([GOVERNANCE.md](../../GOVERNANCE.md)).
