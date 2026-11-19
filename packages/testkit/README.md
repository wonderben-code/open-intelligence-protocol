# @oip/testkit

Test helpers for the reference implementation. It is private, never published, and used only by tests: a package's source must not import it (a layering rule enforces that).

## Citing the specification

Every requirement has a test that cites its clause. Put `clause()` in the test's name:

```ts
import { clause } from "@oip/testkit";
import { expect, it } from "vitest";

it(`${clause("L1 11.1")} rejects a delegation to its own author`, () => {
  // …
});
```

- `clause()` throws on an ID that is not a clause of the specification, so a typing mistake or a renumbered clause fails the run.
- `pnpm spec:coverage` reads the citations out of the names of the tests that pass and writes [docs/conformance/coverage.md](../../docs/conformance/coverage.md).
- A clause ID is a document and a number: `core 4.4`, `L0 2.2`, `L1 6.4`, `L2 8.3`. A section with no numbered paragraphs is cited by its number alone: `core 11`, `L1 19`. The full list is [spec/clauses.json](../../spec/clauses.json), which `pnpm spec:clauses` extracts from `spec/*.md`.

## Reading the vectors

`readVectors()` returns `spec/test-vectors/vectors.json`, and `positiveVectorRecords()` every record in its positive part. Packages below `@oip/conformance` use these for samples. The typed loader and the runners are in [`@oip/conformance`](../conformance).
