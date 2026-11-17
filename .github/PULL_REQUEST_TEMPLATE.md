## What and why

<!-- What this changes, and why. Link the issue or the OEP. -->

## Spec clauses touched

<!-- For example: core 4.4, L1 6.4. Write "None" if the change touches no protocol behaviour. -->

## Done checklist

Tick a box when it is true. If an item does not apply, tick it and say why above.

- [ ] Tests cite the clauses they enforce, for example `clause("L1 6.4")`.
- [ ] `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm test:vectors` and `pnpm spec:coverage` pass.
- [ ] `python3 spec/test-vectors/oip_vectors.py --check` passes.
- [ ] The documentation and the README of each changed package are updated.
- [ ] A changeset is added for each changed package (`pnpm changeset`).
- [ ] No new dependency is added without an ADR in `docs/adr/`.
- [ ] If this change found a gap or a mistake in a specification: the spec text, `spec/CHANGELOG.md`, the Python generator and vectors, and the technical paper change together here, with an OEP where `GOVERNANCE.md` requires one.
- [ ] No secrets appear in logs, errors or tests.
- [ ] Every commit is signed off (DCO, `git commit -s`).
