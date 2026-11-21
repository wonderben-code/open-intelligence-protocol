# Layering fixtures

These files break the layering rules on purpose. `scripts/check-guards.ts` runs dependency-cruiser on this directory with the repository's own configuration and fails unless every rule named in a file's first line is reported for it. That shows the rules still catch what they are meant to catch.

The files are laid out as `packages/<name>/…`, because the rules match on those paths.
