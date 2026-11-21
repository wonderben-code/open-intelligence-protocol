# Changesets

Every pull request that changes a package adds a changeset: a short Markdown file here that names the packages it changes, the kind of version bump, and what changed, in words a user of the package would understand.

```
pnpm changeset
```

At release time the changesets become each package's version and changelog. Until the first publication (gate G1 in [BUILD.md](../BUILD.md)), nothing is published and the packages stay at `0.0.0`.
