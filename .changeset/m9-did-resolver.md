---
"@oip/did-resolver": minor
---

Resolves `did:oip` for the tools of the DID ecosystem (Layer 1, Section 5).

- `getResolver` is a driver for the DIF `did-resolver` library. It has no dependency on the library.
- `resolveDid` gives the result of a resolution, with `versionId` for the document of an earlier version.
- `handle`, and the program `oip-did-resolver`, are the HTTP interface of a driver for the DIF Universal Resolver.
