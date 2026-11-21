---
"@oip/identity": minor
---

`deactivated`, in the metadata of a DID document, is of the mind as its log stands (Layer 1, 5.2; OEP-0006, item 7). The document of an earlier version of a mind that has since retired says `deactivated: true`. It said `false`, so a verifier that followed the key reference of a proof was not told that the mind had retired.
