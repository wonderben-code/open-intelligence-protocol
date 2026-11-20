---
"@oip/server": minor
---

`GuardedFetcher.post` takes further request headers, for a protocol that has its own (`a2a-version`, say). A header that is the fetcher's own, or that says where a request goes or how it is framed, is refused before anything is sent, and so is a value that is not printable ASCII.
