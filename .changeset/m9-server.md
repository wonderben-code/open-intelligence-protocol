---
"@oip/server": minor
---

`GuardedFetcher.post` takes further request headers, for a protocol that has its own (`a2a-version`, say). A header that is the fetcher's own, or that says where a request goes or how it is framed, is refused before anything is sent, and so is a value that is not printable ASCII.

`GuardedFetcher.fetch` asks as `fetch` asks, under the guard: a request of any of GET, POST, PUT and DELETE, with no redirect followed. A gateway gives it to the minds it makes, which send answers and read feeds at URLs that strangers chose.
