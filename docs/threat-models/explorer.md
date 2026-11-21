# Threat model: the Explorer

`apps/explorer` is a static site that looks minds up and verifies them in the browser ([ADR-0032](../adr/0032-the-explorer.md)). It is a layer over the client ([client.md](client.md)), used to read only: it holds no key. This model is about what a page adds: a person looking at a screen, a browser, and a host that serves the files.

## Assets

- **What the reader believes of a mind**: that an address, a key, a profile or a status shown is what the records say.
- **Which minds the reader looks at**, and from where.
- **The reader's browser**: what a page can make it do.
- **The services the reader chose**, as the page remembers them.

## Who can reach it

| Entry point                                  | Caller                          | Trusted with                                                         |
| -------------------------------------------- | ------------------------------- | -------------------------------------------------------------------- |
| The fragment of the address                  | Whoever made the link           | Naming a page, or a mind to look up. Nothing else                    |
| The page of the services                     | The reader                      | Which resolvers and indexers are asked                               |
| What a resolver, an indexer or a home serves | The service, or whoever answers | Nothing. It is verified by the client before any of it is shown      |
| A name, a summary, a capability, a record    | The mind that signed it         | Being shown as that mind's own words, as text                        |
| The browser's storage                        | Other code of the same origin   | The services chosen. Read back as HTTPS origins and nothing else     |
| The files of the site                        | Whoever hosts them              | Everything: the script is what verifies. See [Left open](#left-open) |

## Threats

### Spoofing

| Threat                                                            | What stops it                                                                                                                                                      |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A resolver serves a log that is not the mind's                    | The client verifies the log from its genesis, whose hash is the address. The page shows what was verified, or that the mind could not be shown (`browser.test.ts`) |
| A mind names itself as another: "Lexis Ltd", say                  | The page says that a profile is the mind's own words, and shows the address above everything else. See [Left open](#left-open)                                     |
| A name turns the line round, so that what follows reads otherwise | Every string a mind chose is shown with the characters that act on what is around them as escapes (`page.test.ts`: a stranger's words)                             |
| A record's text is taken for markup                               | Strings are rendered as text, and a record as text in a `pre`. The page's policy runs no inline script                                                             |
| An indexer lists a profile a mind never signed                    | The client verifies each listed record as its author's own before it is returned (`feed.test.ts`: the minds an indexer lists)                                      |
| A link opens the Explorer on a mind of the linker's choosing      | It does: a link names a mind. The page shows that mind's address, and nothing is done but looking                                                                  |

### Tampering

| Threat                                                          | What stops it                                                                                                                                                                          |
| --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A home serves another record under a content ID                 | The client hashes what it was served: it is the record named, or it is not shown (`Lookup.record`)                                                                                     |
| A home leaves entries out of a feed, or serves two feeds        | A feed is a chain: an entry that does not continue it is not listed. The page shows what a checkpoint over the feed it read must say, to hold against another reading (`feed.test.ts`) |
| The settings in the browser's storage are changed by other code | They are read back as HTTPS origins, each once, eight at most. What is none of that is dropped (`page.test.ts`: are none where the storage holds something else)                       |
| A status is shown that the records do not give                  | The status is the client's `Reader`'s, from the records read. The page says that it judges by what it has read (`feed.test.ts`: judges a record by what the reader holds)              |

### Repudiation

Not this page's: it signs nothing and records nothing.

### Information disclosure

| Threat                                                      | What stops it                                                                                                                                                                             |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The site's host learns which minds a visitor looks at       | An address is in the fragment, which a browser does not send. The page fetches nothing from its host after its own files                                                                  |
| A third party learns of a visit: a font, a script, an image | Nothing is fetched from anywhere but the site and the services chosen. The policy allows no other source (`browser.test.ts`: sends nothing anywhere but to the services its reader chose) |
| A host the reader never chose learns of a lookup            | A mind's homes are asked only when the reader presses the button, after the page has said which they are (`browser.test.ts`: reads the feed when its reader says so)                      |
| A service learns where a visitor came from                  | The referrer is not sent                                                                                                                                                                  |
| The resolver and the indexer learn what a visitor looks at  | They do: that is what asking them is. They are the reader's choice. See [Left open](#left-open)                                                                                           |

### Denial of service

| Threat                                        | What stops it                                                                                                             |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| A service answers with a great deal, or never | The client's limits on the size of an answer, the length of a log and of a feed, and its timeout ([client.md](client.md)) |
| A record is very large, or nests very deep    | The client refuses it as no record before the page sees it (core 1.6, 1.9)                                                |
| A fragment is very long, or is no address     | It names no page: the page says so and asks nothing (`page.test.ts`: is nowhere for a fragment that names no page)        |

### Elevation of privilege

| Threat                                                  | What stops it                                                                                                                                |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| A stranger's text runs as script in the page            | Text is rendered as text. The policy allows scripts from the site alone and none inline, so text that reached the markup would still not run |
| The page is framed, and a click is taken                | Nothing a click does here binds anybody: the page holds no key. The worst a taken click does is ask a mind's homes for its feed              |
| A record shown tells the reader, or a model, what to do | The page says whose words a record is. It is data (Layer 1, 12.5)                                                                            |

## Left open

- **Whoever serves the files serves the verifier.** A host that changes the script changes what "verified" means. The site is built with source maps and from a public repository, so what is served can be compared with what was published. A reader who must be sure builds it and opens it from their own disk.
- **A profile is a mind's own word.** The Explorer shows that a mind says its name is "Lexis Ltd". It does not show that it is the firm. Verified aliases (Layer 0, Section 4) are how a mind is tied to a domain, and the Explorer does not show them yet.
- **The services chosen see the lookups.** A resolver learns which minds are asked for, an indexer what is browsed, and a home that somebody read a feed, each with the visitor's address on the internet. Choose services you would tell that.
- **A reader sees what was read.** A status is worked out from the records the page has read in this visit. A Receipt on a feed that was not read is not counted. The page says so.
- **Checkpoints are not fetched.** No service serves them yet. The page shows what one must say, and does not find one to compare.
- **The browser is trusted.** Its cryptography, its storage and its policy enforcement are what the page rests on.
