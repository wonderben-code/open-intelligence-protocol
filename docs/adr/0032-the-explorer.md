# ADR-0032: The Explorer

**Status:** Accepted, 21 November 2026 (M11).

## Context

M11 is the OIP Explorer ([BUILD.md](../../BUILD.md), M11): a static web app in which anyone looks up a mind and sees its identity log, its keys, its DID document, its location, its profile, its feed and its records of the Mind Web with their status, with every signature verified in the browser and each verdict traced to the clauses behind it. BUILD.md names Vite and React, and asks that no data leave the browser except requests to the resolvers and indexers the user chose.

The Explorer is the first thing in the repository that a person uses without installing anything, and the first that shows a stranger's words in a page.

## Decision

1. **The page verifies with the client a mind uses.** `Lookup` and `Reader` of `@oip/client`, bundled for the browser. Nothing is verified by code of the Explorer's own: its modules under `src/oip/` lay out what the client found and decide nothing. A second verifier in the page would be a second place for the rules to be wrong.

2. **No key, and no record kept.** The Explorer reads. `Reader` judges whether a record counts and how it stands without a key ([M10](../../PROGRESS.md) added it for this). The page keeps nothing of what was looked at: the only thing it stores is which services its reader chose.

3. **The services are the reader's choice, and nothing is chosen for them.** The site ships with no resolver and no indexer. A reader names them on the page of the services, as HTTPS origins, and they are kept in the browser's own storage. A site that came with a default would send every visitor's first lookup to whoever the site's publisher picked.

4. **A mind's homes are asked only on a click.** A feed is served by the mind's homes (Layer 1, 13.1), which its verified log names, and not by a resolver. So the feed cannot be shown without asking a host the reader did not choose. BUILD.md's rule is kept in its intent: the page shows which homes the log names, says that reading the feed tells them somebody looked, and asks them when the reader presses the button. A test holds the page to it with the list of every origin it asked.

5. **A stranger's words are text.** React renders strings as text. That leaves the characters that act on what is around them: controls, and those that turn the direction of a line. Every string a mind chose is shown with those written as escapes (`src/oip/text.ts`), in a name as in a record.

6. **The page's own policy.** A `Content-Security-Policy` in the document: scripts and styles from the site alone, no inline script, requests over HTTPS, no frames, no forms that post. No font, script, style or image is fetched from anywhere else, and the site's mark is in the page. The referrer is not sent.

7. **Addresses are in the fragment.** `#/mind/<address>`. A fragment is not sent to the server, so whoever hosts the static files does not learn which minds a visitor looks at. It also lets the site be served from any path with no rewriting.

8. **Why, from the specification itself.** Each thing a page shows has a reason: what was checked, and the clauses that ask for it (`src/oip/why.ts`). The clauses come from `spec/clauses.json`, which is made from the specifications, and each links to its section. A test fails if a reason names a clause or a heading the specifications do not have. A failure shows the clause the client gave with it.

9. **Checkpoints: what one must say.** No service serves a mind's checkpoints yet, and Layer 1, 13.1 names no place for them. The Explorer shows what any checkpoint over the feed it read must say: the size, the last entry and the Merkle root (10.5), worked out in the page. A place to fetch checkpoints from is noted for an OEP.

10. **React, and nothing else at run time.** `react` and `react-dom`, pinned exactly. No router: three pages and a fragment. No state library: the state is a route, the settings, and what one request returned. No component or style library: one stylesheet, the system's fonts, light and dark by the reader's setting. No Vite plugin: Vite reads the JSX settings from the tsconfig.

11. **Lighthouse is a development dependency.** BUILD.md asks for its scores, so it is the tool that gives them. It is pinned, runs in the CI job that has a browser, and is in nothing that is shipped. It brings some ninety packages of its own into the lockfile, all under the supply-chain policy of [ADR-0001](0001-tooling.md).

12. **The tests walk the site as it is shipped.** The site is built with Vite as for a release and loaded in Chromium. The demo of M10 is played on a network on the machine, and the page's requests are carried to it. The walk ends by reading the list of origins the page asked. Lighthouse loads the pages a reader meets before choosing a service.

13. **A person sees the demo network the same way.** The services of `oip demo` have HTTPS origins that are names, with no certificate behind them: the `oip` command carries a request for one to a port of the machine ([ADR-0026](0026-the-command.md)). A browser cannot be told that, and the Explorer asks nothing over plain HTTP. So `pnpm explorer:demo` opens a window of Chromium in which the page's requests for those origins are carried as the tests carry them, with the network's resolver and indexer chosen. The site in the window is the site as shipped: nothing in it knows of the demo. The alternative was a way for the page to ask a service on the machine over plain HTTP, which would be a rule of the page's that a record could try to use.

## Consequences

- Anyone can check a mind with a browser and a resolver's address, and see why each thing is so.
- A reader must name a resolver before anything is shown. The demo's documentation says which.
- The script is about 180 KiB compressed, most of it the client and its cryptography. It is one file. Lighthouse scores the start page at 99 to 100 for performance with it.
- Reading a feed tells the mind's homes that somebody looked, and from which address on the internet. The page says so before it asks.
- The Explorer shows a mind's own words. It says whose they are. It cannot say whether they are true.

## Alternatives

- **A verifier written for the page.** Smaller, and a second implementation of rules that took nine milestones to get right.
- **A default resolver.** Friendlier on the first visit. It would make the site's publisher a party to every lookup, which BUILD.md's last criterion is there to prevent.
- **Reading the feed at once.** One click fewer. The reader would have contacted a host they never chose, on the word of a record.
- **Addresses in the path.** Cleaner to read. It needs the server to rewrite paths, and tells the server every address.
- **Without React.** Three pages can be written without it. BUILD.md names it, the pages have enough state that changes for it to earn its place, and its text rendering is the first defence of decision 5.
