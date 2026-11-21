# OIP Explorer

A static site that looks up a mind and verifies it in the browser.

Give it the address of a mind, and it shows the mind's identity log, its keys, its DID document, where it is reached, what it says of itself, its feed, and its records of the Mind Web with how each stands. Every signature is verified in the page, by the client a mind uses (`@oip/client`). Beside each thing shown is a **Why**: what was checked, and the clauses of the specification that ask for it.

It holds no key and signs nothing. It keeps nothing of what was looked at.

## See it on the demo network

From a clean checkout, with Node.js 24 and Google Chrome:

```sh
pnpm install
pnpm explorer:demo
```

This starts a resolver, a host and an indexer on this machine, plays the [translation demo](../../examples/translation-demo/README.md) on them, and opens the Explorer in a window with that network's services chosen. Press **List the minds the indexers know**, and follow one. The program prints the addresses of the cast. It ends when the window is closed.

To look at a network that runs already:

```sh
oip demo                                   # in one terminal: a network, until it is stopped
pnpm demo --network ~/.oip-demo            # in another: play the scenario on it
pnpm explorer:demo --network ~/.oip-demo   # and look at what the minds published
```

To use another browser, set `OIP_CHROMIUM` to the path of a Chromium or a Chrome.

The window is needed because the services of `oip demo` have HTTPS origins that are only names (`https://resolver.oip.localhost`), which the `oip` command carries to ports of this machine. The program gives the page the same carrying. The site in the window is the site as it is shipped.

## Use it with real services

```sh
pnpm --filter @oip/explorer build     # the site, in apps/explorer/dist
pnpm --filter @oip/explorer preview   # serve it from this machine, to look
```

The site is a page, a script and a stylesheet. Serve the directory from any static host, at any path.

It comes with no services. Open **Services** and name the resolvers and indexers to ask, as HTTPS origins. They are kept in the browser's own storage, and nowhere else. Then enter an address on the start page.

A service must let a browser ask it from another origin (CORS). The resolver, the host and the indexer of this repository do.

## What a page shows

| Page                       | What is on it                                                                                                                                                                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Start                      | A field for an address, and the minds the chosen indexers know of, which can be narrowed by tags                                                                                                                                                                   |
| A mind, `#/mind/<address>` | How many events and signatures were checked. The identity log, event by event. Each key with the stretch of the log in which it is the mind's. The profile and the location, if the mind's current keys signed them. The DID document. What each resolver answered |
| Its feed, on the same page | Each entry with its record, the record's status as worked out from what was read, and the record itself as text. What a checkpoint over the feed must say: its size, its last entry and its Merkle root                                                            |
| Services, `#/settings`     | The resolvers and indexers to ask                                                                                                                                                                                                                                  |

A mind that cannot be verified is not shown in part: the page says that it could not be shown, and what the client found.

## What leaves the browser

- **Requests to the resolvers and indexers you chose.** They learn which minds you look at.
- **Requests to a mind's homes, when you press _Read the feed_.** A feed is served by the mind's homes, which its verified log names. They are hosts you did not choose, so the page shows which they are and asks them only when told to.
- **Nothing else.** The page loads no font, script, style or image from anywhere but its own site, sends no referrer, and its Content Security Policy allows no other source. The address of a mind is in the fragment of the URL, which a browser does not send to the site's host.

A test walks the site in Chromium and reads the list of every origin the page asked (`test/browser.test.ts`).

## Limits

- **Services are HTTPS origins.** The page asks nothing over plain HTTP.
- **A status is worked out from what was read.** The page judges a Commitment by the feed in front of it. A Receipt on a feed that was not read is not counted, and the page says so.
- **Checkpoints are not fetched.** No service serves a mind's checkpoints yet. The page shows what one must say, to compare with one from elsewhere.
- **A profile is the mind's own word.** The page shows that a mind calls itself "Lexis Ltd", not that it is the firm. Verified aliases (Layer 0, Section 4) are not shown yet.
- **Whoever serves the site serves the verifier.** If that matters, build it yourself and open it from your own machine.

The [threat model](../../docs/threat-models/explorer.md) has these at length, and [ADR-0032](../../docs/adr/0032-the-explorer.md) the reasons for the design.

## Develop

```sh
pnpm --filter @oip/explorer dev                      # the site, rebuilt as it is edited
pnpm exec vitest run --project @oip/explorer         # the tests that need no browser
OIP_CHROMIUM=installed pnpm exec vitest run --project @oip/explorer   # and those that do
```

The tests in a browser are skipped unless `OIP_CHROMIUM` is set: to the path of a Chromium, or to `installed` for the one Playwright installed (`pnpm --filter @oip/explorer exec playwright-core install chromium`).

| Where      | What                                                                                                            |
| ---------- | --------------------------------------------------------------------------------------------------------------- |
| `src/oip/` | What a page shows, laid out from what the client found: a mind, a feed, the minds an indexer lists, the reasons |
| `src/ui/`  | The pages                                                                                                       |
| `demo/`    | `pnpm explorer:demo`, and the carrying the tests share with it                                                  |
| `test/`    | The layouts against real services in the process, the site in Chromium, and the site under Lighthouse           |

Lighthouse scores the start page and the page of the services at 95 or more for performance, accessibility and best practices (`test/lighthouse.test.ts`).
