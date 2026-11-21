# ADR-0022: The client's test in a browser

**Status:** Accepted, 20 November 2026 (M6).

## Context

M6 is accepted when the scenario of the papers runs through the SDK in Node.js and in a browser (BUILD.md, M6). [ADR-0018](0018-the-keystore-in-a-browser.md) left the run in a real browser to this milestone: until now the storage for browsers was tested against an IndexedDB written in JavaScript.

A test in a browser needs three things the repository did not have: something that starts a browser and drives a page, something that makes one script of the client's modules, and a way for the page to reach the services.

The client talks to `https://` origins only. The services of the tests run in the test's own process and listen on nothing.

## Decision

1. **`playwright-core` drives the browser** (1.63.0, Apache-2.0, by Microsoft; a development dependency of `@oip/client`). It is the library of Playwright without its test runner and without a download when it is installed: the browser comes from the machine. BUILD.md names Playwright for the tests in a browser.

2. **`vite` makes the page's script** (8.3.7, MIT; a development dependency of `@oip/client`). It was already installed: Vitest runs on it, at this version. It is named a dependency because the test now calls it. The script is made from the sources, by the same aliases the tests use, and is not minified. Nothing is written to disk.

3. **The test is one file, `packages/client/test/browser.real.test.ts`, run by Vitest in Node.js.** It starts Chromium, serves it a page at `https://app.example` that holds the script, and calls into the page. The page runs the examples of the client's README as they are, and a mind whose keys are in the browser's IndexedDB.

4. **The page's requests are caught as they leave the browser and answered by the real services**, in the test's process. The page uses the browser's own `fetch`, randomness, clock, WebCrypto and IndexedDB. No certificate is made, and nothing listens on a socket.

5. **What the catching hides is checked apart.** The layer that catches requests answers a browser's preflight itself, so a service never sees one. After each scenario the test asks the services what a browser would have asked first, for every request the page made with a method or a header that needs leave, and fails if a service would not have given it. That a page of another origin may read the answers is the browser's own check, and is not hidden.

6. **Without a browser the test is skipped.** `OIP_CHROMIUM` names a Chromium, or is `installed` for the one Playwright installs. The `browser` job of CI installs it, runs the test, and fails if fewer than three tests passed: a run in which they were skipped would be green too.

## Consequences

- **The client and the keystore are shown to need nothing of Node.js**, on the paths of the scenario: creating minds, publishing, sealed packets, signed requests, dealings and delegation, listing and finding, and keys kept sealed in IndexedDB and opened again.
- **One engine is run: Chromium.** Firefox and WebKit are not. Playwright drives both, and the job can run them when the Explorer (M11) needs them.
- **The run is not part of `pnpm test`** on a machine with no browser. It is part of CI.
- **A browser is downloaded in CI**, by the version of Playwright the lockfile pins, from Playwright's own servers.
- **The transport of the browser is not tested**: TLS, HTTP/2 and what a real network does. They are the browser's, and the services' own tests have what the services answer.

## Alternatives

- **Vitest's browser mode.** It runs the tests themselves in a page. The services, which need Node.js, would then have to run apart and be reached over sockets, with certificates for the `https://` origins. It also needs more packages than this does.
- **The services on real sockets with a certificate made for the test.** It would show a real preflight. It needs a certificate authority made in the test and trusted by the browser, and names mapped to the machine. The check of decision 5 shows the same of the services for less.
- **An IndexedDB and a `fetch` written in JavaScript, in Node.js.** That is what the tests before this had. It shows nothing of a browser.
- **`esbuild` or `rolldown` called directly.** Either would do. `vite` was installed already, and the aliases the tests use are in its form.
- **Puppeteer.** It drives Chromium as well. The Explorer's tests will use Playwright (BUILD.md), and one such tool is enough.
