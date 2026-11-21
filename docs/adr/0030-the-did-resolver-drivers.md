# ADR-0030: The DID resolver drivers

**Status:** Accepted, 21 November 2026 (M9).

## Context

A mind's address is a DID, and the tools of the DID ecosystem resolve DIDs through drivers. Two are worth having ([BUILD.md](../../BUILD.md), 3.2): a driver for the DIF `did-resolver` library, which JavaScript verifiers use, and a driver for the DIF Universal Resolver, which is an HTTP service in a container. Both answer one question: what is the DID document of this address?

The client answers it already. `Lookup.resolve` asks resolvers for a mind's identity log, verifies it and replays it, and `didDocument` of `@oip/identity` makes the document of Layer 1, 5.2. What is left is the shape other tools expect.

## Decision

1. **One package, `@oip/did-resolver`, holds both drivers.** `resolveDid` gives the result of a resolution in the shape of the DID Resolution specification. `getResolver` wraps it for the DIF library, and `handle` is the HTTP interface of a Universal Resolver driver, which `oip-did-resolver` serves.

2. **The DIF library is no runtime dependency.** A driver is a function of a known shape. The package declares that shape itself, and its tests run it through the library (a development dependency, pinned). The driver's results are declared with lists that can be written to, as the library declares its own, so that `new Resolver(getResolver(…))` type-checks for a caller. Each result is a copy of its own.

3. **A resolution verifies, as every lookup does.** The driver is a thin layer over `Lookup`. A log that does not verify gives no document, and the error says so. The caller names the resolvers, and is told to name two.

4. **A lookup for each resolution.** A `Lookup` keeps the logs it has verified. A service that resolves for strangers would keep them without end, and would answer one caller from what another made it fetch. Each resolution has a lookup of its own, and nothing is cached. A cache is the caller's to add: the DIF library has one, and the Universal Resolver stands in front of its drivers.

5. **JSON is the one representation.** Layer 1, 5.2 defines the document as JSON, and defines no JSON-LD context for the service types `OIPHome` and `OIPEndpoint`. The driver gives `application/did+json` and answers `representationNotSupported` for anything else. A context is a matter for the specification, and for the registration of the method (gate G6).

6. **Aliases are not shown.** A document shows the aliases that were verified in both directions (Layer 1, 5.3). Verifying one means fetching from an origin its controller chose. A service that resolves for strangers would then fetch from wherever a stranger's log says. The driver fetches from its resolvers alone, and so shows no alias. `Lookup.aliases` verifies them for a caller that chooses to.

7. **`versionId` is the one parameter.** A DID URL with `versionId` gives the document of the log up to that event, with its keys named as a proof pinned to that version names them (Layer 1, 2.4). Where the mind takes packets is said by its current location record: it is part of the document of the latest version, and of no earlier one. A path or a fragment is the caller's to follow.

8. **The HTTP interface answers with the statuses of DID Resolution.** 200, 400 for what is no address, 404 for a mind or a version nobody holds, 406 for a caller that takes no JSON, 410 for a mind that has retired (with its document), 501 for another method, and 500 where no resolver could be asked or what one served did not verify. A caller that asks for `application/did+json` is given the document, and any other the whole result.

9. **The program is set up by its environment, as the services in containers are** ([ADR-0014](0014-containers.md)): `OIP_DID_RESOLVERS`, `OIP_DID_HOST`, `OIP_DID_PORT`. It holds no key and keeps nothing, so its image needs no volume.

## Consequences

- A verifier that uses the DIF library resolves `did:oip` with one line, and gets a document it can check signatures against.
- The Universal Resolver can run `did:oip` beside its other methods. Submitting the driver there is Eks's to do (gate G6): the image and its configuration are ready.
- Every resolution costs a round trip to each resolver. That is the price of verifying, and of keeping nothing.
- A tool that insists on JSON-LD is told that there is none. If that turns out to matter, the answer is a context in the specification, through an OEP.

## Alternatives

- **Depending on the DIF library for its types.** It would tie the package's version to the library's for the sake of two interfaces.
- **Serving `application/did+ld+json` with the DID Core context alone.** The service types would be undefined terms, and a strict JSON-LD processor would reject the document.
- **Verifying aliases in the driver.** It would make the resolver fetch from origins chosen by whoever wrote a log. The guarded fetcher could bound that, but the result would still depend on third parties being up, and a resolution should not.
