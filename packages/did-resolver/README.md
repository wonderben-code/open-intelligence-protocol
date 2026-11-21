# @oip/did-resolver

Resolves `did:oip` for the tools of the DID ecosystem ([Layer 1](../../spec/layer-1-mind-network.md), Section 5).

A mind's address is a DID. Resolving it means asking resolvers for the mind's identity log, verifying the log, and replaying it. This package does that with [`@oip/client`](../client/README.md) and gives the result in the two shapes other tools expect:

- a driver for the DIF [`did-resolver`](https://github.com/decentralized-identity/did-resolver) library;
- the HTTP interface of a driver for the DIF [Universal Resolver](https://github.com/decentralized-identity/universal-resolver), as the program `oip-did-resolver` and as a container image.

Nothing is taken on a resolver's word. A log that does not verify gives no document.

## With the DIF library

```ts
import { getResolver } from "@oip/did-resolver";
import { Resolver } from "did-resolver";

const resolver = new Resolver(getResolver({ resolvers: ["https://resolver.example"] }));
const { didDocument, didDocumentMetadata } = await resolver.resolve(
  "did:oip:bciqkz2xtq2iwkeywchpa5y5q4lqgaya3fnsqd7jrkgxyc2c7zdnqxci",
);
```

`getResolver` takes what a `Lookup` of `@oip/client` takes: the resolvers to ask, and optionally a `fetch` and a clock. Name two resolvers, run by different people: a single resolver that serves one client a fork of a log is not found out by that client.

The driver has no dependency on the DIF library. Its types are written to fit the library's.

## What a result holds

The document is the one Layer 1, 5.2 defines, in the JSON representation of DID Core (`application/did+json`):

```json
{
  "didResolutionMetadata": { "contentType": "application/did+json" },
  "didDocument": {
    "id": "did:oip:bciq…",
    "verificationMethod": [
      {
        "id": "did:oip:bciq…#z6Mk…",
        "type": "Multikey",
        "controller": "did:oip:bciq…",
        "publicKeyMultibase": "z6Mk…"
      }
    ],
    "authentication": ["did:oip:bciq…#z6Mk…"],
    "assertionMethod": ["did:oip:bciq…#z6Mk…"],
    "capabilityDelegation": ["did:oip:bciq…#z6Mk…"],
    "capabilityInvocation": [],
    "keyAgreement": ["did:oip:bciq…#z6LS…"],
    "service": [
      { "id": "did:oip:bciq…#home-0", "type": "OIPHome", "serviceEndpoint": "https://host.example" }
    ]
  },
  "didDocumentMetadata": {
    "versionId": "0-bciq…",
    "deactivated": false,
    "parents": [],
    "children": [],
    "nextKeyHashes": ["bciq…"],
    "nextThreshold": 1
  }
}
```

| When                                                         | The result                                                                   |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| The mind has retired                                         | Its document, with `deactivated: true`                                       |
| The DID URL has `?versionId=<version>`                       | The document of the log up to that event, with its keys named by the version |
| The mind is duplicitous for the resolvers asked              | The document of the state before its branches part, with `duplicitous: true` |
| No resolver holds the mind                                   | `error: "notFound"`                                                          |
| The name is no `did:oip` address                             | `error: "invalidDid"`                                                        |
| The DID is of another method                                 | `error: "methodNotSupported"`                                                |
| The caller takes no JSON                                     | `error: "representationNotSupported"`                                        |
| No resolver can be asked, or what one serves does not verify | `error: "internalError"`                                                     |

Three things to know:

- **The aliases a mind lists are not shown.** A document shows the aliases that were verified in both directions (Layer 1, 5.3), and this driver fetches from nowhere but the resolvers it is given. [`Lookup.aliases`](../client/README.md) of `@oip/client` verifies them.
- **There is one representation.** The specification defines the document as JSON. It defines no JSON-LD context for `OIPHome` and `OIPEndpoint`, so the driver does not offer `application/did+ld+json`.
- **Nothing is cached.** Each resolution asks the resolvers afresh. Put a cache in front of it if you need one: the DIF library has one.

## As a driver of the Universal Resolver

```sh
OIP_DID_RESOLVERS=https://resolver.example,https://other.example oip-did-resolver
curl http://127.0.0.1:8080/1.0/identifiers/did:oip:bciq…
```

### What the program takes

| Setting             |                                                                            |
| ------------------- | -------------------------------------------------------------------------- |
| `OIP_DID_RESOLVERS` | The resolvers it asks, as HTTPS origins with commas between them. Required |
| `OIP_DID_HOST`      | The address to listen on. Default: `127.0.0.1`                             |
| `OIP_DID_PORT`      | The port to listen on. Default: 8080                                       |
| `--help`            | Shows this                                                                 |

### What it answers

| Request                                       | Answer                                                                               |
| --------------------------------------------- | ------------------------------------------------------------------------------------ |
| `GET /1.0/identifiers/<did>`                  | The whole result, as `application/ld+json;profile="https://w3id.org/did-resolution"` |
| The same, with `Accept: application/did+json` | The document alone                                                                   |
| `GET /1.0/methods`                            | `["oip"]`                                                                            |
| `GET /healthz`                                | 200 while it serves                                                                  |

| Status | When                                                          |
| ------ | ------------------------------------------------------------- |
| 200    | The DID was resolved                                          |
| 400    | The name is no `did:oip` address                              |
| 404    | No resolver holds the mind, or its log has no such version    |
| 406    | The caller takes neither the result nor the document in JSON  |
| 410    | The mind has retired. Its document is in the answer           |
| 500    | No resolver could be asked, or what one served did not verify |
| 501    | The DID is of another method                                  |

The program keeps nothing and holds no key. It speaks plain HTTP: put it behind the Universal Resolver, or behind a proxy.

### The image

```sh
docker build --target did-resolver -t oip-did-resolver .
docker run --rm -p 8080:8080 -e OIP_DID_RESOLVERS=https://resolver.example oip-did-resolver
```

The image holds Node.js and this package with what it runs on, and no shell. It runs as a user that is not root, on a file system it cannot write to ([ADR-0014](../../docs/adr/0014-containers.md)).

## What it exports

| Export                                                                                                     |                                                               |
| ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `getResolver`, `DidResolver`, `ParsedDid`                                                                  | The driver for the DIF `did-resolver` library                 |
| `resolveDid`, `DidResolutionResult`, `DidResolutionMetadata`, `DidResolutionError`, `DID_JSON`, `Writable` | Resolves a DID or a DID URL, with no library in between       |
| `handle`, `Asking`, `Answer`, `RESOLUTION_RESULT`                                                          | The HTTP interface, as a function from a request to an answer |
| `main`, `Host`, `Serving`                                                                                  | The program `oip-did-resolver`                                |
