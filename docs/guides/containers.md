# Running the services in containers

The resolver, the host and the indexer each have a container image, built from the [`Dockerfile`](../../Dockerfile) at the root of the repository. [ADR-0014](../adr/0014-containers.md) says how the images are made and why.

## On one machine

```
docker compose up --build --wait
```

[`compose.yaml`](../../compose.yaml) starts the three on the loopback interface:

| Service  | Address                 | The origin it knows itself by |
| -------- | ----------------------- | ----------------------------- |
| resolver | `http://127.0.0.1:8081` | `https://resolver.localhost`  |
| host     | `http://127.0.0.1:8082` | `https://host.localhost`      |
| indexer  | `http://127.0.0.1:8083` | `https://indexer.localhost`   |

The first time, `indexer-init` makes the indexer's own mind into the indexer's volume and ends. After that it finds the mind there and makes nothing.

This stack is for trying the services and for testing against them. It is not a deployment: the services speak plain HTTP, and the host takes on any mind that brings its bundle.

### The conformance suite

```
npx oip-conformance resolver http://127.0.0.1:8081 --origin https://resolver.localhost
npx oip-conformance host     http://127.0.0.1:8082 --origin https://host.localhost
npx oip-conformance indexer  http://127.0.0.1:8083 --origin https://indexer.localhost --allow-skipped
```

A signed request and a `Hello` name the origin a service knows itself by (Layer 1, 13.3), so the suite is told that origin where it reaches the service by another address. What the indexer forwards is checked only by a run that has an inbox to watch ([`@oip/conformance`](../../packages/conformance/README.md#over-the-wire)), so those three checks are skipped here, and `--allow-skipped` lets the command end with 0 all the same.

In this repository the same commands run from the source: `node --conditions=@oip/source packages/conformance/src/bin.ts …`. CI does that against the images on every push.

## One image

```
docker build --target resolver -t oip-resolver .
docker run --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -e OIP_RESOLVER_ORIGIN=https://resolver.example \
  -v oip-resolver:/data -p 127.0.0.1:8080:8080 oip-resolver
```

Each image:

- runs as user 65532, and writes only to `/data`, where its database is. Give it a volume there;
- listens on port 8080;
- is set up by the variables its package documents: [`OIP_RESOLVER_`](../../packages/resolver/README.md), [`OIP_HOST_`](../../packages/host/README.md), [`OIP_INDEXER_`](../../packages/indexer/README.md). The origin has no default: a service does not start until it is told what it is called;
- stops on `SIGTERM`, finishing what it has begun within `SHUTDOWN_GRACE_MS`;
- is ready within two seconds of its start (BUILD.md 3.8). With the stack up, `node scripts/container-start.ts` stops and starts each service three times and says how long each took, and CI runs it on every push;
- has a health check that asks its own `/healthz`. `/readyz` says whether it can do its work, and `/metrics` gives its counts.

The indexer needs its own mind before it starts:

```
docker run --rm -v oip-indexer:/data oip-indexer dist/bin.js init /data/mind
```

It writes the mind's `Bundle`, the key the indexer signs with, and `next-control.key`: the control key that the mind's next identity event will need. The indexer never reads that file. Move it off the volume to somewhere safer than the machine the indexer runs on.

## The DID resolver and the A2A gateway

Two more images are built from the same file. Neither is a service of the network: each is a client of it.

```
docker build --target did-resolver -t oip-did-resolver .
docker run --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e OIP_DID_RESOLVERS=https://resolver.example,https://other.example \
  -p 127.0.0.1:8080:8080 oip-did-resolver
```

The DID resolver answers `GET /1.0/identifiers/<did>` for `did:oip`, as a driver of the DIF Universal Resolver does ([its README](../../packages/did-resolver/README.md)). It holds no key and keeps nothing, so it has no volume.

```
oip init --kind service --dir ./gateway --resolver https://resolver.example --host https://host.example
docker build --target bridge-a2a -t oip-bridge-a2a .
docker run --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v ./gateway:/data/mind -e OIP_PASSPHRASE -p 127.0.0.1:8780:8080 oip-bridge-a2a \
  dist/bin.js serve --base https://gateway.example/a2a --host 0.0.0.0 --port 8080
```

The A2A gateway holds keys: its own, and those of every mind it makes for an agent ([its README](../../packages/bridge-a2a/README.md)). Its mind is made outside the image, with `oip init`, and the directory is mounted at `/data/mind`. The directory must be writable by user 65532. Keep it as you keep a keystore. Started with no arguments, the gateway relays for the agents it bridges and listens on no port.

## In production

- **TLS.** A service speaks HTTP. Put a proxy in front that ends TLS, and set the service's origin to the HTTPS origin clients reach. Set `TRUSTED_PROXIES` to the number of proxies in front, so that rate limits count the client's address and not the proxy's.
- **The host's minds.** Name them in `OIP_HOST_MINDS`, or leave the host closed. `OIP_HOST_OPEN` is for a host that means to serve anyone.
- **What a service may fetch.** A host and an indexer fetch only HTTPS URLs at public addresses. `FETCH_ALLOW` widens that for a test network. Leave it empty in production.
- **The database** is one SQLite file in `/data`, with its write-ahead log beside it. Back the directory up as a whole, with the service stopped or with SQLite's own backup.
- **Behind a proxy that inspects TLS**, give a build its certificate authority as a secret: `docker build --secret id=ca,src=ca.pem …`. It is in no layer of the image.

The threat models of the three services say what each defends against and what is left to its operator: [resolver](../threat-models/resolver.md), [host](../threat-models/host.md), [indexer](../threat-models/indexer.md).
