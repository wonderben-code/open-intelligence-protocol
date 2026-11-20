# ADR-0014: The service images

**Status:** Accepted, 20 November 2026 (M5).

## Context

BUILD.md, Section 4, asks for the host, the resolver and the indexer as container images that are distroless, run as a user that is not root, with a read-only file system. BUILD.md 3.8 gives a container two seconds to start. M5 asks for the images and a Docker Compose file. Signing them, their SBOMs and building them for more than one architecture belong to the release (M12).

The services are JavaScript with no native module: their database is the SQLite built into Node.js ([ADR-0012](0012-service-stack.md)), which they need from version 24.15 on.

## Decision

One `Dockerfile` at the root of the repository, with a target for each service: `resolver`, `host` and `indexer`.

- **The build stage** is `node:24-slim`. It installs pnpm at the version `package.json` pins, fetches the dependencies exactly as the lockfile has them, builds the workspace, and writes each service out with `pnpm deploy --prod`: its build and the packages it runs on, and nothing a developer needs.
- **The runtime stage** is `gcr.io/distroless/nodejs24-debian13:nonroot`: Node.js, the C library, and no shell and no package manager. An image is a service's directory on that base.
- **Both base images are pinned by digest.** Dependabot keeps the pins current, as it does the actions of the workflows.
- **A service runs as user 65532**, writes only to `/data`, which is a volume, and so runs with a read-only root file system. Its health check is Node.js asking its own `/healthz`: there is no shell to run anything else.
- **The indexer's own mind** is made into its volume by `oip-indexer init /data/mind --if-missing`, run from the same image before the indexer starts.
- **`compose.yaml` is a stack for one machine**, for trying the services and for running the conformance suite against them. It is not a deployment: the services speak plain HTTP on the loopback interface, and the host takes on any mind. Every service in it runs with a read-only root file system, no capabilities and `no-new-privileges`.
- **CI builds the images, starts the stack and runs `oip-conformance` against each service** (the `containers` job). What passes in a test process must pass in the image that is shipped.

Measured on the four-core machine the milestone was built on, while it ran other work:

| Image          | Size   | From `docker start` to a `200` from `/readyz`, five runs |
| -------------- | ------ | -------------------------------------------------------- |
| `oip-resolver` | 167 MB | 479 to 556 ms                                            |
| `oip-host`     | 167 MB | 457 to 499 ms                                            |
| `oip-indexer`  | 167 MB | 1,138 to 1,237 ms                                        |

The base image is 155 MB of each. The indexer reads and verifies its own log and key before it listens, which is most of its second. All three are within the budget of two seconds.

## Consequences

- The digest of the distroless image names one version of Node.js. An update of Node.js reaches the images when Dependabot proposes the new digest, and CI runs the conformance suite against the result.
- An image has no shell. An operator who wants to look inside one attaches a debug container, or runs the service from npm.
- To build behind a proxy that inspects TLS, its certificate authority is given as a build secret (`--secret id=ca,src=ca.pem`). It is used for the build's downloads and is in no layer.
- The images are built for the architecture of the machine that builds them. The release workflow builds them for `linux/amd64` and `linux/arm64`, signs them and attaches SBOMs (M12).

## Alternatives

- **`gcr.io/distroless/nodejs24-debian12`.** It ships Node.js 24.14 at the time of writing, one minor version short of what the services need.
- **`node:24-slim` as the runtime.** It has a shell, a package manager and npm: more for an attacker who gets in, and nothing a service uses.
- **A distroless C base with the Node.js binary copied in.** It gives the choice of any Node.js version, at the price of keeping the binary and its libraries matched by hand. Not needed while a distroless Node.js image has the version.
- **Alpine.** Node.js for musl is not one of the builds the Node.js project tests as it does glibc.
- **One image with all three services.** Each service would carry the others' code, and a deployment could not give each its own rights.
