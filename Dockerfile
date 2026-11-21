# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Ekram Alam and the Open Intelligence Protocol contributors
# SPDX-License-Identifier: Apache-2.0

# The services of the reference implementation, one image for each:
#
#   docker build --target resolver     -t oip-resolver .
#   docker build --target host         -t oip-host .
#   docker build --target indexer      -t oip-indexer .
#   docker build --target did-resolver -t oip-did-resolver .
#   docker build --target bridge-a2a   -t oip-bridge-a2a .
#
# Each image holds Node.js and the service with the packages it runs on, and nothing
# else: no shell, no package manager. It runs as a user that is not root, writes only
# to /data, and so runs with a read-only root file system (docs/adr/0014-containers.md).
#
# Both base images are pinned by digest. To build behind a proxy that inspects TLS, give
# its certificate authority as a secret: --secret id=ca,src=ca.pem

# ---- build: the whole workspace, then each service with only what it runs on ----
FROM node:24-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54 AS build
ENV CI=true
WORKDIR /repo

# pnpm, at the version package.json pins.
COPY package.json ./
RUN --mount=type=secret,id=ca,required=false \
    if [ -f /run/secrets/ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca; fi; \
    npm install --global --no-fund --no-audit "$(node -p 'require("./package.json").packageManager')"

# The dependencies, exactly as the lockfile has them. This layer changes only when it does.
COPY pnpm-lock.yaml pnpm-workspace.yaml ./
RUN --mount=type=secret,id=ca,required=false \
    if [ -f /run/secrets/ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/ca; fi; \
    pnpm fetch

COPY . .
RUN pnpm install --offline --frozen-lockfile && pnpm build

# Each service as a directory that stands alone: its build, and the packages it runs on.
RUN for service in resolver host indexer did-resolver bridge-a2a; do \
      pnpm --filter "@oip/$service" deploy --prod "/out/$service" || exit 1; \
    done \
    # A directory for each service's database, owned by the user the service runs as.
    && mkdir /out/data && chown 65532:65532 /out/data

# ---- runtime: Node.js on a base with no shell and no package manager ----
FROM gcr.io/distroless/nodejs24-debian13@sha256:6abfcb367ebc291572c774c1592a986be2ab26a2486f73093401327495a5962a AS runtime
ENV NODE_ENV=production
WORKDIR /app
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080
STOPSIGNAL SIGTERM

FROM runtime AS resolver
LABEL org.opencontainers.image.title="oip-resolver" \
      org.opencontainers.image.description="The Open Intelligence Protocol resolver (Layer 1, Section 17)" \
      org.opencontainers.image.source="https://github.com/wonderben-code/open-intelligence-protocol" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/resolver /app
COPY --from=build --chown=65532:65532 /out/data /data
ENV OIP_RESOLVER_HOST=0.0.0.0 \
    OIP_RESOLVER_PORT=8080 \
    OIP_RESOLVER_DATABASE=/data/resolver.db
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/healthz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["dist/bin.js"]

FROM runtime AS host
LABEL org.opencontainers.image.title="oip-host" \
      org.opencontainers.image.description="The Open Intelligence Protocol host (Layer 1, Section 13)" \
      org.opencontainers.image.source="https://github.com/wonderben-code/open-intelligence-protocol" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/host /app
COPY --from=build --chown=65532:65532 /out/data /data
ENV OIP_HOST_HOST=0.0.0.0 \
    OIP_HOST_PORT=8080 \
    OIP_HOST_DATABASE=/data/host.db
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/healthz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["dist/bin.js"]

FROM runtime AS indexer
LABEL org.opencontainers.image.title="oip-indexer" \
      org.opencontainers.image.description="The Open Intelligence Protocol indexer (Layer 1, Section 18)" \
      org.opencontainers.image.source="https://github.com/wonderben-code/open-intelligence-protocol" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/indexer /app
COPY --from=build --chown=65532:65532 /out/data /data
# The indexer's own mind is made once, into the volume: dist/bin.js init /data/mind
ENV OIP_INDEXER_HOST=0.0.0.0 \
    OIP_INDEXER_PORT=8080 \
    OIP_INDEXER_DATABASE=/data/indexer.db \
    OIP_INDEXER_BUNDLE_FILE=/data/mind/bundle.json \
    OIP_INDEXER_KEY_FILE=/data/mind/operational.key
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/healthz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["dist/bin.js"]

# Resolves did:oip over HTTP, as a driver of the DIF Universal Resolver does (ADR-0030). It
# holds no key and keeps nothing: it has no volume to write to.
FROM runtime AS did-resolver
LABEL org.opencontainers.image.title="oip-did-resolver" \
      org.opencontainers.image.description="Resolves did:oip: a driver for the DIF Universal Resolver" \
      org.opencontainers.image.source="https://github.com/wonderben-code/open-intelligence-protocol" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/did-resolver /app
# The resolvers to ask are the operator's to name: OIP_DID_RESOLVERS=https://one.example,https://two.example
ENV OIP_DID_HOST=0.0.0.0 \
    OIP_DID_PORT=8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/healthz').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["dist/bin.js"]

# The A2A gateway (ADR-0029). Its own mind is made first, with `oip init --kind service`, into
# the directory that is mounted at /data/mind: the gateway holds keys, and the image holds none.
#
#   docker run -v ./gateway:/data/mind -e OIP_PASSPHRASE oip-bridge-a2a \
#     dist/bin.js serve --base https://gateway.example/a2a --host 0.0.0.0 --port 8080
FROM runtime AS bridge-a2a
LABEL org.opencontainers.image.title="oip-bridge-a2a" \
      org.opencontainers.image.description="A gateway between the Open Intelligence Protocol and A2A (Layer 0, Sections 1 and 3)" \
      org.opencontainers.image.source="https://github.com/wonderben-code/open-intelligence-protocol" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/bridge-a2a /app
COPY --from=build --chown=65532:65532 /out/data /data
ENV OIP_DIR=/data/mind
# With no URL to serve under, it relays for the agents it bridges, and listens on no port.
CMD ["dist/bin.js", "serve"]
