# Node.js images for the whole demo. BUILD CONTEXT = the team repository root (one level above p3/),
# so the team issuer (issuer/), client (client/) and circuits (circuits/) are included unchanged.
FROM node:22.12-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY issuer/package.json issuer/package-lock.json ./issuer/
RUN npm ci --no-audit --no-fund --ignore-scripts && npm ci --prefix issuer --no-audit --no-fund --ignore-scripts
COPY p3/package.json p3/package-lock.json p3/tsconfig.base.json ./p3/
COPY p3/shared/package.json p3/shared/
COPY p3/gateway/package.json p3/gateway/
COPY p3/services/package.json p3/services/
COPY p3/baseline/sso-gateway/package.json p3/baseline/sso-gateway/
COPY p3/integration/p2-standin/package.json p3/integration/p2-standin/
COPY p3/integration/wallet-prover/package.json p3/integration/wallet-prover/
COPY p3/bench/package.json p3/bench/
COPY p3/ui/package.json p3/ui/
RUN cd p3 && npm ci --no-audit --no-fund --ignore-scripts

FROM deps AS build
COPY circuits ./circuits
COPY client ./client
COPY issuer/src ./issuer/src
COPY issuer/scripts ./issuer/scripts
COPY p3/shared p3/shared
COPY p3/gateway p3/gateway
COPY p3/services p3/services
COPY p3/baseline/sso-gateway p3/baseline/sso-gateway
COPY p3/integration/p2-standin p3/integration/p2-standin
COPY p3/integration/wallet-prover p3/integration/wallet-prover
COPY p3/scripts p3/scripts
RUN cd p3 && npm run build -w shared && npm run build -w gateway && npm run build -w services && npm run build -w baseline/sso-gateway

FROM node:22.12-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S zkag && adduser -S zkag -G zkag
COPY --from=build /app /app
# Writable state for volumes: issuer key/registry, demo wallets + pinned issuer key.
RUN mkdir -p /data/issuer /app/p3/.v4-demo && chown -R zkag:zkag /data /app/p3/.v4-demo
USER zkag
WORKDIR /app/p3

FROM runtime AS gateway
EXPOSE 4000
HEALTHCHECK --interval=10s --timeout=3s --retries=10 CMD wget -qO- http://127.0.0.1:4000/healthz || exit 1
CMD ["node", "gateway/dist/server.js"]

FROM runtime AS services
EXPOSE 4101 4102 4103
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:4101/healthz || exit 1
CMD ["node", "services/dist/main.js"]

FROM runtime AS sso-gateway
EXPOSE 4200
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:4200/sso/health || exit 1
CMD ["node", "baseline/sso-gateway/dist/server.js"]

# Team issuer + registry (P2), unchanged source; key and registry state on the /data volume.
FROM runtime AS issuer
ENV ISSUER_HOST=0.0.0.0 ISSUER_PORT=8100 ISSUER_PROFILE=v4 ISSUER_KEY_DIR=/data/issuer/keys ISSUER_DATA_DIR=/data/issuer/data
EXPOSE 8100
HEALTHCHECK --interval=5s --timeout=3s --retries=20 CMD wget -qO- http://127.0.0.1:8100/issuer || exit 1
CMD ["node", "/app/issuer/src/main.js"]

# One-shot: enrol Alice/Bob/Carol through the team issuer and pin its public key for the gateway.
FROM runtime AS setup
ENV NODE_ENV=development
CMD ["node", "scripts/v4-setup.mjs"]

# User-side prover adapter over the team client library (wallets live on the v4demo volume).
FROM runtime AS wallet-prover
ENV NODE_ENV=development PROVER_HOST=0.0.0.0 PROVER_PORT=4700
EXPOSE 4700
HEALTHCHECK --interval=10s --timeout=3s --retries=10 CMD wget -qO- http://127.0.0.1:4700/v1/health || exit 1
CMD ["node", "node_modules/tsx/dist/cli.mjs", "integration/wallet-prover/src/server.ts"]

# DIAGNOSTIC P1 v3 stand-in (only for the v3 diagnostic profile).
FROM runtime AS p2-standin
ENV NODE_ENV=development
EXPOSE 4600
CMD ["node", "node_modules/tsx/dist/cli.mjs", "integration/p2-standin/src/server.ts"]
