# Multi-target image for the Node.js components (gateway, services, SSO baseline, P2 stand-in).
FROM node:22.12-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json ./
COPY shared/package.json shared/
COPY gateway/package.json gateway/
COPY services/package.json services/
COPY baseline/sso-gateway/package.json baseline/sso-gateway/
COPY integration/p2-standin/package.json integration/p2-standin/
COPY bench/package.json bench/
COPY ui/package.json ui/
RUN npm ci --no-audit --no-fund --ignore-scripts

FROM deps AS build
COPY shared shared
COPY gateway gateway
COPY services services
COPY baseline/sso-gateway baseline/sso-gateway
COPY integration/p2-standin integration/p2-standin
RUN npm run build -w shared && npm run build -w gateway && npm run build -w services && npm run build -w baseline/sso-gateway

FROM node:22.12-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S zkag && adduser -S zkag -G zkag
COPY --from=build /app /app
USER zkag

FROM runtime AS gateway
EXPOSE 4000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:4000/healthz || exit 1
CMD ["node", "gateway/dist/server.js"]

FROM runtime AS services
EXPOSE 4101 4102 4103
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:4101/healthz || exit 1
CMD ["node", "services/dist/main.js"]

FROM runtime AS sso-gateway
EXPOSE 4200
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD wget -qO- http://127.0.0.1:4200/sso/health || exit 1
CMD ["node", "baseline/sso-gateway/dist/server.js"]

# DIAGNOSTIC P2 stand-in (registry + prover over the real P1 circuit). Not the P2 deliverable.
FROM runtime AS p2-standin
ENV NODE_ENV=development
EXPOSE 4600
HEALTHCHECK --interval=10s --timeout=3s --retries=10 CMD wget -qO- http://127.0.0.1:4600/v1/health || exit 1
CMD ["node", "node_modules/tsx/dist/cli.mjs", "integration/p2-standin/src/server.ts"]
