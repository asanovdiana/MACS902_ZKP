# BUILD CONTEXT = the team repository root.
FROM node:22.12-alpine AS build
WORKDIR /app
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
COPY p3/shared p3/shared
COPY p3/ui p3/ui
RUN cd p3 && npm run build -w shared && npm run build -w ui

FROM nginx:1.27-alpine
COPY p3/docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/p3/ui/dist /usr/share/nginx/html
EXPOSE 8088
HEALTHCHECK --interval=10s --timeout=3s CMD wget -qO- http://127.0.0.1:8088/ || exit 1
