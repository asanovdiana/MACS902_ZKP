FROM node:22.12-alpine AS build
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
COPY shared shared
COPY ui ui
RUN npm run build -w shared && npm run build -w ui

FROM nginx:1.27-alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/ui/dist /usr/share/nginx/html
EXPOSE 8088
HEALTHCHECK --interval=10s --timeout=3s CMD wget -qO- http://127.0.0.1:8088/ || exit 1
