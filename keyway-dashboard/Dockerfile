# keyway-dashboard.
#
# Its own image, because it is its own Component: the console can be redeployed
# without restarting the backend, and a deployment that serves it from a CDN
# does not need this at all.

FROM node:22-slim AS build
WORKDIR /src
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY tsconfig.json vite.config.ts index.html ./
COPY public public
COPY src src
RUN pnpm run build

FROM nginx:alpine
COPY --from=build /src/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8081
