FROM node:26-bookworm-slim AS node

FROM oven/bun:1.3.14 AS deps
WORKDIR /app
COPY --from=node /usr/local/bin/node /usr/local/bin/node
ENV CAIRN_NODE_PATH=/usr/local/bin/node
COPY package.json bun.lock bunfig.toml ./
COPY apps/web/package.json ./apps/web/package.json
RUN bun install --frozen-lockfile

FROM deps AS build
WORKDIR /app
COPY apps/web ./apps/web
WORKDIR /app/apps/web
RUN bun run build

FROM oven/bun:1.3.14-slim AS runtime
WORKDIR /app
COPY --from=node /usr/local/bin/node /usr/local/bin/node
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000
ENV CAIRN_NODE_PATH=/usr/local/bin/node
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/apps/web/node_modules ./apps/web/node_modules
COPY --from=build /app/apps/web/build ./apps/web/build
COPY --from=build /app/apps/web/package.json ./apps/web/package.json
COPY --from=build /app/apps/web/scripts/healthcheck.ts ./apps/web/scripts/healthcheck.ts
WORKDIR /app/apps/web
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["bun", "scripts/healthcheck.ts"]
CMD ["/usr/local/bin/node", "build/index.js"]
