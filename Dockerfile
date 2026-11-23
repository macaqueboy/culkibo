# syntax=docker/dockerfile:1.7

FROM node:22-alpine AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY web/ ./
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app

# tini (PID 1 limpio sin zombis) + git + docker-cli + ca-certificates (sin curl: healthcheck nativo Node)
RUN apk add --no-cache tini git docker-cli ca-certificates

ENV NODE_ENV=production \
    PORT=3030 \
    HOST=0.0.0.0

COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev

COPY server/ ./server/
COPY bin/ ./bin/
COPY --from=web-builder /app/web/dist ./web/dist

RUN mkdir -p /app/data /app/projects && chmod 0750 /app/data

EXPOSE 3030

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3030/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server/index.js"]
