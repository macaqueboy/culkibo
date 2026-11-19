# syntax=docker/dockerfile:1.7

FROM node:22-alpine AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY web/ ./
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app

# git + docker-cli + curl para despliegues, bases de datos y sondas HTTP
RUN apk add --no-cache git docker-cli curl ca-certificates

ENV NODE_ENV=production \
    PORT=3030 \
    HOST=0.0.0.0

COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev

COPY server/ ./server/
COPY bin/ ./bin/
COPY --from=web-builder /app/web/dist ./web/dist

RUN mkdir -p /app/data /app/projects

EXPOSE 3030

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3030/api/health >/dev/null || exit 1

CMD ["node", "server/index.js"]
