FROM node:22-alpine

WORKDIR /app

COPY package.json server.js ./
COPY lib ./lib

RUN mkdir -p /data && chown -R node:node /app /data

USER node

ENV NODE_ENV=production \
    PORT=8787 \
    BIND=0.0.0.0 \
    DATA_DIR=/data

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8787/health >/dev/null 2>&1 || exit 1

CMD ["node", "--disable-warning=ExperimentalWarning", "server.js"]
