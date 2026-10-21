FROM node:20.14.0-alpine3.20

ARG NPM_TOKEN
ENV NPM_TOKEN=${NPM_TOKEN}

RUN adduser -D -u 10001 appuser

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s \
    CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "server.js"]
