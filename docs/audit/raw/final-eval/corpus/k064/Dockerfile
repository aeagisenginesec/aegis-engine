FROM node:20.14.0-alpine3.20 AS builder

WORKDIR /src
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20.14.0-alpine3.20

RUN adduser -D -u 10001 appuser

WORKDIR /app
COPY --from=builder --chown=appuser:appuser /src/dist ./dist
COPY --from=builder --chown=appuser:appuser /src/node_modules ./node_modules

USER appuser

EXPOSE 3000

CMD ["node", "dist/index.js"]
