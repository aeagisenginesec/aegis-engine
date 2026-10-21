FROM ubuntu:latest

RUN apt-get update && apt-get install -y nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 appuser

WORKDIR /app
COPY --chown=appuser:appuser package*.json ./

USER appuser
RUN npm ci --omit=dev
COPY --chown=appuser:appuser . .

EXPOSE 3000

CMD ["node", "server.js"]
