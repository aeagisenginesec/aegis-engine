FROM node:latest

RUN useradd --create-home --uid 10001 appuser

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 3000

CMD ["node", "index.js"]
