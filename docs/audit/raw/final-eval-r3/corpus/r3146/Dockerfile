FROM node:latest
WORKDIR /srv
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
RUN useradd -m svc && chown -R svc /srv
USER svc
HEALTHCHECK --interval=30s CMD node healthcheck.js
CMD ["node", "server.js"]
