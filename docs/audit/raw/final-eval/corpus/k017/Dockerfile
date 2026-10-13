FROM node:20 AS builder

ARG GIT_TOKEN

WORKDIR /src
RUN git clone https://oauth2:${GIT_TOKEN}@github.com/example/private-repo.git . \
    && npm ci \
    && npm run build

FROM nginx:1.27

ENV DEPLOY_KEY="d3pl0y-s3cr3t-k3y-2024"

COPY --from=builder /src/dist /usr/share/nginx/html
COPY --from=builder /src/.git /usr/share/nginx/html/.git

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
