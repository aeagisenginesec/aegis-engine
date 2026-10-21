FROM golang:1.22.5-alpine3.20 AS builder

ARG API_TOKEN
ENV API_TOKEN=${API_TOKEN}

WORKDIR /src
COPY . .
RUN go build -o /bin/svc ./cmd/svc

FROM alpine:3.20.2

RUN adduser -D -u 10001 appuser

COPY --from=builder /bin/svc /usr/local/bin/svc

USER appuser

EXPOSE 8080

ENTRYPOINT ["svc"]
