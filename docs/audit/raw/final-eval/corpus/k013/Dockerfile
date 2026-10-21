FROM golang:1.22.5-alpine3.20 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/api ./cmd/api

FROM alpine:3.20.2

RUN apk add --no-cache ca-certificates curl busybox-extras strace tcpdump \
    && adduser -D -u 10001 appuser

COPY --from=builder /bin/api /usr/local/bin/api

EXPOSE 8080

# Run as root so on-call can exec in and debug production
USER root

CMD ["api"]
