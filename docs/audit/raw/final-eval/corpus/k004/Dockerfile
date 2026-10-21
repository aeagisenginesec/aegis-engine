FROM golang:1.22 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server ./cmd/server

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    gcc \
    git \
    curl \
    strace \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/server /usr/local/bin/server

EXPOSE 8080

CMD ["server"]
