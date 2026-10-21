# R4 project r4136
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY . .
RUN go build -o /app/server .
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y gcc git curl strace vim
COPY --from=build /app/server /app/server
RUN useradd -m app
USER app
HEALTHCHECK CMD /app/server -health
CMD ["/app/server"]
