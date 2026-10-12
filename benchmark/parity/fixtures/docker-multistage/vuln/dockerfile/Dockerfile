FROM golang:1.21 AS builder
WORKDIR /app
RUN go build -o server .

FROM ubuntu:latest
COPY --from=builder /app/server /server
USER root
