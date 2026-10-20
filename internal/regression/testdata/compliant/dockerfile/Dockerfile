FROM alpine:3.20@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
LABEL maintainer="platform@example.com"
WORKDIR /app
COPY app.bin /app/app
USER 10001
HEALTHCHECK --interval=30s --timeout=5s CMD ["/app/app", "health"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/app/app"]
