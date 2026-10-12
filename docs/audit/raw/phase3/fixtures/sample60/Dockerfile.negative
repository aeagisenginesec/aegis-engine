# Phase 3 sample-60 NEGATIVE Dockerfile fixtures (fixed).
FROM ubuntu:22.04
LABEL maintainer="p3@example.com"
LABEL org.opencontainers.image.authors="p3@example.com"
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
COPY pkg.tar.gz /tmp/
RUN apt-get update && apt-get install -y --no-install-recommends curl
RUN apk add --no-cache curl
