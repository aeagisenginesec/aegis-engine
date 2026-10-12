# Phase 3 sample-60 POSITIVE Dockerfile fixtures (violating).
# AEGIS-DOCKER-023: SHELL without pipefail
# AEGIS-DOCKER-016: Deprecated MAINTAINER instruction
# AEGIS-DOCKER-020: VOLUME declared in image
# AEGIS-DOCKER-004: ADD used instead of COPY
# AEGIS-DOCKER-007: apt-get install without --no-install-recommends
# AEGIS-DOCKER-030: apk add without --no-cache
FROM ubuntu:22.04
MAINTAINER p3@example.com
SHELL ["/bin/bash", "-c"]
ADD https://example.com/pkg.tar.gz /tmp/
VOLUME /data
RUN apt-get update && apt-get install -y curl
RUN apk add curl
