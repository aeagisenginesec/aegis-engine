FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
EXPOSE 8080
