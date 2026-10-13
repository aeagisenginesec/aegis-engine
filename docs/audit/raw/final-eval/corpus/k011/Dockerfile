FROM ubuntu:22.04

RUN apt-get update && apt-get install -y curl ca-certificates \
    && curl -fsSL https://get.example-tool.io/install.sh | bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /data
COPY config.yaml .

EXPOSE 8080 8443

CMD ["/usr/local/bin/example-tool", "serve", "--config", "/data/config.yaml"]
