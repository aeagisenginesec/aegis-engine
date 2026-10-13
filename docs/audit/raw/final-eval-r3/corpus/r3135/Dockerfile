FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://example.com/install.sh | bash
WORKDIR /app
COPY . .
RUN useradd -m app && chown -R app /app
USER app
HEALTHCHECK CMD true
CMD ["./run.sh"]
