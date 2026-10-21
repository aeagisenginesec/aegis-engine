FROM debian:bookworm-20240904-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends dumb-init \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/tmp && chown appuser:appuser /app/tmp

WORKDIR /app
COPY --chown=appuser:appuser bin/worker /app/worker

USER 10001

ENV TMPDIR=/app/tmp

ENTRYPOINT ["dumb-init", "--"]
CMD ["/app/worker"]
