FROM ubuntu:latest

RUN useradd --create-home --uid 10001 appuser

WORKDIR /app
COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8080

CMD ["./start.sh"]
