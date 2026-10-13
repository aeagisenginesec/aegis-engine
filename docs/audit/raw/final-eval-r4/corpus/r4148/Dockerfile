# R4 project r4148
FROM python:3.11.9-slim-bookworm
RUN apt-get update && apt-get install -y curl git strace
WORKDIR /app
COPY --chown=app:app . .
RUN useradd -m app
USER app
HEALTHCHECK --interval=30s CMD python -c "print(1)"
CMD ["python", "app.py"]
