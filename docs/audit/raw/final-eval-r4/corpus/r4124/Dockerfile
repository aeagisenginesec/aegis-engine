# R4 project r4124
FROM python:3.15.2-slim-bookworm
WORKDIR /app
COPY . .
RUN useradd -m app
USER app
HEALTHCHECK --interval=30s CMD python -c "print(1)"
CMD ["python", "app.py"]
