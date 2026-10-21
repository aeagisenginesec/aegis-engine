FROM python:3.11.9-slim-bookworm

RUN useradd --create-home --uid 10001 appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8000

CMD ["python", "server.py"]
