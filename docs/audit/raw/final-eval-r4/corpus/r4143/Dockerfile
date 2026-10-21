# R4 project r4143
FROM python:3.11.9-slim-bookworm
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=app:app . .
RUN useradd -m app
USER app
HEALTHCHECK --interval=30s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"
EXPOSE 8000
CMD ["python", "app.py"]
