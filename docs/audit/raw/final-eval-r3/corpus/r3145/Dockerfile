FROM python:3.15.2-slim-bookworm
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=app:app . .
RUN useradd -m app
USER app
EXPOSE 8000
CMD ["python", "app.py"]
