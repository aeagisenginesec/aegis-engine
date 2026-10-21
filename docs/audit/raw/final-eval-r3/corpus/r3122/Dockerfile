FROM python:3.11.9-slim-bookworm
WORKDIR /app
COPY . .
RUN useradd -m app && chown -R app /app
USER app
EXPOSE 8000
CMD ["python", "app.py"]
