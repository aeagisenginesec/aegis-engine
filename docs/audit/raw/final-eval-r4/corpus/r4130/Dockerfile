# R4 project r4130
FROM python:3.11-slim
WORKDIR /app
ADD https://example.com/releases/agent-2.4.1.tar.gz /tmp/
RUN tar -xzf /tmp/agent-2.4.1.tar.gz -C /opt && rm /tmp/agent-2.4.1.tar.gz
COPY . .
RUN useradd -m app && chown -R app /app
USER app
HEALTHCHECK CMD curl -f http://localhost:8000/health || exit 1
CMD ["python", "app.py"]
