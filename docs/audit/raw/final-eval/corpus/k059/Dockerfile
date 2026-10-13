FROM ubuntu:latest

RUN apt-get update && apt-get install -y python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app.py .

EXPOSE 8080

CMD ["python3", "app.py"]
