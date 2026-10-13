FROM python:3.11-slim

ENV DATABASE_URL="postgres://admin:P@ssw0rd123@db.internal:5432/appdb"
ENV STRIPE_API_KEY="sk_live_51H7xYzAbCdEfGhIjKlMnOp"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 8000
CMD ["python", "server.py"]
