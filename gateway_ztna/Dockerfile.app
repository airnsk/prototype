FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common/ ./common/
COPY gateway_ztna/main.py ./gateway_ztna/main.py

WORKDIR /app/gateway_ztna

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8443", "--ssl-keyfile", "/app/certs/server.key", "--ssl-certfile", "/app/certs/server.crt"]
