"""
Защищаемый сервис для экспериментального стенда.

Может работать как S1, S2 или S3 в зависимости от переменной окружения SERVICE_ID.
"""

import os
from fastapi import FastAPI

service_id = os.environ.get("SERVICE_ID", "protected-service-1")

app = FastAPI(title=f"Protected Service ({service_id})")


@app.get("/")
async def root():
    return {"status": "ok", "service": service_id}


@app.get("/api/data")
async def api_data():
    return {"data": f"sensitive-info-from-{service_id}", "service": service_id}


@app.get("/health")
async def health():
    return {"status": "ok", "service": service_id}
