"""
Mock IdP для прототипа Direct-ZTNA.

Простейший сервис аутентификации: Bearer-токен → идентификатор пользователя.
"""

import json
import os

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

app = FastAPI(title="Mock IdP")

_USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")
_users_data = {}


@app.on_event("startup")
async def startup():
    global _users_data
    if os.path.exists(_USERS_FILE):
        with open(_USERS_FILE, "r", encoding="utf-8") as f:
            _users_data = json.load(f)
    else:
        _users_data = {"users": {}, "bearer_tokens": {}}


class AuthResponse(BaseModel):
    sub: str
    attrs: dict


@app.post("/auth", response_model=AuthResponse)
async def authenticate(authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization

    # Reverse lookup: token -> username
    username = None
    for user, t in _users_data.get("bearer_tokens", {}).items():
        if t == token:
            username = user
            break

    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_info = _users_data.get("users", {}).get(username, {})
    return AuthResponse(sub=username, attrs=user_info.get("attrs", {}))


@app.get("/health")
async def health():
    return {"status": "ok", "node": "mock-idp"}
