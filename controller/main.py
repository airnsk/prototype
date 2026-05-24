"""
Контроллер доступа (Policy Decision Point) для Direct-ZTNA.

FastAPI-приложение, реализующее:
- POST /access — запрос билета (auth → policy → issue → notify server)
- POST /revoke — отзыв доступа
- GET /revoked — список отозванных jti
- GET /health — health-check
"""

import os
import time
import json
from typing import Set, Dict, Any

import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel

from common.models import AccessTicket, TransportProfile, RevokeCommand
from common import config
from common.crypto import load_private_key, sign_ticket
from common.telemetry import emit
from controller.auth import authenticate_user
from controller.policy_engine import check_policy

app = FastAPI(title="Direct-ZTNA Controller")

# --- Загрузка состояния ---
_controller_sk = None
_registry: Dict[str, Any] = {}
_revoked: Set[str] = set()
_issued_tickets: Dict[str, AccessTicket] = {}


def _load_keys():
    global _controller_sk
    if os.path.exists(config.CONTROLLER_SK_PATH):
        _controller_sk = load_private_key(config.CONTROLLER_SK_PATH)
    else:
        raise RuntimeError(f"Controller private key not found at {config.CONTROLLER_SK_PATH}")


def _load_registry():
    global _registry
    if os.path.exists(config.CONTROLLER_REGISTRY_PATH):
        with open(config.CONTROLLER_REGISTRY_PATH, "r", encoding="utf-8") as f:
            _registry = json.load(f)
    else:
        _registry = {"services": {}, "agents": {}}


@app.on_event("startup")
async def startup():
    _load_keys()
    _load_registry()
    print("[controller] Started, keys loaded.")


# --- API Models ---
class AccessRequestBody(BaseModel):
    user_token: str
    service_id: str


class RevokeRequestBody(BaseModel):
    jti: str
    reason: str = "admin_revoke"


# --- Helpers ---
async def _notify_server_activate(ticket: AccessTicket) -> bool:
    """Отправить серверному агенту команду на активацию peer."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{config.SERVER_CONTROLLER_URL}/activate",
                json={"ticket": ticket.to_dict()},
                timeout=5.0,
            )
            return response.status_code == 200
    except Exception as e:
        print(f"[controller] Failed to notify server agent: {e}")
        return False


# --- Endpoints ---
@app.post("/access")
async def access_request(body: AccessRequestBody, background: BackgroundTasks):
    emit("controller", "request", details={"service_id": body.service_id})

    # 1. Аутентификация через IdP
    idp_result = await authenticate_user(body.user_token)
    if not idp_result:
        raise HTTPException(status_code=401, detail="Authentication failed")

    sub = idp_result["sub"]
    attrs = idp_result.get("attrs", {})
    emit("controller", "auth_done", details={"sub": sub})

    # 2. Policy-check
    allowed, reason = check_policy(sub, attrs, body.service_id, _registry)
    if not allowed:
        raise HTTPException(status_code=403, detail=f"Access denied: {reason}")

    emit("controller", "policy_done", details={"sub": sub, "service_id": body.service_id})

    # 3. Формирование билета
    service_info = _registry.get("services", {}).get(body.service_id)
    now = int(time.time())
    ttl = 300  # 5 minutes ticket TTL

    transport = TransportProfile(
        endpoint=service_info["endpoint"],
        allowed_ips=service_info["allowed_ips"],
    )

    ticket = AccessTicket(
        iss="ztna-controller",
        aud="client",
        sub=sub,
        service_id=body.service_id,
        jti=f"{sub}-{body.service_id}-{now}-{os.urandom(4).hex()}",
        nbf=now,
        iat=now,
        exp=now + ttl,
        key_id=f"psk-{sub}-{body.service_id}",
        transport=transport,
        scope="tcp:443",
    )

    payload = ticket.payload_dict()
    ticket.sig = sign_ticket(payload, _controller_sk)

    _issued_tickets[ticket.jti] = ticket
    emit("controller", "ticket_issued", ticket_id=ticket.jti)

    # 4. Уведомление серверного агента (async in background)
    # Для прототипа делаем синхронно, чтобы клиент получил билет только после готовности сервера
    print(f"[controller] Notifying server-agent for ticket {ticket.jti} ...")
    try:
        ticket_dict = ticket.to_dict()
        print(f"[controller] Ticket dict ready, calling activate ...")
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "http://server-agent:8000/activate",
                json={"ticket": ticket_dict},
                timeout=5.0,
            )
        print(f"[controller] Activate response: {r.status_code}")
        emit("controller", "peer_add", ticket_id=ticket.jti)
    except Exception as e:
        print(f"[controller] Server-agent notification failed: {e}")
        import traceback
        traceback.print_exc()
        # Не блокируем выдачу билета, но логируем

    return ticket.to_dict()


@app.post("/revoke")
async def revoke_request(body: RevokeRequestBody):
    _revoked.add(body.jti)
    emit("controller", "revoke_cmd", ticket_id=body.jti, details={"reason": body.reason})

    # Уведомить серверный агент
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                "http://server-agent:8000/revoke",
                json={"jti": body.jti},
                timeout=5.0,
            )
    except Exception as e:
        print(f"[controller] Server-agent revoke notification failed: {e}")

    return {"status": "revoked", "jti": body.jti}


@app.get("/revoked")
async def get_revoked():
    return {"revoked": list(_revoked)}


@app.get("/health")
async def health():
    return {"status": "ok", "node": config.NODE_NAME}
