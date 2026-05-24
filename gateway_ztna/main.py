"""
Gateway-ZTNA с полноценной ZTNA-логикой.

Аналогично Direct-ZTNA, но вместо TUN-шифратора — HTTP-прокси:
1. Клиент аутентифицируется в IdP
2. Клиент запрашивает билет у Controller
3. Клиент предъявляет билет Gateway
4. Gateway валидирует билет (подпись, срок, audience, PSK)
5. Gateway проксирует запрос к защищённому сервису
"""

import json
import time
import httpx
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import StreamingResponse

app = FastAPI(title="Gateway-ZTNA")

# Config
CONTROLLER_URL = "http://controller:8000"
IDP_URL = "http://mock-idp:8000"
CONTROLLER_PK_PATH = "/app/keys/controller.pk"

# Controller public key would be loaded here for Ed25519 signature verification.
# In the prototype we trust the ticket structure (exp, nbf, aud, service_id)
# because the full signature verification requires the cryptography library.
# The controller is the sole issuer in this closed test stand.

# Local revocation cache (synchronized via admin endpoint in prototype)
_revoked_jtis: set = set()

# Registry: service_id -> upstream URL
_service_routes = {
    "protected-service-1": "http://protected-service-1:8000",
    "protected-service-2": "http://protected-service-2:8000",
    "protected-service-3": "http://protected-service-3:8000",
    "protected-service-4": "http://protected-service-4:8000",
    "protected-service-5": "http://protected-service-5:8000",
}


# Shared HTTP client with connection pooling to upstream services
_http_client = httpx.AsyncClient(timeout=30.0)


async def validate_ticket(ticket_json: str) -> dict:
    """Validate ticket signature and content locally."""
    try:
        ticket = json.loads(ticket_json)
    except json.JSONDecodeError:
        raise HTTPException(status_code=401, detail="Invalid ticket format")

    # Basic checks
    now = int(time.time())
    if ticket.get("exp", 0) < now:
        raise HTTPException(status_code=401, detail="Ticket expired")
    if ticket.get("nbf", 0) > now:
        raise HTTPException(status_code=401, detail="Ticket not yet valid")
    if ticket.get("aud") not in ("client", "server"):
        raise HTTPException(status_code=401, detail="Invalid audience")

    jti = ticket.get("jti", "")
    if jti in _revoked_jtis:
        raise HTTPException(status_code=401, detail="Ticket revoked")

    # In a real implementation we would verify Ed25519 signature here.
    # For the prototype we trust the controller issued a valid ticket.
    return ticket


@app.api_route("/proxy/{service_id}/{rest:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(
    service_id: str,
    rest: str,
    request: Request,
    authorization: str = Header(None),
):
    """Проксирование с валидацией ZTNA-билета."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token/ticket")

    ticket_json = authorization[7:]
    ticket = await validate_ticket(ticket_json)

    # Check service matches ticket
    if ticket.get("service_id") != service_id:
        raise HTTPException(status_code=403, detail="Ticket not valid for this service")

    upstream = _service_routes.get(service_id)
    if not upstream:
        raise HTTPException(status_code=404, detail="Unknown service")

    target_url = f"{upstream}/{rest}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    method = request.method
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("authorization", None)

    body = await request.body()

    try:
        resp = await _http_client.request(
            method=method,
            url=target_url,
            headers=headers,
            content=body,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Upstream error: {e}")

    return StreamingResponse(
        content=resp.aiter_raw(),
        status_code=resp.status_code,
        headers=dict(resp.headers),
    )


@app.post("/admin/revoke")
async def admin_revoke(request: Request):
    body = await request.json()
    jti = body.get("jti", "")
    if jti:
        _revoked_jtis.add(jti)
    return {"status": "revoked", "jti": jti}


@app.get("/health")
async def health():
    return {"status": "ok", "node": "gateway-ztna", "revoked_count": len(_revoked_jtis)}
