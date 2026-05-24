"""
Серверный агент Direct-ZTNA.

FastAPI-приложение, принимающее команды от контроллера:
- POST /activate — добавить peer (запустить/обновить TUN-forwarder)
- POST /revoke — удалить peer
- GET /health — health-check
"""

from fastapi import FastAPI
from pydantic import BaseModel

from common import config
from common.telemetry import emit
from server_agent.key_store import KeyStore
from server_agent.ticket_validator import TicketValidator
from server_agent.tunnel import TunnelServer
from server_agent.session_monitor import SessionMonitor
from server_agent.revoked_cache import RevokedCache

app = FastAPI(title="Direct-ZTNA Server Agent")

# --- Components ---
_keystore = KeyStore()
_validator = TicketValidator()
_tunnel_server = TunnelServer(listen_port=51820, tun_dev="tun0", tun_ip="10.200.200.1/24")
_revoked_cache = RevokedCache()
_session_monitor = SessionMonitor(check_interval=10)

_active_sessions: dict = {}  # jti -> {key_id, exp, service_id}


def _on_session_expire(jti: str):
    """Callback при истечении срока сессии."""
    info = _active_sessions.pop(jti, None)
    if info:
        _tunnel_server.remove_peer(info["key_id"])
        emit("server", "traffic_stop", ticket_id=jti, details={"reason": "expired"})


@app.on_event("startup")
async def startup():
    _tunnel_server.start()
    _revoked_cache.start()
    _session_monitor.set_on_expire(_on_session_expire)
    _session_monitor.start()
    print("[server] Server agent started. TUN-forwarder active on port 51820.")


@app.on_event("shutdown")
async def shutdown():
    _tunnel_server.stop()
    _revoked_cache.stop()
    _session_monitor.stop()


# --- API Models ---
class ActivateBody(BaseModel):
    ticket: dict


class RevokeBody(BaseModel):
    jti: str


# --- Endpoints ---
@app.post("/activate")
async def activate(body: ActivateBody):
    ticket = body.ticket
    jti = ticket.get("jti", "")

    # 1. Validate ticket
    valid, reason = _validator.validate(ticket, _revoked_cache.all_revoked())
    if not valid:
        emit("server", "peer_add_denied", ticket_id=jti, details={"reason": reason})
        return {"status": "denied", "reason": reason}

    # 2. Check key
    key_id = ticket.get("key_id", "")
    psk = _keystore.get(key_id)
    if not psk:
        return {"status": "denied", "reason": f"No PSK for key_id {key_id}"}

    # 3. Add peer to TUN-forwarder
    allowed_ips = ticket["transport"]["allowed_ips"]

    _tunnel_server.add_peer(key_id, psk, allowed_ips)
    exp = ticket.get("exp", 0)
    svc = ticket.get("service_id", "")
    _active_sessions[jti] = {"key_id": key_id, "exp": exp, "service_id": svc}
    _session_monitor.add_session(jti, exp)
    emit("server", "peer_add", ticket_id=jti)
    return {"status": "activated", "jti": jti}


@app.post("/revoke")
async def revoke(body: RevokeBody):
    jti = body.jti
    _revoked_cache.add(jti)

    info = _active_sessions.pop(jti, None)
    if info:
        _tunnel_server.remove_peer(info["key_id"])
        _session_monitor.remove_session(jti)

    emit("server", "traffic_stop", ticket_id=jti, details={"reason": "revoked"})
    return {"status": "revoked", "jti": jti}


@app.get("/health")
async def health():
    return {"status": "ok", "node": config.NODE_NAME, "peers": len(_tunnel_server.list_peers())}
