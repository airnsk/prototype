"""
Клиентский агент Direct-ZTNA.

CLI для запроса доступа, валидации билетов и активации TUN-шифратора.
Режим daemon предоставляет HTTP API для экспериментов (избегает накладных
расходов docker exec + импорт модулей при каждом прогоне).
"""

import argparse
import asyncio
import json
import subprocess
import sys
import threading
import time
import os

from fastapi import FastAPI
import uvicorn

from client_agent.idp_client import IdPClient
from client_agent.controller_client import ControllerClient
from client_agent.ticket_manager import TicketManager
from client_agent.key_store import KeyStore
from client_agent.tunnel import TunnelClient, stop_daemon, PID_FILE
from client_agent.revoked_cache import RevokedCache
from common.telemetry import emit


def get_user_token() -> str:
    """Получить токен пользователя из env или дефолт."""
    return os.environ.get("ZTNA_USER_TOKEN", "bearer-alice-token-abc123")


def get_user_name() -> str:
    """Получить имя пользователя из env или дефолт."""
    return os.environ.get("ZTNA_USER_NAME", "alice")


async def cmd_request_access(service_id: str, quiet: bool = False):
    user_token = get_user_token()
    user_name = get_user_name()
    t_start = time.perf_counter()
    emit("client", "request", details={"service_id": service_id, "user": user_name})

    # 1. Auth via IdP
    t_idp_0 = time.perf_counter()
    idp = IdPClient()
    auth = await idp.authenticate(user_token)
    t_idp_1 = time.perf_counter()
    if not auth:
        if not quiet:
            print(f"[client-{user_name}] Authentication failed")
        return None, {}
    if not quiet:
        print(f"[client-{user_name}] Authenticated as {auth['sub']}")
        print(f"[phase] T_idp = {(t_idp_1 - t_idp_0) * 1000:.3f} ms")

    # 2. Request ticket from controller
    t_ctrl_0 = time.perf_counter()
    ctrl = ControllerClient()
    ticket_data = await ctrl.request_access(user_token, service_id)
    t_ctrl_1 = time.perf_counter()
    if not ticket_data:
        if not quiet:
            print(f"[client-{user_name}] Access request denied")
        return None, {}

    jti = ticket_data.get("jti")
    if not quiet:
        print(f"[client-{user_name}] Ticket received: {jti}")
        print(f"[phase] T_controller = {(t_ctrl_1 - t_ctrl_0) * 1000:.3f} ms")

    # 3. Validate ticket locally
    t_val_0 = time.perf_counter()
    tm = TicketManager()
    revoked = set()
    valid, reason = tm.validate(ticket_data, revoked)
    t_val_1 = time.perf_counter()
    if not valid:
        if not quiet:
            print(f"[client-{user_name}] Ticket validation failed: {reason}")
        return None, {}
    if not quiet:
        print(f"[client-{user_name}] Ticket signature valid")
        print(f"[phase] T_validate = {(t_val_1 - t_val_0) * 1000:.3f} ms")

    # 4. Check PSK
    ks = KeyStore()
    key_id = ticket_data.get("key_id")
    psk = ks.get(key_id)
    if not psk:
        if not quiet:
            print(f"[client-{user_name}] No PSK for key_id {key_id}")
        return None, {}

    # 5. Activate transport (TUN-forwarder)
    t_tunnel_0 = time.perf_counter()
    transport = ticket_data.get("transport", {})

    # Deactivate previous tunnel if any
    stop_daemon()

    proc = subprocess.Popen(
        [
            "python", "/app/client_agent/tunnel.py",
            "--endpoint", transport["endpoint"],
            "--key", psk,
            "--allowed-ips", ",".join(transport["allowed_ips"]),
        ],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Reap the child to avoid zombies
    threading.Thread(target=proc.wait, daemon=True).start()
    t_tunnel_1 = time.perf_counter()

    emit("client", "first_data", ticket_id=jti)
    if not quiet:
        print(f"[client-{user_name}] Access granted. Tunnel active for service {service_id}")
        print(f"[phase] T_tunnel = {(t_tunnel_1 - t_tunnel_0) * 1000:.3f} ms")
        t_total = (t_tunnel_1 - t_start) * 1000
        print(f"[phase] T_setup_total = {t_total:.3f} ms")
        print(f"[client-{user_name}] Ticket expires at {ticket_data['exp']} (in {ticket_data['exp'] - int(time.time())} seconds)")

    phases = {
        "T_idp": round((t_idp_1 - t_idp_0) * 1000, 3),
        "T_controller": round((t_ctrl_1 - t_ctrl_0) * 1000, 3),
        "T_validate": round((t_val_1 - t_val_0) * 1000, 3),
        "T_tunnel": round((t_tunnel_1 - t_tunnel_0) * 1000, 3),
        "T_setup_total": round((t_tunnel_1 - t_start) * 1000, 3),
    }
    return ticket_data, phases


async def cmd_revoke_local(jti: str, quiet: bool = False):
    """Локальная деактивация (для тестов отзыва)."""
    user_name = get_user_name()
    stop_daemon()
    emit("client", "traffic_stop", ticket_id=jti)
    if not quiet:
        print(f"[client-{user_name}] Local tunnel deactivated for {jti}")


# --- Daemon mode (FastAPI) ---
app_daemon = FastAPI()

@app_daemon.get("/request-access")
async def api_request_access(service_id: str):
    ticket, phases = await cmd_request_access(service_id, quiet=True)
    if ticket:
        ticket["_phases"] = phases
        return {"ok": True, "ticket": ticket}
    return {"ok": False}


@app_daemon.get("/revoke-local")
async def api_revoke_local(jti: str):
    await cmd_revoke_local(jti, quiet=True)
    return {"ok": True}


def run_daemon():
    uvicorn.run(app_daemon, host="0.0.0.0", port=9000, log_level="warning")


def main():
    parser = argparse.ArgumentParser(description="Direct-ZTNA Client Agent")
    subparsers = parser.add_subparsers(dest="command")

    req = subparsers.add_parser("request-access", help="Request access to a service")
    req.add_argument("--service-id", required=True, help="Target service ID")

    rev = subparsers.add_parser("revoke-local", help="Locally deactivate tunnel")
    rev.add_argument("--jti", required=True, help="Ticket JTI")

    daemon = subparsers.add_parser("daemon", help="Run HTTP daemon for experiments")

    args = parser.parse_args()

    if args.command == "request-access":
        asyncio.run(cmd_request_access(args.service_id))
    elif args.command == "revoke-local":
        asyncio.run(cmd_revoke_local(args.jti))
    elif args.command == "daemon":
        run_daemon()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
