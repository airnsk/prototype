#!/usr/bin/env python3
"""
Эксперимент экспонированности сервисов (Gateway-ZTNA).

Проверяет:
1. Видимость снаружи (из probe-client): gateway TCP, direct TCP/ping к сервисам,
   HTTP через gateway для S1/S2/S3 (без билета, с билетом S1, после отзыва).
2. Lateral movement из инфраструктурного компонента (из gateway-ztna):
   прямой HTTP-доступ к upstream-сервисам (plain HTTP).

Ожидаемое поведение:
- Снаружи: 0 доступных сервисов до/после, 1 сервис (S1) во время сессии.
- Lateral movement: шлюз имеет доступ ко всем 3 сервисам по plain HTTP.
"""

import json
import shlex
import subprocess
import time
from pathlib import Path

REPORT_PATH = Path(__file__).parent / "exposure_report.json"
PROBE = "gateway-probe"
GATEWAY = "gateway-ztna"
GATEWAY_HOST = "gateway-ztna"
GATEWAY_PORT = "8443"

SERVICES = [
    {"id": "protected-service-1", "ip": "172.27.0.50", "port": "8000"},
    {"id": "protected-service-2", "ip": "172.27.0.51", "port": "8000"},
    {"id": "protected-service-3", "ip": "172.27.0.52", "port": "8000"},
]


def docker_exec(container, cmd, timeout=10):
    docker_cmd = shlex.join(["docker", "exec", container] + cmd)
    full = ["sg", "docker", "-c", docker_cmd]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def probe_exposure(label: str, ticket: str = None) -> dict:
    """Probe exposure from probe-client perspective."""
    result = {"label": label}

    # 1. Gateway port visibility (TCP connect)
    rc_gw, _, _ = docker_exec(PROBE, ["nc", "-z", "-w", "2", GATEWAY_HOST, GATEWAY_PORT])
    result["gateway_tcp"] = "open" if rc_gw == 0 else "closed"

    # 2. Direct service visibility and HTTP via gateway for each service
    headers = ["-H", f"Authorization: Bearer {ticket}"] if ticket else []
    for svc in SERVICES:
        svc_id = svc["id"]
        svc_ip = svc["ip"]
        svc_port = svc["port"]

        # Direct TCP (should be closed)
        rc_svc, _, _ = docker_exec(PROBE, ["nc", "-z", "-w", "2", svc_ip, svc_port])
        result[f"{svc_id}_direct_tcp"] = "open" if rc_svc == 0 else "closed"

        # ICMP (should fail)
        rc_ping, _, _ = docker_exec(PROBE, ["ping", "-c", "1", "-W", "2", svc_ip])
        result[f"{svc_id}_ping"] = "reachable" if rc_ping == 0 else "unreachable"

        # HTTP via gateway
        rc_http, out_http, _ = docker_exec(PROBE, [
            "curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
            *headers,
            f"https://{GATEWAY_HOST}:{GATEWAY_PORT}/proxy/{svc_id}/health",
        ], timeout=5)
        result[f"{svc_id}_http_via_gateway"] = out_http.strip() if (rc_http == 0 or out_http.strip()) else "unreachable"

    return result


def count_accessible_services(metrics: dict) -> int:
    """Count services accessible through the gateway (HTTP 200)."""
    count = 0
    for svc in SERVICES:
        code = metrics.get(f"{svc['id']}_http_via_gateway", "")
        if code == "200":
            count += 1
    return count


def probe_lateral_movement() -> dict:
    """Probe access from compromised infrastructure component (gateway-ztna)."""
    result = {}
    for svc in SERVICES:
        svc_id = svc["id"]
        script = f"import urllib.request; r=urllib.request.urlopen('http://{svc_id}:8000/health'); print(r.getcode())"
        rc, out, _ = docker_exec(GATEWAY, ["python3", "-c", script], timeout=5)
        result[f"{svc_id}_from_gateway"] = out.strip() if (rc == 0 and out.strip()) else "unreachable"
    return result


def get_ticket(service_id: str) -> str:
    """Request ticket from controller."""
    script = f"""
import asyncio, json, os, sys, time
sys.path.insert(0, '/app')
from client_agent.idp_client import IdPClient
from client_agent.controller_client import ControllerClient

async def main():
    user_token = os.environ.get('ZTNA_USER_TOKEN')
    idp = IdPClient(base_url='http://mock-idp:8000')
    auth = await idp.authenticate(user_token)
    if not auth:
        print('AUTH_FAILED')
        return
    ctrl = ControllerClient(base_url='http://controller:8000')
    ticket = await ctrl.request_access(user_token, '{service_id}')
    print(json.dumps(ticket))
asyncio.run(main())
"""
    docker_cmd = shlex.join(["docker", "exec", "-i", PROBE, "tee", "/tmp/get_ticket.py"])
    subprocess.run(
        ["sg", "docker", "-c", docker_cmd],
        input=script,
        capture_output=True,
        text=True,
    )
    rc, out, _ = docker_exec(PROBE, ["python3", "/tmp/get_ticket.py"], timeout=30)
    if rc != 0 or not out.strip():
        return None
    try:
        ticket = json.loads(out.strip().splitlines()[-1])
        return json.dumps(ticket)
    except (json.JSONDecodeError, IndexError):
        return None


def main():
    report = {
        "architecture": "Gateway-ZTNA",
        "timestamp": int(time.time()),
        "phases": {},
    }

    print("[Gateway-ZTNA Exposure] Starting...")

    # Phase 1: Before any access
    phase1 = probe_exposure("pre_access")
    report["phases"]["pre_access"] = phase1
    report["phases"]["pre_access"]["accessible_services"] = count_accessible_services(phase1)
    print(f"  Pre-access:  accessible={count_accessible_services(phase1)}  {phase1}")

    # Phase 2: Get ticket and access
    ticket = get_ticket("protected-service-1")
    if not ticket:
        print("  FAILED to get ticket")
        return

    phase2 = probe_exposure("during_session", ticket)
    report["phases"]["during_session"] = phase2
    report["phases"]["during_session"]["accessible_services"] = count_accessible_services(phase2)
    print(f"  During:      accessible={count_accessible_services(phase2)}  {phase2}")

    # Phase 3: Revoke
    ticket_data = json.loads(ticket)
    jti = ticket_data.get("jti", "")
    docker_exec(GATEWAY, [
        "curl", "-s", "-k", "-X", "POST", "http://localhost:8443/admin/revoke",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"jti": jti}),
    ])
    time.sleep(0.5)

    phase3 = probe_exposure("post_revoke")
    report["phases"]["post_revoke"] = phase3
    report["phases"]["post_revoke"]["accessible_services"] = count_accessible_services(phase3)
    print(f"  Post-revoke: accessible={count_accessible_services(phase3)}  {phase3}")

    # Phase 4: Lateral movement from compromised gateway
    lateral = probe_lateral_movement()
    report["lateral_movement_from_gateway"] = lateral
    print(f"  Lateral movement from gateway: {lateral}")

    report["summary"] = {
        "pre_access_accessible": count_accessible_services(phase1),
        "during_accessible": count_accessible_services(phase2),
        "post_revoke_accessible": count_accessible_services(phase3),
        "lateral_movement": lateral,
        "expected": "Gateway-ZTNA: 0 -> 1 (S1 via gateway) -> 0; lateral: 3 services reachable from gateway via plain HTTP",
    }

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[report] Saved to {REPORT_PATH}")


if __name__ == "__main__":
    main()
