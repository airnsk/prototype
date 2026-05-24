#!/usr/bin/env python3
"""
Эксперимент экспонированности сервисов (Direct-ZTNA).

Проверяет:
1. Видимость снаружи (из direct-client): ping, TCP-connect, HTTP к S1/S2/S3
   до доступа, во время TUN-сессии, после отзыва.
2. Lateral movement из инфраструктурного компонента (из direct-controller):
   прямой доступ к сервисам в data-plane.

Ожидаемое поведение:
- Снаружи: 0 -> 1 (только S1) -> 0 доступных сервисов.
- Lateral movement: контроллер не имеет доступа к сервисам (нет PSK/TUN).
"""

import json
import os
import shlex
import subprocess
import tempfile
import time
from pathlib import Path

REPORT_PATH = Path(__file__).parent / "exposure_report.json"
CLIENT = "direct-client"
CONTROLLER = "direct-controller"
CLIENT_DAEMON_URL = "http://direct-client:9000"

SERVICES = [
    {"id": "protected-service-1", "ip": "172.23.0.50", "port": "8000"},
    {"id": "protected-service-2", "ip": "172.23.0.51", "port": "8000"},
    {"id": "protected-service-3", "ip": "172.23.0.52", "port": "8000"},
]


def docker_exec(container, cmd, timeout=10):
    docker_cmd = shlex.join(["docker", "exec", container] + cmd)
    full = ["sg", "docker", "-c", docker_cmd]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def curl_client_daemon(endpoint, timeout=30):
    """Вызов HTTP API клиентского агента изнутри direct-client контейнера."""
    return docker_exec(CLIENT, [
        "curl", "-s", "-m", str(timeout), endpoint,
    ], timeout=timeout + 5)


def probe_services(label: str) -> dict:
    """Probe services from client-agent (via TUN tunnel when active)."""
    result = {"label": label}

    for svc in SERVICES:
        svc_id = svc["id"]
        svc_ip = svc["ip"]
        svc_port = svc["port"]

        # ICMP ping
        rc_ping, _, _ = docker_exec(CLIENT, ["ping", "-c", "1", "-W", "2", svc_ip])
        result[f"{svc_id}_ping"] = "unreachable" if rc_ping != 0 else "reachable"

        # TCP connect
        rc_tcp, _, _ = docker_exec(CLIENT, ["nc", "-z", "-w", "2", svc_ip, svc_port])
        result[f"{svc_id}_tcp_connect"] = "refused/timeout" if rc_tcp != 0 else "open"

        # HTTP request
        rc_http, out_http, _ = docker_exec(CLIENT, [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--connect-timeout", "3",
            f"http://{svc_ip}:{svc_port}/health",
        ], timeout=5)
        result[f"{svc_id}_http"] = out_http.strip() if (rc_http == 0 or out_http.strip()) else "unreachable"

    return result


def count_accessible_services(metrics: dict) -> int:
    """Count services reachable via HTTP (HTTP 200)."""
    count = 0
    for svc in SERVICES:
        code = metrics.get(f"{svc['id']}_http", "")
        if code == "200":
            count += 1
    return count


def probe_lateral_movement() -> dict:
    """Probe access from compromised infrastructure component (direct-controller)."""
    result = {}
    for svc in SERVICES:
        svc_id = svc["id"]
        svc_ip = svc["ip"]
        rc, out, _ = docker_exec(CONTROLLER, [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--connect-timeout", "3",
            f"http://{svc_ip}:8000/health",
        ], timeout=5)
        result[f"{svc_id}_from_controller"] = out.strip() if (rc == 0 or out.strip()) else "unreachable"
    return result


def wait_until_unreachable(max_wait_ms=5000, poll_interval_ms=50):
    """Активный polling до тех пор, пока HTTP к S1 не вернёт 000.
    Выполняет loop внутри контейнера одним docker exec вызовом."""
    url = f"http://{SERVICES[0]['ip']}:{SERVICES[0]['port']}/health"
    iterations = max_wait_ms // poll_interval_ms
    sleep_s = poll_interval_ms / 1000.0
    script_lines = [
        "#!/bin/sh",
        f"for i in $(seq 1 {iterations}); do",
        f"  code=$(curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 1 --max-time 1 '{url}')",
        '  if [ "$code" = "000" ]; then echo "ok"; exit 0; fi',
        f"  sleep {sleep_s}",
        "done",
        'echo "timeout"',
    ]
    script = "\n".join(script_lines)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write(script)
        tmp_path = f.name
    try:
        subprocess.run(["sg", "docker", "-c", f"docker cp {tmp_path} {CLIENT}:/tmp/poll.sh"], check=True, capture_output=True)
        rc, out, _ = docker_exec(CLIENT, ["sh", "/tmp/poll.sh"], timeout=max_wait_ms / 1000.0 + 5)
        return out.strip() == "ok"
    finally:
        os.unlink(tmp_path)


def main():
    report = {
        "architecture": "Direct-ZTNA",
        "timestamp": int(time.time()),
        "phases": {},
    }

    print("[Direct-ZTNA Exposure] Starting...")

    # Cleanup any leftover tunnel from previous runs
    curl_client_daemon(f"{CLIENT_DAEMON_URL}/revoke-local?jti=cleanup")
    time.sleep(0.3)

    # Phase 1: Before any access
    phase1 = probe_services("pre_access")
    report["phases"]["pre_access"] = phase1
    report["phases"]["pre_access"]["accessible_services"] = count_accessible_services(phase1)
    print(f"  Pre-access:  accessible={count_accessible_services(phase1)}  {phase1}")

    # Phase 2: Request access (setup TUN tunnel) через daemon API
    rc, out, _ = curl_client_daemon(f"{CLIENT_DAEMON_URL}/request-access?service_id=protected-service-1")
    jti = None
    if rc == 0:
        try:
            resp = json.loads(out)
            if resp.get("ok"):
                jti = resp["ticket"].get("jti")
        except json.JSONDecodeError:
            pass

    if rc != 0 or not jti:
        print("  FAILED to setup access")
        return

    # After setup: service should be reachable via TUN tunnel
    phase2 = probe_services("during_session")
    report["phases"]["during_session"] = phase2
    report["phases"]["during_session"]["accessible_services"] = count_accessible_services(phase2)
    print(f"  During:      accessible={count_accessible_services(phase2)}  {phase2}")

    # Phase 3: Revoke через daemon API + контроллер, затем polling
    curl_client_daemon(f"{CLIENT_DAEMON_URL}/revoke-local?jti={jti}")
    docker_exec(CONTROLLER, [
        "curl", "-s", "-X", "POST", "http://localhost:8000/revoke",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"jti": jti}),
    ])
    reached = wait_until_unreachable(max_wait_ms=5000, poll_interval_ms=10)
    print(f"  Revoke polling reached={reached}")

    phase3 = probe_services("post_revoke")
    report["phases"]["post_revoke"] = phase3
    report["phases"]["post_revoke"]["accessible_services"] = count_accessible_services(phase3)
    print(f"  Post-revoke: accessible={count_accessible_services(phase3)}  {phase3}")

    # Phase 4: Lateral movement from compromised controller
    lateral = probe_lateral_movement()
    report["lateral_movement_from_controller"] = lateral
    print(f"  Lateral movement from controller: {lateral}")

    # Summary
    report["summary"] = {
        "pre_access_accessible": count_accessible_services(phase1),
        "during_accessible": count_accessible_services(phase2),
        "post_revoke_accessible": count_accessible_services(phase3),
        "lateral_movement": lateral,
        "expected": "Direct-ZTNA: 0 -> 1 (S1 via TUN) -> 0; lateral: 0 services reachable from controller",
    }

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[report] Saved to {REPORT_PATH}")


if __name__ == "__main__":
    main()
