#!/usr/bin/env python3
"""
Эксперимент экспонированности сервисов (VPN).

Проверяет:
1. Видимость снаружи (из vpn-client): ping, TCP-connect, HTTP к S1/S2/S3
   до туннеля, во время туннеля, после отключения.
2. Lateral movement из инфраструктурного компонента (из vpn-server):
   прямой доступ к сервисам в data-plane.

Ожидаемое поведение:
- Снаружи: 0 -> 3 -> 0 доступных сервисов.
- Lateral movement: VPN-сервер имеет доступ ко всем 3 сервисам.
"""

import json
import shlex
import subprocess
import time
from pathlib import Path

REPORT_PATH = Path(__file__).parent / "exposure_report.json"
CLIENT = "vpn-client"
SERVER = "vpn-server"

SERVICES = [
    {"id": "protected-service-1", "ip": "172.25.0.50", "port": "8000"},
    {"id": "protected-service-2", "ip": "172.25.0.51", "port": "8000"},
    {"id": "protected-service-3", "ip": "172.25.0.52", "port": "8000"},
]


def docker_exec(container, cmd, timeout=10):
    docker_cmd = shlex.join(["docker", "exec", container] + cmd)
    full = ["sg", "docker", "-c", docker_cmd]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def probe_exposure(label: str) -> dict:
    """Probe exposure from vpn-client perspective."""
    result = {"label": label}

    for svc in SERVICES:
        svc_id = svc["id"]
        svc_ip = svc["ip"]
        svc_port = svc["port"]

        # ICMP ping
        rc_ping, _, _ = docker_exec(CLIENT, ["ping", "-c", "1", "-W", "2", svc_ip])
        result[f"{svc_id}_ping"] = "reachable" if rc_ping == 0 else "unreachable"

        # TCP connect
        rc_tcp, _, _ = docker_exec(CLIENT, ["nc", "-z", "-w", "2", svc_ip, svc_port])
        result[f"{svc_id}_tcp_connect"] = "open" if rc_tcp == 0 else "closed"

        # HTTP request
        rc_http, out_http, _ = docker_exec(CLIENT, [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            f"http://{svc_ip}:{svc_port}/health",
        ], timeout=5)
        result[f"{svc_id}_http"] = out_http.strip() if rc_http == 0 else "unreachable"

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
    """Probe access from compromised infrastructure component (vpn-server)."""
    result = {}
    for svc in SERVICES:
        svc_id = svc["id"]
        svc_ip = svc["ip"]
        rc, out, _ = docker_exec(SERVER, [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            f"http://{svc_ip}:8000/health",
        ], timeout=5)
        result[f"{svc_id}_from_vpn_server"] = out.strip() if (rc == 0 or out.strip()) else "unreachable"
    return result


def wait_tun_up(timeout=30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, _, _ = docker_exec(CLIENT, ["ip", "addr", "show", "tun0"])
        if rc == 0:
            return True
        time.sleep(0.2)
    return False


def wait_tun_down(timeout=10) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, _, _ = docker_exec(CLIENT, ["ip", "addr", "show", "tun0"])
        if rc != 0:
            return True
        time.sleep(0.2)
    return False


def main():
    report = {
        "architecture": "VPN",
        "timestamp": int(time.time()),
        "phases": {},
    }

    print("[VPN Exposure] Starting...")

    # Ensure clean state
    docker_exec(CLIENT, ["pkill", "-9", "openvpn"])
    time.sleep(1)

    # Phase 1: Before VPN
    phase1 = probe_exposure("pre_access")
    report["phases"]["pre_access"] = phase1
    report["phases"]["pre_access"]["accessible_services"] = count_accessible_services(phase1)
    print(f"  Pre-access:  accessible={count_accessible_services(phase1)}  {phase1}")

    # Phase 2: Connect VPN
    docker_exec(CLIENT, ["openvpn", "--config", "/etc/openvpn/client.conf", "--daemon"])
    ok = wait_tun_up(timeout=30)
    if not ok:
        print("  FAILED to connect VPN")
        return

    phase2 = probe_exposure("during_session")
    report["phases"]["during_session"] = phase2
    report["phases"]["during_session"]["accessible_services"] = count_accessible_services(phase2)
    print(f"  During:      accessible={count_accessible_services(phase2)}  {phase2}")

    # Phase 3: Disconnect VPN
    docker_exec(CLIENT, ["pkill", "-TERM", "openvpn"])
    wait_tun_down(timeout=10)
    time.sleep(0.5)

    phase3 = probe_exposure("post_revoke")
    report["phases"]["post_revoke"] = phase3
    report["phases"]["post_revoke"]["accessible_services"] = count_accessible_services(phase3)
    print(f"  Post-revoke: accessible={count_accessible_services(phase3)}  {phase3}")

    # Phase 4: Lateral movement from compromised VPN server
    lateral = probe_lateral_movement()
    report["lateral_movement_from_vpn_server"] = lateral
    print(f"  Lateral movement from VPN server: {lateral}")

    report["summary"] = {
        "pre_access_accessible": count_accessible_services(phase1),
        "during_accessible": count_accessible_services(phase2),
        "post_revoke_accessible": count_accessible_services(phase3),
        "lateral_movement": lateral,
        "expected": "VPN: 0 -> 3 (all subnet visible) -> 0; lateral: 3 services reachable from vpn-server",
    }

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[report] Saved to {REPORT_PATH}")


if __name__ == "__main__":
    main()
