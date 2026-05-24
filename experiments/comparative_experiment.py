#!/usr/bin/env python3
"""
Сравнительный эксперимент: Direct-ZTNA vs VPN vs Gateway-ZTNA.

Один физический стенд, три архитектурных режима.
Методология согласно Главе 5 ВКР:
  - Reachability (pre/during/post)
  - Lateral movement
  - Negative tests
  - Временные метрики: T_setup, T_revoke, RTT
  - Расчёт AS̅_direct через K_avg (телеметрия)
"""

import asyncio
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))


REPORTS_DIR = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def docker_exec(container: str, cmd: List[str], timeout: int = 30) -> tuple:
    full = ["docker", "exec", container] + cmd
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def now_ms() -> float:
    return time.perf_counter() * 1000


# ---------------------------------------------------------------------------
# Direct-ZTNA
# ---------------------------------------------------------------------------

async def direct_ztna_experiment() -> dict:
    """Run the full Direct-ZTNA experiment via client-01 container."""
    container = "ztna-client-01"
    service = "protected-service-1"
    service2 = "protected-service-2"

    results = {
        "reachability": {},
        "lateral_movement": {},
        "negatives": {},
        "timing": {},
    }

    # --- 1. Reachability: pre-access ---
    rc, _, _ = docker_exec(container, ["curl", "-s", "--connect-timeout", "2",
                                       f"http://172.21.0.50:8000/health"])
    results["reachability"]["pre_access"] = "reachable" if rc == 0 else "unreachable"

    # --- 2. Setup session ---
    t0 = now_ms()
    rc, out, err = docker_exec(
        container,
        ["python", "main.py", "request-access", "--service-id", service],
        timeout=30,
    )
    t1 = now_ms()
    setup_ms = t1 - t0
    jti = None
    for line in out.splitlines():
        if "Ticket received:" in line:
            jti = line.split("Ticket received:")[1].strip()
            break

    results["timing"]["t_setup_ms"] = setup_ms
    results["setup_ok"] = rc == 0 and jti is not None

    # --- 3. Reachability: during session ---
    rc2, _, _ = docker_exec(container, ["curl", "-s", "--connect-timeout", "2",
                                         f"http://172.21.0.50:8000/health"])
    results["reachability"]["during_session"] = "reachable" if rc2 == 0 else "unreachable"

    # --- 4. Lateral movement ---
    rc_lat, _, _ = docker_exec(
        container,
        ["curl", "-s", "--connect-timeout", "2", f"http://172.21.0.51:8000/health"],
    )
    results["lateral_movement"][service2] = "blocked" if rc_lat != 0 else "allowed"

    # --- 5. RTT ---
    rtts = []
    for _ in range(20):
        rc_rtt, out_rtt, _ = docker_exec(
            container,
            ["curl", "-s", "-o", "/dev/null", "-w", "%{time_total}",
             f"http://172.21.0.50:8000/health"],
            timeout=5,
        )
        if rc_rtt == 0:
            rtts.append(float(out_rtt.strip()) * 1000)
    results["timing"]["rtt_ms"] = {
        "mean": round(sum(rtts) / len(rtts), 3) if rtts else None,
        "min": round(min(rtts), 3) if rtts else None,
        "max": round(max(rtts), 3) if rtts else None,
    }

    # --- 6. Revoke ---
    if jti:
        t2 = now_ms()
        docker_exec(container, ["python", "main.py", "revoke-local", "--jti", jti])
        t3 = now_ms()
        results["timing"]["t_revoke_ms"] = t3 - t2

        # --- 7. Reachability: post-revoke ---
        rc3, _, _ = docker_exec(container, ["curl", "-s", "--connect-timeout", "2",
                                             f"http://172.21.0.50:8000/health"])
        results["reachability"]["post_revoke"] = "reachable" if rc3 == 0 else "unreachable"

    # --- 8. Negatives (run inside container via Python one-liners) ---
    # No ticket
    rc_n1, _, _ = docker_exec(
        container, ["curl", "-s", "--connect-timeout", "2", "-o", "/dev/null", "-w", "%{http_code}",
                    f"http://172.21.0.50:8000/health"]
    )
    results["negatives"]["no_ticket"] = "blocked" if rc_n1 != 0 else "allowed"

    return results


# ---------------------------------------------------------------------------
# VPN Baseline
# ---------------------------------------------------------------------------

def vpn_wait_tun_up(container: str, timeout: int = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, _, _ = docker_exec(container, ["ip", "addr", "show", "tun0"])
        if rc == 0:
            return True
        time.sleep(0.2)
    return False


def vpn_wait_tun_down(container: str, timeout: int = 10) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, _, _ = docker_exec(container, ["ip", "addr", "show", "tun0"])
        if rc != 0:
            return True
        time.sleep(0.2)
    return False


async def vpn_experiment() -> dict:
    """Run VPN baseline experiment via ztna-vpn-client."""
    container = "ztna-vpn-client"
    results = {
        "reachability": {},
        "lateral_movement": {},
        "negatives": {},
        "timing": {},
    }

    # Ensure no existing tunnel
    docker_exec(container, ["pkill", "-9", "openvpn"])
    time.sleep(1)

    # --- 1. Reachability: pre-access ---
    rc, _, _ = docker_exec(container, ["ping", "-c", "1", "-W", "2", "172.21.0.50"])
    results["reachability"]["pre_access"] = "reachable" if rc == 0 else "unreachable"

    # --- 2. Setup (connect VPN) ---
    t0 = now_ms()
    docker_exec(container, ["openvpn", "--config", "/etc/openvpn/client.conf", "--daemon"])
    ok = vpn_wait_tun_up(container, timeout=30)
    t1 = now_ms()
    results["timing"]["t_setup_ms"] = t1 - t0
    results["setup_ok"] = ok

    # --- 3. Reachability: during session ---
    rc2, _, _ = docker_exec(container, ["ping", "-c", "1", "-W", "2", "172.21.0.50"])
    results["reachability"]["during_session"] = "reachable" if rc2 == 0 else "unreachable"

    # --- 4. Lateral movement (VPN allows entire subnet) ---
    rc_lat, _, _ = docker_exec(container, ["ping", "-c", "1", "-W", "2", "172.21.0.51"])
    results["lateral_movement"]["protected-service-2"] = "allowed" if rc_lat == 0 else "blocked"

    # --- 5. RTT ---
    rtts = []
    for _ in range(20):
        rc_rtt, out_rtt, _ = docker_exec(
            container,
            ["curl", "-s", "-o", "/dev/null", "-w", "%{time_total}",
             "http://172.21.0.50:8000/health"],
            timeout=5,
        )
        if rc_rtt == 0:
            rtts.append(float(out_rtt.strip()) * 1000)
    results["timing"]["rtt_ms"] = {
        "mean": round(sum(rtts) / len(rtts), 3) if rtts else None,
        "min": round(min(rtts), 3) if rtts else None,
        "max": round(max(rtts), 3) if rtts else None,
    }

    # --- 6. Revoke (disconnect VPN) ---
    t2 = now_ms()
    docker_exec(container, ["pkill", "-TERM", "openvpn"])
    vpn_wait_tun_down(container, timeout=10)
    t3 = now_ms()
    results["timing"]["t_revoke_ms"] = t3 - t2

    # --- 7. Reachability: post-revoke ---
    rc3, _, _ = docker_exec(container, ["ping", "-c", "1", "-W", "2", "172.21.0.50"])
    results["reachability"]["post_revoke"] = "reachable" if rc3 == 0 else "unreachable"

    # --- 8. Negatives (no cert) ---
    # VPN without valid cert cannot connect; we verify by attempting with missing CA
    rc_n1, _, _ = docker_exec(
        container,
        ["openvpn", "--config", "/etc/openvpn/client.conf",
         "--ca", "/dev/null", "--daemon"],
    )
    time.sleep(2)
    rc_n1_check, _, _ = docker_exec(container, ["ip", "addr", "show", "tun0"])
    results["negatives"]["invalid_cert"] = "blocked" if rc_n1_check != 0 else "allowed"
    docker_exec(container, ["pkill", "-9", "openvpn"])

    return results


# ---------------------------------------------------------------------------
# Gateway-ZTNA Baseline
# ---------------------------------------------------------------------------

async def gateway_ztna_experiment() -> dict:
    """Run Gateway-ZTNA baseline experiment against ztna-gateway."""
    gateway_url = "https://gateway-ztna:8443"
    results = {
        "reachability": {},
        "lateral_movement": {},
        "negatives": {},
        "timing": {},
    }

    # Use ztna-client-01 as probing host (has curl and is in data-plane)
    probe_container = "ztna-client-01"

    # --- 1. Reachability: pre-access (no auth) ---
    rc, out, _ = docker_exec(
        probe_container,
        ["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
         f"{gateway_url}/s1/health"],
    )
    results["reachability"]["pre_access"] = "unreachable" if out.strip() == "401" else f"unexpected:{out.strip()}"

    # --- 2. Setup (first authenticated request) ---
    t0 = now_ms()
    rc, out, _ = docker_exec(
        probe_container,
        ["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
         "-u", "alice:alice123", f"{gateway_url}/s1/health"],
    )
    t1 = now_ms()
    results["timing"]["t_setup_ms"] = t1 - t0
    results["setup_ok"] = out.strip() == "200"

    # --- 3. Reachability: during session ---
    rc2, out2, _ = docker_exec(
        probe_container,
        ["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
         "-u", "alice:alice123", f"{gateway_url}/s1/health"],
    )
    results["reachability"]["during_session"] = "reachable" if out2.strip() == "200" else f"unexpected:{out2.strip()}"

    # --- 4. Lateral movement (Gateway allows any path after auth) ---
    rc_lat, out_lat, _ = docker_exec(
        probe_container,
        ["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
         "-u", "alice:alice123", f"{gateway_url}/s2/health"],
    )
    results["lateral_movement"]["protected-service-2"] = (
        "allowed" if out_lat.strip() == "200" else f"unexpected:{out_lat.strip()}"
    )

    # --- 5. RTT ---
    rtts = []
    for _ in range(20):
        rc_rtt, out_rtt, _ = docker_exec(
            probe_container,
            ["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{time_total}",
             "-u", "alice:alice123", f"{gateway_url}/s1/health"],
            timeout=5,
        )
        if rc_rtt == 0:
            rtts.append(float(out_rtt.strip()) * 1000)
    results["timing"]["rtt_ms"] = {
        "mean": round(sum(rtts) / len(rtts), 3) if rtts else None,
        "min": round(min(rtts), 3) if rtts else None,
        "max": round(max(rtts), 3) if rtts else None,
    }

    # --- 6. Revoke (remove user from htpasswd and reload nginx) ---
    t2 = now_ms()
    docker_exec("ztna-gateway", ["sh", "-c", "> /etc/nginx/htpasswd"])
    docker_exec("ztna-gateway", ["nginx", "-s", "reload"])
    # Poll until 401
    revoked = False
    for _ in range(30):
        rc_r, out_r, _ = docker_exec(
            probe_container,
            ["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
             "-u", "alice:alice123", f"{gateway_url}/s1/health"],
        )
        if out_r.strip() == "401":
            revoked = True
            break
        time.sleep(0.2)
    t3 = now_ms()
    results["timing"]["t_revoke_ms"] = t3 - t2
    results["revoke_ok"] = revoked

    # --- 7. Reachability: post-revoke ---
    rc3, out3, _ = docker_exec(
        probe_container,
        ["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
         "-u", "alice:alice123", f"{gateway_url}/s1/health"],
    )
    results["reachability"]["post_revoke"] = "unreachable" if out3.strip() == "401" else f"unexpected:{out3.strip()}"

    # --- 8. Negatives ---
    # Wrong password
    rc_n1, out_n1, _ = docker_exec(
        probe_container,
        ["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
         "-u", "alice:wrongpass", f"{gateway_url}/s1/health"],
    )
    results["negatives"]["wrong_password"] = "blocked" if out_n1.strip() == "401" else f"unexpected:{out_n1.strip()}"

    # No auth
    rc_n2, out_n2, _ = docker_exec(
        probe_container,
        ["curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
         f"{gateway_url}/s1/health"],
    )
    results["negatives"]["no_auth"] = "blocked" if out_n2.strip() == "401" else f"unexpected:{out_n2.strip()}"

    # Restore htpasswd for future runs
    docker_exec("ztna-gateway", ["sh", "-c", "htpasswd -cb /etc/nginx/htpasswd alice alice123"])
    docker_exec("ztna-gateway", ["nginx", "-s", "reload"])

    return results


# ---------------------------------------------------------------------------
# Telemetry: K_avg -> AS̅_direct
# ---------------------------------------------------------------------------

async def fetch_telemetry_k_avg() -> Optional[float]:
    """Fetch K_avg from telemetry server."""
    import httpx
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get("http://localhost:8082/metrics", timeout=5)
            if r.status_code == 200:
                data = r.json()
                return data.get("k_avg")
    except Exception:
        pass
    return None


def compute_as_direct(k_avg: float, u: int, s: int) -> dict:
    """
    Вычисление расчётной метрики AS̅_direct по формулам из Главы 5.
    При подстановке K_avg в модель.
    """
    # Упрощённая формула из методологии:
    # AS̅_direct = K_avg / (|U| × |S|)  (нормализованная доля открытых путей)
    # Для масштабов 10×5, 100×50, 1000×500
    scales = [
        {"u": 10, "s": 5},
        {"u": 100, "s": 50},
        {"u": 1000, "s": 500},
    ]
    results = {}
    for sc in scales:
        as_direct = k_avg / (sc["u"] * sc["s"])
        results[f"{sc['u']}x{sc['s']}"] = round(as_direct, 6)
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main():
    print("=" * 60)
    print("Сравнительный эксперимент: Direct-ZTNA / VPN / Gateway-ZTNA")
    print("=" * 60)

    report = {
        "timestamp": int(time.time()),
        "direct_ztna": {},
        "vpn": {},
        "gateway_ztna": {},
        "as_direct": {},
    }

    # 1. Direct-ZTNA
    print("\n[1/3] Direct-ZTNA ...")
    report["direct_ztna"] = await direct_ztna_experiment()
    print(f"  Setup: {report['direct_ztna']['timing'].get('t_setup_ms', 0):.1f}ms")
    print(f"  Revoke: {report['direct_ztna']['timing'].get('t_revoke_ms', 0):.1f}ms")
    print(f"  RTT: {report['direct_ztna']['timing'].get('rtt_ms', {})}")
    print(f"  Lateral: {report['direct_ztna']['lateral_movement']}")
    print(f"  Reachability: {report['direct_ztna']['reachability']}")

    # 2. VPN
    print("\n[2/3] VPN Baseline ...")
    report["vpn"] = await vpn_experiment()
    print(f"  Setup: {report['vpn']['timing'].get('t_setup_ms', 0):.1f}ms")
    print(f"  Revoke: {report['vpn']['timing'].get('t_revoke_ms', 0):.1f}ms")
    print(f"  RTT: {report['vpn']['timing'].get('rtt_ms', {})}")
    print(f"  Lateral: {report['vpn']['lateral_movement']}")
    print(f"  Reachability: {report['vpn']['reachability']}")

    # 3. Gateway-ZTNA
    print("\n[3/3] Gateway-ZTNA Baseline ...")
    report["gateway_ztna"] = await gateway_ztna_experiment()
    print(f"  Setup: {report['gateway_ztna']['timing'].get('t_setup_ms', 0):.1f}ms")
    print(f"  Revoke: {report['gateway_ztna']['timing'].get('t_revoke_ms', 0):.1f}ms")
    print(f"  RTT: {report['gateway_ztna']['timing'].get('rtt_ms', {})}")
    print(f"  Lateral: {report['gateway_ztna']['lateral_movement']}")
    print(f"  Reachability: {report['gateway_ztna']['reachability']}")

    # Telemetry / AS̅
    print("\n[telemetry] Fetching K_avg ...")
    k_avg = await fetch_telemetry_k_avg()
    if k_avg is not None:
        report["k_avg"] = k_avg
        report["as_direct"] = compute_as_direct(k_avg, u=10, s=5)
        print(f"  K_avg = {k_avg}")
        print(f"  AS̅_direct = {report['as_direct']}")
    else:
        print("  Telemetry unavailable, using default K_avg=1.0")
        report["k_avg"] = 1.0
        report["as_direct"] = compute_as_direct(1.0, u=10, s=5)

    # Save report
    ts = int(time.time())
    path = REPORTS_DIR / f"comparative_experiment_{ts}.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[report] Saved to {path}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
