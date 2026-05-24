#!/usr/bin/env python3
"""
Эксперимент Gateway-ZTNA стенда (полноценный ZTNA с билетами).

Flow: probe-client → IdP auth → Controller ticket → Gateway proxy → service.
Сопоставим с Direct-ZTNA: разница только в том, что вместо TUN-шифратора
используется HTTP-прокси с предъявлением билета.
"""

import json
import shlex
import subprocess
import time
from pathlib import Path
from typing import Optional

REPORT_PATH = Path(__file__).parent / "report.json"
PROBE = "gateway-probe"
GATEWAY = "gateway-ztna"
CONTROLLER = "gateway-ctrl"


def docker_exec(container, cmd, timeout=30):
    docker_cmd = shlex.join(["docker", "exec", container] + cmd)
    full = ["sg", "docker", "-c", docker_cmd]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def now_ms():
    return time.perf_counter() * 1000


def get_ticket(service_id: str) -> tuple[Optional[str], float, str]:
    """Request ticket via curl (avoids Python import overhead)."""
    phases = {}
    out_lines = []

    # 1. Auth via IdP
    t_idp_0 = now_ms()
    rc, out, _ = docker_exec(PROBE, [
        "curl", "-s", "-X", "POST",
        "http://mock-idp:8000/auth",
        "-H", "Authorization: Bearer bearer-user01-token-85421c1a4d5a0b18",
    ])
    t_idp_1 = now_ms()
    phases["T_idp"] = t_idp_1 - t_idp_0
    if rc != 0 or not out.strip():
        return None, 0.0, ""

    # 2. Request ticket from controller
    t_ctrl_0 = now_ms()
    rc, out, _ = docker_exec(PROBE, [
        "curl", "-s", "-X", "POST",
        "http://controller:8000/access",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"user_token": "bearer-user01-token-85421c1a4d5a0b18", "service_id": service_id}),
    ])
    t_ctrl_1 = now_ms()
    phases["T_controller"] = t_ctrl_1 - t_ctrl_0
    phases["T_total"] = t_ctrl_1 - t_idp_0
    if rc != 0 or not out.strip():
        return None, 0.0, ""

    ticket_json = out.strip()
    # Verify it's valid JSON
    try:
        json.loads(ticket_json)
    except json.JSONDecodeError:
        return None, 0.0, ""

    phase_lines = "\n".join(f"[phase] {k} = {v:.3f} ms" for k, v in phases.items())
    return ticket_json, phases["T_total"], phase_lines


def main():
    report = {
        "architecture": "Gateway-ZTNA (full ZTNA)",
        "timestamp": int(time.time()),
        "reachability": {},
        "timing": {},
        "lateral_movement": {},
        "negatives": {},
    }

    print("[Gateway-ZTNA] Starting experiment...")

    # 1. Pre-access (no ticket)
    rc, out, _ = docker_exec(PROBE, [
        "curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
        "https://gateway-ztna:8443/proxy/protected-service-1/health",
    ])
    report["reachability"]["pre_access"] = "blocked" if out.strip() == "401" else f"unexpected:{out.strip()}"
    print(f"  Pre-access: {report['reachability']['pre_access']}")

    # 2. Setup: IdP → Controller → Ticket → First proxy request
    ticket_s1, ticket_ms, ticket_out = get_ticket("protected-service-1")
    phases = {}
    for line in (ticket_out or "").splitlines():
        if "[phase]" in line:
            key, val = line.replace("[phase] ", "").split(" = ")
            phases[key.strip()] = float(val.replace(" ms", "").strip())

    if not ticket_s1:
        print("  FAILED to get ticket for S1")
        report["setup_ok"] = False
    else:
        # First request with ticket = T_setup complete
        t0 = now_ms()
        rc, out, _ = docker_exec(PROBE, [
            "curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
            "-H", f"Authorization: Bearer {ticket_s1}",
            "https://gateway-ztna:8443/proxy/protected-service-1/health",
        ])
        t1 = now_ms()
        phases["T_tls_proxy"] = t1 - t0
        report["timing"]["t_setup_ms"] = round(ticket_ms + (t1 - t0), 3)
        report["timing"]["t_setup_phases"] = phases
        report["setup_ok"] = out.strip() == "200"
        print(f"  Setup: {report['timing']['t_setup_ms']:.1f}ms  ok={report['setup_ok']}")

    # 3. During-session
    rc2, out2, _ = docker_exec(PROBE, [
        "curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
        "-H", f"Authorization: Bearer {ticket_s1}",
        "https://gateway-ztna:8443/proxy/protected-service-1/health",
    ])
    report["reachability"]["during_session"] = "reachable" if out2.strip() == "200" else f"unexpected:{out2.strip()}"
    print(f"  During-session: {report['reachability']['during_session']}")

    # 4. Lateral movement (ticket for S1, request to S2 and S3)
    rc_lat2, out_lat2, _ = docker_exec(PROBE, [
        "curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
        "-H", f"Authorization: Bearer {ticket_s1}",
        "https://gateway-ztna:8443/proxy/protected-service-2/health",
    ])
    rc_lat3, out_lat3, _ = docker_exec(PROBE, [
        "curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
        "-H", f"Authorization: Bearer {ticket_s1}",
        "https://gateway-ztna:8443/proxy/protected-service-3/health",
    ])
    report["lateral_movement"]["protected-service-2"] = "blocked" if out_lat2.strip() == "403" else f"unexpected:{out_lat2.strip()}"
    report["lateral_movement"]["protected-service-3"] = "blocked" if out_lat3.strip() == "403" else f"unexpected:{out_lat3.strip()}"
    print(f"  Lateral movement: {report['lateral_movement']}")

    # 5. RTT (20 runs with ticket)
    rtts = []
    for _ in range(20):
        rc_rtt, out_rtt, _ = docker_exec(PROBE, [
            "curl", "-s", "-k", "-o", "/dev/null", "-w", "%{time_total}",
            "-H", f"Authorization: Bearer {ticket_s1}",
            "https://gateway-ztna:8443/proxy/protected-service-1/health",
        ], timeout=5)
        if out_rtt.strip():
            rtts.append(float(out_rtt.strip()) * 1000)
    report["timing"]["rtt_ms"] = {
        "mean": round(sum(rtts) / len(rtts), 3) if rtts else None,
        "min": round(min(rtts), 3) if rtts else None,
        "max": round(max(rtts), 3) if rtts else None,
    }
    print(f"  RTT: {report['timing']['rtt_ms']}")

    # 6. Revoke (call controller revoke + notify gateway)
    t2 = now_ms()
    ticket_data = json.loads(ticket_s1)
    jti = ticket_data.get("jti", "")
    docker_exec(CONTROLLER, [
        "curl", "-s", "-k", "-X", "POST", "http://localhost:8000/revoke",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"jti": jti}),
    ])
    docker_exec(PROBE, [
        "curl", "-s", "-k", "-k", "-X", "POST", "https://gateway-ztna:8443/admin/revoke",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"jti": jti}),
    ])
    # Poll until 401
    revoked = False
    for _ in range(30):
        rc_r, out_r, _ = docker_exec(PROBE, [
            "curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
            "-H", f"Authorization: Bearer {ticket_s1}",
            "https://gateway-ztna:8443/proxy/protected-service-1/health",
        ])
        if out_r.strip() == "401":
            revoked = True
            break
        time.sleep(0.2)
    t3 = now_ms()
    report["timing"]["t_revoke_ms"] = round(t3 - t2, 3)
    report["revoke_ok"] = revoked
    print(f"  Revoke: {report['timing']['t_revoke_ms']:.1f}ms  ok={revoked}")

    # 7. Post-revoke
    rc3, out3, _ = docker_exec(PROBE, [
        "curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
        "-H", f"Authorization: Bearer {ticket_s1}",
        "https://gateway-ztna:8443/proxy/protected-service-1/health",
    ])
    report["reachability"]["post_revoke"] = "blocked" if out3.strip() == "401" else f"unexpected:{out3.strip()}"
    print(f"  Post-revoke: {report['reachability']['post_revoke']}")

    # 8. Negatives
    # No ticket
    rc_n1, out_n1, _ = docker_exec(PROBE, [
        "curl", "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}",
        "https://gateway-ztna:8443/proxy/protected-service-1/health",
    ])
    report["negatives"]["no_ticket"] = "blocked" if out_n1.strip() == "401" else f"unexpected:{out_n1.strip()}"

    # Wrong service (already tested by lateral movement)
    report["negatives"]["wrong_service"] = report["lateral_movement"]["protected-service-2"]

    # Expired — not tested in single run
    report["negatives"]["expired_ticket"] = "not_tested"
    print(f"  Negatives: {report['negatives']}")

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[report] Saved to {REPORT_PATH}")
    return report


if __name__ == "__main__":
    main()
