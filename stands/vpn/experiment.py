#!/usr/bin/env python3
"""
Эксперимент VPN стенда.

Стенд: vpn-client (control-plane) → vpn-server (control+data) → protected-service (data-plane).
"""

import json
import shlex
import subprocess
import time
from pathlib import Path

REPORT_PATH = Path(__file__).parent / "report.json"
CLIENT = "vpn-client"


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


def wait_tun_up(timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, _, _ = docker_exec(CLIENT, ["ip", "addr", "show", "tun0"])
        if rc == 0:
            return True
        time.sleep(0.2)
    return False


def wait_tun_down(timeout=10):
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
        "reachability": {},
        "timing": {},
        "lateral_movement": {},
        "negatives": {},
    }

    print("[VPN] Starting experiment...")

    # Ensure clean state
    docker_exec(CLIENT, ["pkill", "-9", "openvpn"])
    time.sleep(1)

    # 1. Pre-access (no VPN)
    rc, _, _ = docker_exec(CLIENT, ["ping", "-c", "1", "-W", "2", "172.25.0.50"])
    report["reachability"]["pre_access"] = "unreachable" if rc != 0 else "unexpected_reachable"
    print(f"  Pre-access: {report['reachability']['pre_access']}")

    # 2. Setup (connect VPN)
    t0 = now_ms()
    docker_exec(CLIENT, ["openvpn", "--config", "/etc/openvpn/client.conf", "--daemon"])
    ok = wait_tun_up(timeout=30)
    t1 = now_ms()
    report["timing"]["t_setup_ms"] = round(t1 - t0, 3)
    report["setup_ok"] = ok
    print(f"  Setup: {report['timing']['t_setup_ms']:.1f}ms  ok={ok}")

    # 3. During-session
    rc2, _, _ = docker_exec(CLIENT, ["ping", "-c", "1", "-W", "2", "172.25.0.50"])
    report["reachability"]["during_session"] = "reachable" if rc2 == 0 else "unexpected_unreachable"
    print(f"  During-session: {report['reachability']['during_session']}")

    # 4. Lateral movement (VPN gives access to whole subnet — S1, S2, S3)
    rc_lat1, _, _ = docker_exec(CLIENT, ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                                      "http://172.25.0.50:8000/health"])
    rc_lat2, _, _ = docker_exec(CLIENT, ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                                      "http://172.25.0.51:8000/health"])
    rc_lat3, _, _ = docker_exec(CLIENT, ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                                      "http://172.25.0.52:8000/health"])
    report["lateral_movement"]["protected-service-1"] = "allowed" if rc_lat1 == 0 else "blocked"
    report["lateral_movement"]["protected-service-2"] = "allowed" if rc_lat2 == 0 else "blocked"
    report["lateral_movement"]["protected-service-3"] = "allowed" if rc_lat3 == 0 else "blocked"
    print(f"  Lateral movement: {report['lateral_movement']}")

    # 5. RTT
    rtts = []
    for _ in range(20):
        rc_rtt, out_rtt, _ = docker_exec(CLIENT, [
            "curl", "-s", "-o", "/dev/null", "-w", "%{time_total}",
            "http://172.25.0.50:8000/health",
        ], timeout=5)
        if rc_rtt == 0:
            rtts.append(float(out_rtt.strip()) * 1000)
    report["timing"]["rtt_ms"] = {
        "mean": round(sum(rtts) / len(rtts), 3) if rtts else None,
        "min": round(min(rtts), 3) if rtts else None,
        "max": round(max(rtts), 3) if rtts else None,
    }
    print(f"  RTT: {report['timing']['rtt_ms']}")

    # 6. Revoke (disconnect)
    t2 = now_ms()
    docker_exec(CLIENT, ["pkill", "-TERM", "openvpn"])
    wait_tun_down(timeout=10)
    t3 = now_ms()
    report["timing"]["t_revoke_ms"] = round(t3 - t2, 3)
    print(f"  Revoke: {report['timing']['t_revoke_ms']:.1f}ms")

    # 7. Post-revoke
    rc3, _, _ = docker_exec(CLIENT, ["ping", "-c", "1", "-W", "2", "172.25.0.50"])
    report["reachability"]["post_revoke"] = "unreachable" if rc3 != 0 else "unexpected_reachable"
    print(f"  Post-revoke: {report['reachability']['post_revoke']}")

    # 8. Negatives (invalid cert)
    docker_exec(CLIENT, ["pkill", "-9", "openvpn"])
    time.sleep(1)
    docker_exec(CLIENT, [
        "openvpn", "--config", "/etc/openvpn/client.conf",
        "--ca", "/dev/null", "--daemon",
    ])
    time.sleep(2)
    rc_n, _, _ = docker_exec(CLIENT, ["ip", "addr", "show", "tun0"])
    report["negatives"]["invalid_cert"] = "blocked" if rc_n != 0 else "allowed"
    docker_exec(CLIENT, ["pkill", "-9", "openvpn"])
    print(f"  Negatives: {report['negatives']}")

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[report] Saved to {REPORT_PATH}")
    return report


if __name__ == "__main__":
    main()
