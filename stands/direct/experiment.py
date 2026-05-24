#!/usr/bin/env python3
"""
Эксперимент Direct-ZTNA стенда.

Стенд: client-agent (только control-plane) → server-agent (control+data) → protected-service (data-plane).
Измерения: T_setup, T_revoke, RTT, reachability, lateral movement, negatives.

Оптимизации измерений (vs docker exec + python):
- T_setup: вызов долгоживущего daemon через HTTP API (curl), избегая ~800 ms
  накладных расходов docker exec + импорт модулей.
- T_revoke: активный polling до недоступности сервиса вместо фиксированного sleep(0.5).
"""

import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

REPORT_PATH = Path(__file__).parent / "report.json"

CLIENT = "direct-client"
SERVER = "direct-server"
CONTROLLER = "direct-controller"
SERVICE_URL_S1 = "http://172.23.0.50:8000/health"
SERVICE_URL_S2 = "http://172.23.0.51:8000/health"
SERVICE_URL_S3 = "http://172.23.0.52:8000/health"
CLIENT_DAEMON_URL = "http://direct-client:9000"


def docker_exec(container, cmd, timeout=30):
    docker_cmd = shlex.join(["docker", "exec", container] + cmd)
    full = ["sg", "docker", "-c", docker_cmd]
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


def curl_to_container(container, url, timeout=5):
    """Выполняет curl изнутри контейнера. Возвращает (http_code, time_total)."""
    rc, out, _ = docker_exec(container, [
        "curl", "-s", "-o", "/dev/null",
        "-w", "%{http_code},%{time_total}",
        "--connect-timeout", str(timeout),
        url,
    ], timeout=timeout + 2)
    if rc == 0 and out.strip():
        parts = out.strip().split(",")
        if len(parts) == 2:
            return parts[0].strip(), float(parts[1].strip())
    return "000", None


def curl_client_daemon(endpoint, timeout=30):
    """Вызов HTTP API клиентского агента изнутри direct-client контейнера."""
    return docker_exec(CLIENT, [
        "curl", "-s", "-m", str(timeout), endpoint,
    ], timeout=timeout + 5)


def now_ms():
    return time.perf_counter() * 1000


def wait_until_unreachable(container, url, max_wait_ms=5000, poll_interval_ms=50):
    """Активный polling до тех пор, пока curl не вернёт 000 (недоступно).
    Выполняет loop внутри контейнера одним docker exec вызовом для минимальных
    накладных расходов."""
    iterations = max_wait_ms // poll_interval_ms
    sleep_s = poll_interval_ms / 1000.0
    script_lines = [
        "#!/bin/sh",
        f"for i in $(seq 1 {iterations}); do",
        f"  code=$(curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 0.1 --max-time 0.1 '{url}')",
        '  if [ "$code" = "000" ]; then echo "ok"; exit 0; fi',
        f"  sleep {sleep_s}",
        "done",
        'echo "timeout"',
    ]
    script = "\n".join(script_lines)
    # Write script via docker cp to avoid shell quoting issues
    import tempfile, subprocess
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write(script)
        tmp_path = f.name
    try:
        subprocess.run(["sg", "docker", "-c", f"docker cp {tmp_path} {container}:/tmp/poll.sh"], check=True, capture_output=True)
        rc, out, _ = docker_exec(container, ["sh", "/tmp/poll.sh"], timeout=max_wait_ms / 1000.0 + 5)
        return out.strip() == "ok"
    finally:
        os.unlink(tmp_path)


def main():
    report = {
        "architecture": "Direct-ZTNA",
        "timestamp": int(time.time()),
        "reachability": {},
        "timing": {},
        "lateral_movement": {},
        "negatives": {},
    }

    print("[Direct-ZTNA] Starting experiment...")

    # Cleanup any leftover tunnel from previous runs
    curl_client_daemon(f"{CLIENT_DAEMON_URL}/revoke-local?jti=cleanup")
    time.sleep(0.3)

    # 1. Pre-access reachability (no session → unreachable)
    code, _ = curl_to_container(CLIENT, SERVICE_URL_S1, timeout=2)
    report["reachability"]["pre_access"] = "blocked" if code == "000" else f"unexpected:{code}"
    print(f"  Pre-access: {report['reachability']['pre_access']}")

    # 2. Setup (request ticket + activate) через daemon API
    t0 = now_ms()
    rc, out, err = curl_client_daemon(
        f"{CLIENT_DAEMON_URL}/request-access?service_id=protected-service-1"
    )
    t1 = now_ms()
    setup_ms = t1 - t0
    jti = None
    phases = {}
    if rc == 0:
        try:
            resp = json.loads(out)
            if resp.get("ok"):
                ticket = resp["ticket"]
                jti = ticket.get("jti")
                # Извлекаем фазы из ответа (если daemon их возвращает),
                # иначе используем wall-clock как fallback
                phases = ticket.get("_phases", {})
        except json.JSONDecodeError:
            pass

    report["timing"]["t_setup_ms"] = round(setup_ms, 3)
    report["timing"]["t_setup_phases"] = phases
    report["setup_ok"] = rc == 0 and jti is not None
    print(f"  Setup: {setup_ms:.1f}ms  jti={jti}  ok={report['setup_ok']}")

    # Give tunnel a moment to bring up tun0 and routes
    time.sleep(0.15)

    # 3. During-session reachability (via TUN tunnel) — S1
    code2, _ = curl_to_container(CLIENT, SERVICE_URL_S1, timeout=5)
    report["reachability"]["during_session"] = "reachable" if code2 == "200" else f"unexpected:{code2}"
    print(f"  During-session: {report['reachability']['during_session']}")

    # 4. Lateral movement: S2 and S3 must be blocked (microsegmentation /32)
    code_s2, _ = curl_to_container(CLIENT, SERVICE_URL_S2, timeout=2)
    code_s3, _ = curl_to_container(CLIENT, SERVICE_URL_S3, timeout=2)
    report["lateral_movement"] = {
        "service_2": "blocked" if code_s2 == "000" else f"unexpected:{code_s2}",
        "service_3": "blocked" if code_s3 == "000" else f"unexpected:{code_s3}",
    }
    print(f"  Lateral movement: {report['lateral_movement']}")

    # 5. RTT (20 runs via TUN tunnel)
    rtts = []
    for i in range(20):
        code_rtt, t_total = curl_to_container(CLIENT, SERVICE_URL_S1, timeout=5)
        if t_total is not None:
            rtts.append(t_total * 1000)
    report["timing"]["rtt_ms"] = {
        "mean": round(sum(rtts) / len(rtts), 3) if rtts else None,
        "min": round(min(rtts), 3) if rtts else None,
        "max": round(max(rtts), 3) if rtts else None,
    }
    print(f"  RTT: {report['timing']['rtt_ms']}")

    # 6. Revoke (локально + контроллер), затем активный polling
    if jti:
        t2 = now_ms()
        # Локальная деактивация через daemon API
        t_local_0 = now_ms()
        curl_client_daemon(f"{CLIENT_DAEMON_URL}/revoke-local?jti={jti}")
        t_local_1 = now_ms()
        # Уведомление контроллера
        t_ctrl_0 = now_ms()
        docker_exec(CONTROLLER, [
            "curl", "-s", "-X", "POST", "http://localhost:8000/revoke",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({"jti": jti}),
        ])
        t_ctrl_1 = now_ms()
        # Активный polling до недоступности (вместо фиксированного sleep)
        t_poll_0 = now_ms()
        reached = wait_until_unreachable(CLIENT, SERVICE_URL_S1, max_wait_ms=5000, poll_interval_ms=10)
        t_poll_1 = now_ms()
        t3 = now_ms()
        report["timing"]["t_revoke_ms"] = round(t3 - t2, 3)
        report["timing"]["t_revoke_phases"] = {
            "T_revoke_local": round(t_local_1 - t_local_0, 3),
            "T_controller_revoke": round(t_ctrl_1 - t_ctrl_0, 3),
            "T_polling": round(t_poll_1 - t_poll_0, 3),
        }
        report["revoke_reached"] = reached
        print(f"  Revoke: {report['timing']['t_revoke_ms']:.1f}ms  reached={reached}")
        print(f"    phases: {report['timing']['t_revoke_phases']}")

        # 7. Post-revoke reachability
        code3, _ = curl_to_container(CLIENT, SERVICE_URL_S1, timeout=2)
        report["reachability"]["post_revoke"] = "blocked" if code3 == "000" else f"unexpected:{code3}"
        print(f"  Post-revoke: {report['reachability']['post_revoke']}")

    # 8. Negatives
    report["negatives"]["no_ticket"] = report["reachability"]["pre_access"]
    report["negatives"]["expired_ticket"] = "not_tested"

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[report] Saved to {REPORT_PATH}")
    return report


if __name__ == "__main__":
    main()
