"""
Оркестратор эксперимента Direct-ZTNA.

Запускает сценарии для измерения T_setup, T_revoke, RTT и видимости сервисов.
"""

import time
import json
import sys
from pathlib import Path

import httpx

from experiments.probes import http_probe, ping_probe
from experiments.analysis import generate_report, save_report

CONTROLLER_URL = "http://localhost:8080"
TELEMETRY_URL = "http://localhost:8082"
GATEWAY_URL = "https://localhost:8443"
PROTECTED_URL = "http://localhost:8090"
ALICE_TOKEN = "bearer-alice-token-abc123"


def clear_telemetry():
    try:
        httpx.post(f"{TELEMETRY_URL}/clear", timeout=2)
    except Exception:
        pass


def fetch_telemetry() -> list:
    try:
        resp = httpx.get(f"{TELEMETRY_URL}/report", timeout=5)
        return resp.json().get("events", [])
    except Exception as e:
        print(f"[runner] Telemetry fetch failed: {e}")
        return []


def run_direct_ztna_scenario():
    """Сценарий Direct-ZTNA: запрос доступа + revoke."""
    print("\n=== Direct-ZTNA Scenario ===")
    clear_telemetry()
    
    # 1. Запрос доступа (через контроллер)
    resp = httpx.post(
        f"{CONTROLLER_URL}/access",
        json={"user_token": ALICE_TOKEN, "service_id": "protected-service-1"},
        timeout=10,
    )
    if resp.status_code != 200:
        print(f"[runner] Access request failed: {resp.status_code}")
        return
    
    ticket = resp.json()
    jti = ticket["jti"]
    print(f"[runner] Ticket issued: {jti}")
    
    time.sleep(0.5)
    
    # 2. HTTP проба через Gateway (или напрямую, если WG настроен)
    # Для простоты проверяем доступность защищаемого сервиса
    probe = http_probe(f"{PROTECTED_URL}/health")
    print(f"[runner] Protected service probe: {probe}")
    
    # 3. Revoke
    time.sleep(0.5)
    revoke_resp = httpx.post(
        f"{CONTROLLER_URL}/revoke",
        json={"jti": jti},
        timeout=5,
    )
    print(f"[runner] Revoke status: {revoke_resp.status_code}")
    
    time.sleep(0.5)
    
    # 4. Сбор и анализ
    events = fetch_telemetry()
    report = generate_report(events, num_users=1, num_services=1)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    
    # 5. Сохранение
    out_dir = Path(__file__).parent / "reports"
    out_dir.mkdir(exist_ok=True)
    save_report(report, out_dir / "direct_ztna_report.json")
    print(f"[runner] Report saved to {out_dir / 'direct_ztna_report.json'}")


def run_gateway_ztna_scenario():
    """Сценарий Gateway-ZTNA: доступ через nginx reverse proxy."""
    print("\n=== Gateway-ZTNA Scenario ===")
    clear_telemetry()
    
    start = time.time()
    probe = http_probe(f"{GATEWAY_URL}/health", auth=("alice", "alice123"), verify_ssl=False)
    latency = (time.time() - start) * 1000
    
    print(f"[runner] Gateway probe: {probe}")
    print(f"[runner] Total latency: {latency:.2f} ms")
    
    # Gateway-ZTNA не имеет встроенной телеметрии в нашем прототипе,
    # поэтому сохраняем только результаты проб
    report = {
        "mode": "gateway-ztna",
        "probe": probe,
        "total_latency_ms": round(latency, 2),
    }
    
    out_dir = Path(__file__).parent / "reports"
    out_dir.mkdir(exist_ok=True)
    save_report(report, out_dir / "gateway_ztna_report.json")
    print(f"[runner] Report saved to {out_dir / 'gateway_ztna_report.json'}")


def main():
    print("Direct-ZTNA Experiment Runner")
    print("==============================")
    
    run_direct_ztna_scenario()
    run_gateway_ztna_scenario()
    
    print("\n=== Experiment Complete ===")


if __name__ == "__main__":
    main()
