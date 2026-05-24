"""
Полный цикл эксперимента Direct-ZTNA по методике главы 5.

Включает 7 шагов для каждого архитектурного режима:
1. Проверка экспонированности ДО доступа
2. Установление доступа
3. Проверка экспонированности ВО ВРЕМЯ сессии
4. Проверка горизонтального перемещения (S1→S2→S3)
5. Негативные тесты
6. Отзыв доступа
7. Проверка экспонированности ПОСЛЕ отзыва
"""

import time
import json
import sys
from pathlib import Path

import httpx

from experiments.probes import http_probe, nmap_probe
from experiments.analysis import generate_report, save_report

CONTROLLER_URL = "http://localhost:8080"
TELEMETRY_URL = "http://localhost:8082"
GATEWAY_URL = "https://localhost:8443"
ALICE_TOKEN = "bearer-alice-token-abc123"

SERVICES = {
    "S1": {"id": "protected-service-1", "port": "8090", "url": "http://localhost:8090"},
    "S2": {"id": "protected-service-2", "port": "8091", "url": "http://localhost:8091"},
    "S3": {"id": "protected-service-3", "port": "8092", "url": "http://localhost:8092"},
}


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
        print(f"[exp] Telemetry fetch failed: {e}")
        return []


def print_section(title: str):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def run_step_1_pre_access():
    """Шаг 1: Проверка экспонированности ДО получения доступа."""
    print_section("Шаг 1: Экспонированность ДО доступа")
    results = {}

    for name, svc in SERVICES.items():
        # nmap scan
        nmap = nmap_probe("localhost", svc["port"])
        # curl probe
        curl = http_probe(f"{svc['url']}/health", timeout=2)

        results[name] = {
            "nmap_open_ports": nmap.get("open_ports", []),
            "curl_reachable": curl["reachable"],
            "curl_status": curl.get("status_code"),
        }
        print(f"  {name}: nmap={nmap.get('open_ports')}, curl_reachable={curl['reachable']}")

    return results


def run_step_2_establish_access(service_id: str = "protected-service-1"):
    """Шаг 2: Установление доступа (Direct-ZTNA)."""
    print_section("Шаг 2: Установление доступа (Direct-ZTNA)")
    clear_telemetry()

    resp = httpx.post(
        f"{CONTROLLER_URL}/access",
        json={"user_token": ALICE_TOKEN, "service_id": service_id},
        timeout=10,
    )
    if resp.status_code != 200:
        print(f"  FAILED: {resp.status_code} {resp.text}")
        return None

    ticket = resp.json()
    jti = ticket["jti"]
    print(f"  Ticket issued: {jti}")
    time.sleep(0.5)
    return ticket


def run_step_3_during_session():
    """Шаг 3: Проверка экспонированности ВО ВРЕМЯ активной сессии."""
    print_section("Шаг 3: Экспонированность ВО ВРЕМЯ сессии")
    results = {}

    for name, svc in SERVICES.items():
        curl = http_probe(f"{svc['url']}/health", timeout=2)
        results[name] = {
            "curl_reachable": curl["reachable"],
            "curl_status": curl.get("status_code"),
            "latency_ms": curl.get("latency_ms"),
        }
        print(f"  {name}: reachable={curl['reachable']}, latency={curl.get('latency_ms')} ms")

    return results


def run_step_4_horizontal_movement():
    """Шаг 4: Проверка горизонтального перемещения S1→S2→S3."""
    print_section("Шаг 4: Горизонтальное перемещение")
    results = {}

    for name, svc in SERVICES.items():
        resp = httpx.post(
            f"{CONTROLLER_URL}/access",
            json={"user_token": ALICE_TOKEN, "service_id": svc["id"]},
            timeout=10,
        )
        ok = resp.status_code == 200
        results[name] = {
            "access_granted": ok,
            "status_code": resp.status_code,
        }
        print(f"  {name} ({svc['id']}): granted={ok}, status={resp.status_code}")
        if ok:
            # Revoke immediately to clean up
            ticket = resp.json()
            httpx.post(f"{CONTROLLER_URL}/revoke", json={"jti": ticket["jti"]}, timeout=5)

    return results


def run_step_5_negative_tests():
    """Шаг 5: Негативные тесты."""
    print_section("Шаг 5: Негативные тесты")
    results = {}

    # N4: Просроченный билет
    from client_agent.ticket_manager import TicketManager
    from common.crypto import load_private_key, sign_ticket
    from common.models import AccessTicket, TransportProfile
    import time as time_mod

    past = int(time_mod.time()) - 100
    expired = AccessTicket(
        iss="ztna-controller", aud="client", sub="alice",
        service_id="protected-service-1", jti="expired-test",
        nbf=past-200, iat=past-200, exp=past,
        key_id="psk-alice-protected-service-1",
        transport=TransportProfile(server_pubkey="pk", endpoint="e", allowed_ips=["10.0.0.1/32"]),
        scope="tcp:443",
    )
    sk = load_private_key("keys/controller.sk")
    expired.sig = sign_ticket(expired.payload_dict(), sk)
    tm = TicketManager(controller_pk_path="keys/controller.pk")
    valid, reason = tm.validate(expired.to_dict(), set())
    results["N4_expired_ticket"] = {"passed": not valid, "reason": reason}
    print(f"  N4 (expired ticket): blocked={not valid}, reason={reason}")

    # N2: Чужой билет (wrong audience)
    ticket_resp = httpx.post(
        f"{CONTROLLER_URL}/access",
        json={"user_token": ALICE_TOKEN, "service_id": "protected-service-1"},
        timeout=10,
    )
    if ticket_resp.status_code == 200:
        ticket = ticket_resp.json()
        ticket["aud"] = "server"
        payload = {k: v for k, v in ticket.items() if k != "sig"}
        ticket["sig"] = sign_ticket(payload, sk)
        valid2, reason2 = tm.validate(ticket, set())
        results["N2_wrong_audience"] = {"passed": not valid2, "reason": reason2}
        print(f"  N2 (wrong audience): blocked={not valid2}, reason={reason2}")

    return results


def run_step_6_revoke(ticket: dict):
    """Шаг 6: Отзыв доступа."""
    print_section("Шаг 6: Отзыв доступа")
    jti = ticket["jti"]

    resp = httpx.post(
        f"{CONTROLLER_URL}/revoke",
        json={"jti": jti},
        timeout=5,
    )
    print(f"  Revoke status: {resp.status_code}")
    time.sleep(0.5)

    # Calculate T_revoke from telemetry
    events = fetch_telemetry()
    from experiments.analysis import calc_t_revoke
    t_revoke = calc_t_revoke(events, jti)
    if t_revoke:
        print(f"  T_revoke: {t_revoke} ms")
    return {"revoked": resp.status_code == 200, "T_revoke_ms": t_revoke}


def run_step_7_post_revoke():
    """Шаг 7: Проверка экспонированности ПОСЛЕ отзыва."""
    print_section("Шаг 7: Экспонированность ПОСЛЕ отзыва")
    results = {}

    for name, svc in SERVICES.items():
        curl = http_probe(f"{svc['url']}/health", timeout=2)
        results[name] = {
            "curl_reachable": curl["reachable"],
            "curl_status": curl.get("status_code"),
        }
        print(f"  {name}: reachable={curl['reachable']}")

    return results


def run_full_experiment():
    """Полный цикл эксперимента для Direct-ZTNA."""
    print("="*60)
    print("  ПОЛНЫЙ ЦИКЛ ЭКСПЕРИМЕНТА (Direct-ZTNA)")
    print("="*60)

    # Шаг 1
    pre = run_step_1_pre_access()

    # Шаг 2
    ticket = run_step_2_establish_access("protected-service-1")
    if not ticket:
        print("[exp] ABORT: cannot establish access")
        return

    # Шаг 3
    during = run_step_3_during_session()

    # Шаг 4
    horizontal = run_step_4_horizontal_movement()

    # Шаг 5
    negative = run_step_5_negative_tests()

    # Шаг 6
    revoke = run_step_6_revoke(ticket)

    # Шаг 7
    post = run_step_7_post_revoke()

    # Сбор отчёта
    events = fetch_telemetry()
    report = generate_report(events, num_users=1, num_services=3)

    full_report = {
        "mode": "direct-ztna",
        "step_1_pre_access": pre,
        "step_3_during_session": during,
        "step_4_horizontal_movement": horizontal,
        "step_5_negative_tests": negative,
        "step_6_revoke": revoke,
        "step_7_post_revoke": post,
        "metrics": report,
    }

    out_dir = Path(__file__).parent / "reports"
    out_dir.mkdir(exist_ok=True)
    save_report(full_report, out_dir / "full_experiment_direct_ztna.json")
    print(f"\n[exp] Full report saved to {out_dir / 'full_experiment_direct_ztna.json'}")
    print(json.dumps(full_report, indent=2, ensure_ascii=False))


def run_gateway_ztna_experiment():
    """Эксперимент для Gateway-ZTNA."""
    print("\n" + "="*60)
    print("  ЭКСПЕРИМЕНТ Gateway-ZTNA")
    print("="*60)

    results = {}
    for name, svc in SERVICES.items():
        start = time.time()
        probe = http_probe(
            f"{GATEWAY_URL}/{name.lower()}/health",
            auth=("alice", "alice123"),
            verify_ssl=False,
            timeout=5,
        )
        latency = (time.time() - start) * 1000
        results[name] = {
            "reachable": probe["reachable"],
            "status_code": probe.get("status_code"),
            "latency_ms": probe.get("latency_ms"),
            "total_ms": round(latency, 2),
        }
        print(f"  {name}: reachable={probe['reachable']}, latency={probe.get('latency_ms')} ms")

    out_dir = Path(__file__).parent / "reports"
    out_dir.mkdir(exist_ok=True)
    save_report({"mode": "gateway-ztna", "results": results}, out_dir / "gateway_ztna_full.json")
    print(f"[exp] Gateway-ZTNA report saved.")


def main():
    run_full_experiment()
    run_gateway_ztna_experiment()
    print("\n=== All experiments complete ===")


if __name__ == "__main__":
    main()
