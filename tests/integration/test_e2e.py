"""
End-to-end интеграционный тест прототипа Direct-ZTNA.

Предполагает, что стенд запущен через docker-compose:
    make up

Тест проверяет полный жизненный цикл:
1. Запрос доступа → получение билета
2. Валидация билета (подпись, срок, audience)
3. Активация на сервере (peer_add)
4. Отзыв доступа → peer_remove
"""

import pytest
import httpx
import time

CONTROLLER_URL = "http://localhost:8080"
TELEMETRY_URL = "http://localhost:8082"
MOCK_IDP_URL = "http://localhost:8081"

ALICE_TOKEN = "bearer-alice-token-abc123"
SERVICE_ID = "protected-service-1"


@pytest.fixture(autouse=True)
def clear_telemetry():
    """Очистить телеметрию перед каждым тестом."""
    try:
        httpx.post(f"{TELEMETRY_URL}/clear", timeout=2.0)
    except Exception:
        pass


def test_health_endpoints():
    """Все сервисы отвечают на /health."""
    for url in [CONTROLLER_URL, MOCK_IDP_URL, TELEMETRY_URL]:
        resp = httpx.get(f"{url}/health", timeout=5.0)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


def test_access_request_success():
    """Положительный сценарий: запрос доступа возвращает подписанный билет."""
    resp = httpx.post(
        f"{CONTROLLER_URL}/access",
        json={"user_token": ALICE_TOKEN, "service_id": SERVICE_ID},
        timeout=10.0,
    )
    assert resp.status_code == 200
    ticket = resp.json()

    assert ticket["sub"] == "alice"
    assert ticket["service_id"] == SERVICE_ID
    assert ticket["aud"] == "client"
    assert ticket["iss"] == "ztna-controller"
    assert ticket["sig"] != ""
    assert ticket["exp"] > int(time.time())
    assert "transport" in ticket
    assert "server_pubkey" in ticket["transport"]


def test_server_agent_activate_and_revoke():
    """Серверный агент принимает activate и revoke."""
    # 1. Получить билет
    resp = httpx.post(
        f"{CONTROLLER_URL}/access",
        json={"user_token": ALICE_TOKEN, "service_id": SERVICE_ID},
        timeout=10.0,
    )
    ticket = resp.json()
    jti = ticket["jti"]

    # 2. Проверить телеметрию: peer_add от сервера
    time.sleep(0.5)
    telem = httpx.get(f"{TELEMETRY_URL}/report", timeout=5.0).json()
    server_events = [e for e in telem["events"] if e["node"] == "server" and e["event"] == "peer_add"]
    assert len(server_events) >= 1
    assert any(e["ticket_id"] == jti for e in server_events)

    # 3. Revoke
    revoke_resp = httpx.post(
        f"{CONTROLLER_URL}/revoke",
        json={"jti": jti},
        timeout=5.0,
    )
    assert revoke_resp.status_code == 200

    # 4. Проверить телеметрию: traffic_stop
    time.sleep(0.5)
    telem = httpx.get(f"{TELEMETRY_URL}/report", timeout=5.0).json()
    stop_events = [e for e in telem["events"] if e["node"] == "server" and e["event"] == "traffic_stop"]
    assert any(e["ticket_id"] == jti for e in stop_events)


def test_revoke_prevents_reuse():
    """После отзыва jti попадает в список отозванных."""
    resp = httpx.post(
        f"{CONTROLLER_URL}/access",
        json={"user_token": ALICE_TOKEN, "service_id": SERVICE_ID},
        timeout=10.0,
    )
    ticket = resp.json()
    jti = ticket["jti"]

    # Revoke
    httpx.post(f"{CONTROLLER_URL}/revoke", json={"jti": jti}, timeout=5.0)

    # Проверить, что jti в списке отозванных
    revoked_resp = httpx.get(f"{CONTROLLER_URL}/revoked", timeout=5.0)
    assert jti in revoked_resp.json()["revoked"]


def test_access_denied_unknown_service():
    """Доступ к несуществующему сервису отклоняется."""
    resp = httpx.post(
        f"{CONTROLLER_URL}/access",
        json={"user_token": ALICE_TOKEN, "service_id": "nonexistent-service"},
        timeout=10.0,
    )
    assert resp.status_code == 403


def test_access_denied_invalid_token():
    """Доступ с невалидным токеном отклоняется."""
    resp = httpx.post(
        f"{CONTROLLER_URL}/access",
        json={"user_token": "invalid-token", "service_id": SERVICE_ID},
        timeout=10.0,
    )
    assert resp.status_code == 401
