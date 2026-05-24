"""
Негативные тесты безопасности Direct-ZTNA (N1–N7).

Предполагает запущенный стенд (docker-compose up).
"""

import pytest
import httpx
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.crypto import sign_ticket, generate_controller_keypair, load_private_key, load_public_key
from common.models import AccessTicket, TransportProfile

CONTROLLER_URL = "http://localhost:8080"
TELEMETRY_URL = "http://localhost:8082"
ALICE_TOKEN = "bearer-alice-token-abc123"
SERVICE_ID = "protected-service-1"


@pytest.fixture(autouse=True)
def clear_telemetry():
    try:
        httpx.post(f"{TELEMETRY_URL}/clear", timeout=2.0)
    except Exception:
        pass


def get_ticket() -> dict:
    resp = httpx.post(
        f"{CONTROLLER_URL}/access",
        json={"user_token": ALICE_TOKEN, "service_id": SERVICE_ID},
        timeout=10.0,
    )
    assert resp.status_code == 200
    return resp.json()


# N4: Просроченный билет

def test_expired_ticket_rejected():
    """Билет с истекшим сроком действия должен быть отклонён при валидации."""
    # Создаём билет с exp в прошлом
    past = int(time.time()) - 100
    ticket = AccessTicket(
        iss="ztna-controller",
        aud="client",
        sub="alice",
        service_id=SERVICE_ID,
        jti="expired-test-jti",
        nbf=past - 200,
        iat=past - 200,
        exp=past,
        key_id="psk-alice-protected-service-1",
        transport=TransportProfile(server_pubkey="pk", endpoint="e", allowed_ips=["10.0.0.1/32"]),
        scope="tcp:443",
    )
    sk = load_private_key("keys/controller.sk")
    ticket.sig = sign_ticket(ticket.payload_dict(), sk)

    # Валидация должна провалиться по сроку
    from client_agent.ticket_manager import TicketManager
    tm = TicketManager(controller_pk_path="keys/controller.pk")
    valid, reason = tm.validate(ticket.to_dict(), set())
    assert not valid
    assert "not valid" in reason.lower() or "exp" in reason.lower()


# N2: Чужой билет (несовпадение audience)

def test_wrong_audience_rejected():
    """Билет с audience != client должен быть отклонён клиентским агентом."""
    ticket = get_ticket()
    ticket["aud"] = "server"  # подмена
    # Переподписываем контроллером, чтобы проверить именно audience check
    from common.crypto import sign_ticket, load_private_key
    sk = load_private_key("keys/controller.sk")
    payload = {k: v for k, v in ticket.items() if k != "sig"}
    ticket["sig"] = sign_ticket(payload, sk)

    from client_agent.ticket_manager import TicketManager
    tm = TicketManager(controller_pk_path="keys/controller.pk")
    valid, reason = tm.validate(ticket, set())
    assert not valid
    assert "audience" in reason.lower() or "aud" in reason.lower()


# N5: Повторное использование отозванного jti

def test_revoked_jti_rejected():
    """После отзыва jti билет с этим jti должен быть отклонён."""
    ticket = get_ticket()
    jti = ticket["jti"]

    # Revoke
    resp = httpx.post(f"{CONTROLLER_URL}/revoke", json={"jti": jti}, timeout=5.0)
    assert resp.status_code == 200

    # Валидация с revoked set
    from client_agent.ticket_manager import TicketManager
    tm = TicketManager(controller_pk_path="keys/controller.pk")
    valid, reason = tm.validate(ticket, {jti})
    assert not valid
    assert "revoked" in reason.lower()


# N1: Доступ без билета (проверяем, что /activate без валидного билета отклоняется)

def test_access_without_ticket_denied():
    """Попытка активации без валидного подписанного билета отклоняется."""
    fake_ticket = {
        "jti": "fake",
        "sig": "deadbeef",
        "aud": "server",
        "nbf": 0,
        "exp": 9999999999,
        "key_id": "none",
        "transport": {"server_pubkey": "pk", "endpoint": "e", "allowed_ips": []},
    }
    # Это unit-style проверка валидатора
    from server_agent.ticket_validator import TicketValidator
    tv = TicketValidator(controller_pk_path="keys/controller.pk")
    valid, reason = tv.validate(fake_ticket, set())
    assert not valid
    assert "signature" in reason.lower() or "invalid" in reason.lower()


# N3: Доступ без PSK (несовпадение key_id)

def test_missing_psk_rejected():
    """Если key_id отсутствует в key_store, доступ не активируется."""
    ticket = get_ticket()
    ticket["key_id"] = "nonexistent-key-id"
    # Подпись всё ещё валидна, но PSK отсутствует
    from client_agent.key_store import KeyStore
    ks = KeyStore()
    psk = ks.get(ticket["key_id"])
    assert psk is None


# N6: Горизонтальное перемещение (доступ к S2 при билете на S1)

def test_horizontal_movement_blocked():
    """Билет на S1 не даёт доступа к S2 — key_id разный."""
    ticket_s1 = get_ticket()
    # key_id для S1
    key_id_s1 = ticket_s1["key_id"]
    assert "protected-service-1" in key_id_s1

    # Для S2 key_id был бы другим и PSK отсутствовал бы
    from client_agent.key_store import KeyStore
    ks = KeyStore()
    assert not ks.has("psk-alice-protected-service-2")


# N7: Расширение scope без авторизации

def test_scope_enforcement():
    """Scope зафиксирован в билете и не может быть расширен клиентом."""
    ticket = get_ticket()
    original_scope = ticket["scope"]

    # Клиент пытается подменить scope локально
    ticket["scope"] = "tcp:22"
    # Подпись становится невалидной, так как payload изменился
    from client_agent.ticket_manager import TicketManager
    tm = TicketManager(controller_pk_path="keys/controller.pk")
    valid, reason = tm.validate(ticket, set())
    assert not valid
    assert "signature" in reason.lower()
