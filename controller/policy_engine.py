"""
Policy Engine для контроллера Direct-ZTNA.

Упрощённая rule-based реализация:
- проверка существования сервиса в реестре
- проверка прав пользователя на доступ к сервису
- временные ограничения (не реализованы в прототипе)
"""

from typing import Dict, Any, Optional


def check_policy(sub: str, attrs: Dict[str, Any], service_id: str, registry: Dict[str, Any]) -> tuple[bool, Optional[str]]:
    """
    Проверить, разрешён ли доступ пользователю sub к сервису service_id.

    Returns:
        (allowed: bool, reason: str|None)
    """
    services = registry.get("services", {})
    agents = registry.get("agents", {})

    if service_id not in services:
        return False, f"Service {service_id} not found in registry"

    # Проверяем, что клиенту разрешён доступ к этому сервису
    client_cfg = agents.get("client-agent", {})
    allowed_services = client_cfg.get("allowed_services", [])
    if service_id not in allowed_services:
        return False, f"Service {service_id} not in allowed list for client"

    # В прототипе attrs не используются для сложных правил,
    # но в промышленной реализации здесь была бы проверка ролей, групп, времени и т.д.
    return True, None
