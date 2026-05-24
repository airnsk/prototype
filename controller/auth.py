"""
Модуль аутентификации контроллера.

Выполняет вызов mock IdP для проверки токена и получения атрибутов пользователя.
"""

import httpx
from typing import Dict, Any, Optional

from common import config


async def authenticate_user(user_token: str) -> Optional[Dict[str, Any]]:
    """
    Аутентифицировать пользователя через mock IdP.

    Returns:
        {"sub": str, "attrs": dict} или None при ошибке.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{config.CONTROLLER_IDP_URL}/auth",
                headers={"Authorization": f"Bearer {user_token}"},
                timeout=5.0,
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"[auth] IdP request failed: {e}")
            return None
