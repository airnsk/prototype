"""
HTTP-клиент для обращения к контроллеру.
"""

import httpx
from typing import Optional, Dict, Any

from common import config
from common.telemetry import emit


class ControllerClient:
    def __init__(self, base_url: Optional[str] = None):
        self._base_url = base_url or config.CLIENT_CONTROLLER_URL

    async def request_access(self, user_token: str, service_id: str) -> Optional[Dict[str, Any]]:
        """Запросить билет у контроллера."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{self._base_url}/access",
                    json={"user_token": user_token, "service_id": service_id},
                    timeout=10.0,
                )
                if resp.status_code == 200:
                    return resp.json()
                else:
                    print(f"[controller_client] Access denied: {resp.status_code} {resp.text}")
                    return None
            except Exception as e:
                print(f"[controller_client] Request failed: {e}")
                return None

    async def get_revoked(self) -> list:
        """Получить список отозванных jti."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(f"{self._base_url}/revoked", timeout=5.0)
                if resp.status_code == 200:
                    return resp.json().get("revoked", [])
            except Exception as e:
                print(f"[controller_client] Get revoked failed: {e}")
        return []
