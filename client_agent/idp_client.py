"""
Клиент для обращения к mock IdP.
"""

import httpx
from typing import Optional, Dict, Any

from common import config


class IdPClient:
    def __init__(self, base_url: Optional[str] = None):
        self._base_url = base_url or config.CLIENT_IDP_URL

    async def authenticate(self, user_token: str) -> Optional[Dict[str, Any]]:
        """Аутентифицировать пользователя и получить sub + attrs."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{self._base_url}/auth",
                    headers={"Authorization": f"Bearer {user_token}"},
                    timeout=5.0,
                )
                if resp.status_code == 200:
                    return resp.json()
                else:
                    print(f"[idp_client] Auth failed: {resp.status_code}")
                    return None
            except Exception as e:
                print(f"[idp_client] Request failed: {e}")
                return None
