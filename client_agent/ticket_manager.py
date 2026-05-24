"""
Менеджер билетов клиентского агента.

Проверяет:
- подпись контроллера
- audience == "client"
- срок действия (nbf <= now <= exp)
- jti не в списке отозванных
"""

import time
from typing import Optional

from common.crypto import load_public_key, verify_signature
from common import config


class TicketManager:
    def __init__(self, controller_pk_path: Optional[str] = None):
        self._pk_path = controller_pk_path or config.CLIENT_CONTROLLER_PK_PATH
        self._pk = load_public_key(self._pk_path)

    def validate(self, ticket: dict, revoked: set, audience: str = "client") -> tuple[bool, Optional[str]]:
        # 1. Подпись
        sig = ticket.get("sig", "")
        payload = {k: v for k, v in ticket.items() if k != "sig"}
        if not verify_signature(payload, sig, self._pk):
            return False, "Invalid signature"

        # 2. Audience
        if ticket.get("aud") != audience:
            return False, f"Invalid audience: {ticket.get('aud')}"

        # 3. Время
        now = int(time.time())
        nbf = ticket.get("nbf", 0)
        exp = ticket.get("exp", 0)
        if not (nbf <= now <= exp):
            return False, f"Ticket not valid at time {now} (nbf={nbf}, exp={exp})"

        # 4. Отозванность
        jti = ticket.get("jti", "")
        if jti in revoked:
            return False, f"Ticket {jti} revoked"

        return True, None
