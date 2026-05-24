"""
Общие модели данных для прототипа Direct-ZTNA.

Все компоненты системы используют единые структуры данных,
что обеспечивает согласованность телеметрии и воспроизводимость эксперимента.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
import json
import time


@dataclass
class TransportProfile:
    """Транспортный профиль для прямого соединения клиент–сервис."""
    endpoint: str               # IP:port эндпоинта сервера
    allowed_ips: List[str]      # Разрешённые IP-префиксы (CIDR)
    server_pubkey: str = ""     # (устарело) ранее использовался для WG

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TransportProfile":
        return cls(**d)


@dataclass
class AccessTicket:
    """
    Криптографическое разрешение (билет) доступа.

    Структура соответствует формальной модели (2.1) из главы 2:
    Ticket = <sub, service_id, jti, iat, exp, key_id, transport, scope, sigma>
    """
    iss: str                    # issuer — контроллер
    aud: str                    # audience — "client" или "server"
    sub: str                    # идентификатор пользователя
    service_id: str             # целевой сервис
    jti: str                    # уникальный идентификатор билета (для отзыва / replay-защиты)
    nbf: int                    # not before — начало окна валидности (unix timestamp)
    iat: int                    # issued at — время выпуска (unix timestamp)
    exp: int                    # expiration — время истечения (unix timestamp)
    key_id: str                 # идентификатор PSK
    transport: TransportProfile # транспортные параметры
    scope: str                  # конкретные параметры доступа (протокол:порт)
    sig: str = ""               # подпись Ed25519 контроллера (hex)

    def payload_dict(self) -> Dict[str, Any]:
        """Словарь для подписи — без поля sig."""
        return {
            "iss": self.iss,
            "aud": self.aud,
            "sub": self.sub,
            "service_id": self.service_id,
            "jti": self.jti,
            "nbf": self.nbf,
            "iat": self.iat,
            "exp": self.exp,
            "key_id": self.key_id,
            "transport": self.transport.to_dict(),
            "scope": self.scope,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.payload_dict()
        d["sig"] = self.sig
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AccessTicket":
        transport = TransportProfile.from_dict(d.pop("transport"))
        sig = d.pop("sig", "")
        return cls(transport=transport, sig=sig, **d)


@dataclass
class RevokeCommand:
    """Команда отзыва доступа."""
    jti: str
    revoked_at: int             # unix timestamp
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RevokeCommand":
        return cls(**d)


@dataclass
class MetricEvent:
    """
    Событие телеметрии для измерения жизненного цикла доступа.

    Ключевые события:
    - request       — клиент инициировал запрос доступа
    - auth_done     — аутентификация завершена
    - policy_done   — решение политики принято
    - ticket_issued — билет выдан
    - peer_add      — сервер добавил peer
    - tunnel_up     — туннель установлен
    - first_data    — первый прикладной пакет
    - revoke_cmd    — команда отзыва отправлена
    - peer_remove   — peer удалён
    - traffic_stop  — трафик прекращён
    """
    node: str                   # имя узла: controller, client-agent, server-agent, ...
    event: str                  # тип события
    ts: float                   # временная метка (time.time())
    ticket_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "MetricEvent":
        return cls(**d)


@dataclass
class AccessRequest:
    """Запрос доступа от клиентского агента к контроллеру."""
    user_token: str
    service_id: str
    requested_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AccessRequest":
        return cls(**d)
