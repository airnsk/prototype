"""
Подсистема телеметрии для прототипа Direct-ZTNA.

Каждое ключевое событие жизненного цикла доступа фиксируется
с временной меткой для последующего расчёта T_setup, T_revoke и K_avg.

В прототипе используется гибридный подход:
- Локальный in-memory коллектор для быстрого доступа
- Асинхронная отправка на центральный telemetry-сервер (если задан ZTNA_TELEMETRY_URL)
"""

import time
import json
import threading
from typing import List, Optional, Dict, Any
from dataclasses import asdict

import httpx

from common.models import MetricEvent
from common import config


class TelemetryCollector:
    """In-memory сборщик событий с возможностью flush в JSON."""

    def __init__(self):
        self._events: List[MetricEvent] = []
        self._lock = threading.Lock()

    def emit(self, node: str, event: str, ticket_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> MetricEvent:
        """Зафиксировать событие и вернуть его."""
        evt = MetricEvent(
            node=node,
            event=event,
            ts=time.time(),
            ticket_id=ticket_id,
            details=details,
        )
        with self._lock:
            self._events.append(evt)
        return evt

    def all_events(self) -> List[MetricEvent]:
        with self._lock:
            return list(self._events)

    def filter(self, node: Optional[str] = None, event: Optional[str] = None, ticket_id: Optional[str] = None) -> List[MetricEvent]:
        with self._lock:
            result = self._events
        if node:
            result = [e for e in result if e.node == node]
        if event:
            result = [e for e in result if e.event == event]
        if ticket_id:
            result = [e for e in result if e.ticket_id == ticket_id]
        return result

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def to_json(self, indent: Optional[int] = 2) -> str:
        events = self.all_events()
        return json.dumps([e.to_dict() for e in events], indent=indent, ensure_ascii=False, default=str)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())


# Глобальный коллектор (может быть переопределён в тестах)
_global_collector: Optional[TelemetryCollector] = None


def get_collector() -> TelemetryCollector:
    global _global_collector
    if _global_collector is None:
        _global_collector = TelemetryCollector()
    return _global_collector


def _send_to_telemetry_server(evt: MetricEvent):
    """Отправить событие на центральный telemetry-сервер."""
    url = getattr(config, 'TELEMETRY_URL', None)
    if not url:
        return
    try:
        with httpx.Client() as client:
            client.post(
                f"{url}/event",
                json=evt.to_dict(),
                timeout=2.0,
            )
    except Exception:
        pass  # telemetry is best-effort


def emit(node: Optional[str] = None, event: str = "", ticket_id: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> MetricEvent:
    """
    Удобная функция для фиксации события.
    Если node не указан, используется ZTNA_NODE из окружения.
    """
    n = node or config.NODE_NAME
    evt = get_collector().emit(n, event, ticket_id, details)
    _send_to_telemetry_server(evt)
    return evt
