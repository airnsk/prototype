"""
Локальный кэш отозванных jti с фоновой синхронизацией.
"""

import threading
import time
from typing import Set

from client_agent.controller_client import ControllerClient


class RevokedCache:
    def __init__(self, controller_client: ControllerClient, sync_interval: int = 30):
        self._client = controller_client
        self._sync_interval = sync_interval
        self._revoked: Set[str] = set()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def add(self, jti: str):
        with self._lock:
            self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        with self._lock:
            return jti in self._revoked

    def all_revoked(self) -> Set[str]:
        with self._lock:
            return set(self._revoked)

    async def _sync(self):
        try:
            revoked = await self._client.get_revoked()
            with self._lock:
                self._revoked = set(revoked)
        except Exception as e:
            print(f"[revoked_cache] Sync failed: {e}")

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self):
        import asyncio
        while not self._stop_event.is_set():
            try:
                asyncio.run(self._sync())
            except Exception as e:
                print(f"[revoked_cache] Loop error: {e}")
            self._stop_event.wait(self._sync_interval)
