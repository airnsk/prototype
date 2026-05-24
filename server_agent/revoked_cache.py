"""
Локальный кэш отозванных jti с фоновой синхронизацией с контроллером.
"""

import threading
import time
from typing import Set

import httpx

from common import config


class RevokedCache:
    def __init__(self, controller_url: str | None = None, sync_interval: int = 30):
        self._controller_url = controller_url or config.SERVER_CONTROLLER_URL
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

    def _sync(self):
        try:
            with httpx.Client() as client:
                resp = client.get(f"{self._controller_url}/revoked", timeout=5.0)
                if resp.status_code == 200:
                    data = resp.json()
                    with self._lock:
                        self._revoked = set(data.get("revoked", []))
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
        while not self._stop_event.is_set():
            self._sync()
            self._stop_event.wait(self._sync_interval)
