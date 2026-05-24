"""
Монитор сессий для автоматической очистки по exp.
"""

import threading
import time
from typing import Callable


class SessionMonitor:
    def __init__(self, check_interval: int = 10):
        self._check_interval = check_interval
        self._sessions: dict = {}  # jti -> exp
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._on_expire: Callable[[str], None] | None = None

    def set_on_expire(self, callback: Callable[[str], None]):
        self._on_expire = callback

    def add_session(self, jti: str, exp: int):
        with self._lock:
            self._sessions[jti] = exp

    def remove_session(self, jti: str):
        with self._lock:
            self._sessions.pop(jti, None)

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
            now = int(time.time())
            expired = []
            with self._lock:
                for jti, exp in list(self._sessions.items()):
                    if now > exp:
                        expired.append(jti)

            for jti in expired:
                self.remove_session(jti)
                if self._on_expire:
                    try:
                        self._on_expire(jti)
                    except Exception as e:
                        print(f"[session_monitor] on_expire error: {e}")

            self._stop_event.wait(self._check_interval)
