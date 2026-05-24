"""
Локальное хранилище PSK для серверного агента.
"""

import json
import os
from typing import Optional

from common import config


class KeyStore:
    """Загружает key_id → PSK из JSON-файла."""

    def __init__(self, path: Optional[str] = None):
        self._path = path or config.SERVER_KEY_STORE_PATH
        self._keys: dict = {}
        self._load()

    def _load(self):
        if os.path.exists(self._path):
            with open(self._path, "r", encoding="utf-8") as f:
                self._keys = json.load(f)
        else:
            self._keys = {}

    def get(self, key_id: str) -> Optional[str]:
        return self._keys.get(key_id)

    def has(self, key_id: str) -> bool:
        return key_id in self._keys
