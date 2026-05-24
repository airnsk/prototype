"""
Загрузка конфигурации из переменных окружения.
"""

import os
from pathlib import Path


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def env_int(key: str, default: int = 0) -> int:
    return int(os.environ.get(key, default))


# === Controller ===
CONTROLLER_SK_PATH = env("ZTNA_CONTROLLER_SK_PATH", "/app/keys/controller.sk")
CONTROLLER_PK_PATH = env("ZTNA_CONTROLLER_PK_PATH", "/app/keys/controller.pk")
CONTROLLER_IDP_URL = env("ZTNA_IDP_URL", "http://mock-idp:8000")
CONTROLLER_TELEMETRY_URL = env("ZTNA_TELEMETRY_URL", "http://telemetry:8000")
CONTROLLER_REGISTRY_PATH = env("ZTNA_REGISTRY_PATH", "/app/config/registry.json")

# === Client Agent ===
CLIENT_CONTROLLER_URL = env("ZTNA_CONTROLLER_URL", "http://controller:8000")
CLIENT_IDP_URL = env("ZTNA_IDP_URL", "http://mock-idp:8000")
CLIENT_TELEMETRY_URL = env("ZTNA_TELEMETRY_URL", "http://telemetry:8000")
CLIENT_KEY_STORE_PATH = env("ZTNA_KEY_STORE_PATH", "/app/keys/client_keys.json")
CLIENT_CONTROLLER_PK_PATH = env("ZTNA_CONTROLLER_PK_PATH", "/app/keys/controller.pk")

# === Server Agent ===
SERVER_CONTROLLER_URL = env("ZTNA_CONTROLLER_URL", "http://controller:8000")
SERVER_TELEMETRY_URL = env("ZTNA_TELEMETRY_URL", "http://telemetry:8000")
SERVER_KEY_STORE_PATH = env("ZTNA_KEY_STORE_PATH", "/app/keys/server_keys.json")
SERVER_CONTROLLER_PK_PATH = env("ZTNA_CONTROLLER_PK_PATH", "/app/keys/controller.pk")

# === Telemetry ===
TELEMETRY_URL = env("ZTNA_TELEMETRY_URL", "")

# === Node name ===
NODE_NAME = env("ZTNA_NODE", "unknown")
