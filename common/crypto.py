"""
Криптографические примитивы для прототипа Direct-ZTNA.

- Ed25519 для подписи билетов контроллером.
- Детерминированная каноническая сериализация payload.
"""

import json
import os
from typing import Dict, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


def canonical_encode(obj: Dict[str, Any]) -> bytes:
    """
    Детерминированная сериализация словаря в JSON.
    Используется для формирования подписываемого payload.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def generate_controller_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Генерация новой пары ключей Ed25519 для контроллера."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(path: str, sk: Ed25519PrivateKey) -> None:
    """Сохранение закрытого ключа в файл (raw bytes)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(sk.private_bytes_raw())


def load_private_key(path: str) -> Ed25519PrivateKey:
    """Загрузка закрытого ключа из файла."""
    with open(path, "rb") as f:
        raw = f.read()
    return Ed25519PrivateKey.from_private_bytes(raw)


def save_public_key(path: str, pk: Ed25519PublicKey) -> None:
    """Сохранение открытого ключа в файл (raw bytes)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(pk.public_bytes_raw())


def load_public_key(path: str) -> Ed25519PublicKey:
    """Загрузка открытого ключа из файла."""
    with open(path, "rb") as f:
        raw = f.read()
    return Ed25519PublicKey.from_public_bytes(raw)


def sign_ticket(payload: Dict[str, Any], sk_controller: Ed25519PrivateKey) -> str:
    """
    Подпись payload билета закрытым ключом контроллера.
    Возвращает подпись в hex-формате.
    """
    data = canonical_encode(payload)
    signature = sk_controller.sign(data)
    return signature.hex()


def verify_signature(payload: Dict[str, Any], signature_hex: str, pk_controller: Ed25519PublicKey) -> bool:
    """
    Проверка подписи payload открытым ключом контроллера.
    """
    try:
        signature = bytes.fromhex(signature_hex)
        data = canonical_encode(payload)
        pk_controller.verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False
