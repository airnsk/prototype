#!/usr/bin/env python3
"""
Скрипт инициализации ключевого материала для стенда Direct-ZTNA.

Генерирует:
1. Пару ключей Ed25519 для контроллера.
2. Предварительно распределённые симметричные ключи (PSK) для пар (клиент, сервис).
3. Mock IdP users.json с 10 пользователями.
"""

import os
import json
import secrets
import base64

from common.crypto import generate_controller_keypair, save_private_key, save_public_key


def generate_psk() -> str:
    """Генерация 256-битного PSK в base64."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def generate_users_json(path: str, num_users: int = 10):
    """Генерация mock IdP users.json с N пользователями."""
    users = {}
    tokens = {}
    for i in range(1, num_users + 1):
        username = f"user{i:02d}"
        password = f"password-{i}-{secrets.token_hex(4)}"
        token = f"bearer-{username}-token-{secrets.token_hex(8)}"
        users[username] = {
            "password": password,
            "attrs": {"role": "user", "department": f"dept{i % 3 + 1}"}
        }
        tokens[username] = token

    data = {"users": users, "bearer_tokens": tokens}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[init_keys] Generated {num_users} users in {path}")
    return data


def main():
    base_dir = os.path.join(os.path.dirname(__file__), "..")
    keys_dir = os.path.join(base_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)

    # 1. Ключи контроллера Ed25519
    controller_sk_path = os.path.join(keys_dir, "controller.sk")
    controller_pk_path = os.path.join(keys_dir, "controller.pk")

    if os.path.exists(controller_sk_path) and os.path.exists(controller_pk_path):
        print("[init_keys] Ключи контроллера уже существуют, пропускаем генерацию.")
    else:
        sk, pk = generate_controller_keypair()
        save_private_key(controller_sk_path, sk)
        save_public_key(controller_pk_path, pk)
        print(f"[init_keys] Сгенерированы ключи контроллера: {controller_sk_path}, {controller_pk_path}")

    # 2. PSK для 10 пользователей × 5 сервисов = 50 ключей
    services = [f"protected-service-{i}" for i in range(1, 6)]
    users = [f"user{i:02d}" for i in range(1, 11)]
    client_keys = {}
    server_keys = {}

    for svc in services:
        for user in users:
            key_id = f"psk-{user}-{svc}"
            psk = generate_psk()
            client_keys[key_id] = psk
            server_keys[key_id] = psk
        print(f"[init_keys] {svc}: 10 PSKs generated")

    client_keys_path = os.path.join(keys_dir, "client_keys.json")
    server_keys_path = os.path.join(keys_dir, "server_keys.json")

    with open(client_keys_path, "w", encoding="utf-8") as f:
        json.dump(client_keys, f, indent=2)
    print(f"[init_keys] Сохранены клиентские ключи: {client_keys_path} ({len(client_keys)} entries)")

    with open(server_keys_path, "w", encoding="utf-8") as f:
        json.dump(server_keys, f, indent=2)
    print(f"[init_keys] Сохранены серверные ключи: {server_keys_path} ({len(server_keys)} entries)")

    # 3. Mock IdP users.json (10 пользователей)
    users_json_path = os.path.join(base_dir, "mock_idp", "users.json")
    generate_users_json(users_json_path, num_users=10)

    print("[init_keys] Инициализация завершена.")


if __name__ == "__main__":
    main()
