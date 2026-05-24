"""
Unit-тесты криптографического модуля.
"""

import pytest
import tempfile
import os

from common.crypto import (
    generate_controller_keypair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    sign_ticket,
    verify_signature,
    canonical_encode,
)


def test_canonical_encode_deterministic():
    d = {"b": 2, "a": 1}
    encoded1 = canonical_encode(d)
    encoded2 = canonical_encode(d)
    assert encoded1 == encoded2
    assert encoded1 == b'{"a":1,"b":2}'


def test_generate_and_save_load_keys():
    sk, pk = generate_controller_keypair()

    with tempfile.TemporaryDirectory() as tmpdir:
        sk_path = os.path.join(tmpdir, "test.sk")
        pk_path = os.path.join(tmpdir, "test.pk")

        save_private_key(sk_path, sk)
        save_public_key(pk_path, pk)

        sk_loaded = load_private_key(sk_path)
        pk_loaded = load_public_key(pk_path)

        # Проверяем, что загруженные ключи работают
        payload = {"test": "data"}
        sig = sign_ticket(payload, sk_loaded)
        assert verify_signature(payload, sig, pk_loaded)


def test_sign_and_verify():
    sk, pk = generate_controller_keypair()
    payload = {"service_id": "s1", "sub": "alice", "exp": 1234567890}

    sig = sign_ticket(payload, sk)
    assert verify_signature(payload, sig, pk)


def test_verify_fails_with_wrong_key():
    sk1, pk1 = generate_controller_keypair()
    sk2, pk2 = generate_controller_keypair()

    payload = {"service_id": "s1"}
    sig = sign_ticket(payload, sk1)

    assert not verify_signature(payload, sig, pk2)


def test_verify_fails_with_tampered_payload():
    sk, pk = generate_controller_keypair()

    payload = {"service_id": "s1"}
    sig = sign_ticket(payload, sk)

    tampered = {"service_id": "s2"}
    assert not verify_signature(tampered, sig, pk)


def test_verify_fails_with_invalid_signature_hex():
    sk, pk = generate_controller_keypair()
    payload = {"service_id": "s1"}

    assert not verify_signature(payload, "notahex", pk)
    assert not verify_signature(payload, "abcd", pk)
