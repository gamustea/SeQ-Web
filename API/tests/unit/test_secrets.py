"""Tests unitarios del hashing de contraseñas (users.services.secrets)."""

import pytest

from src.modules.users.services.secrets import (
    encode_sha256,
    generate_salt,
    hash_password_with_salt,
    verify_password,
)

pytestmark = pytest.mark.unit


def test_salt_is_random_and_hex():
    s1, s2 = generate_salt(), generate_salt()
    assert s1 != s2
    assert len(s1) == 32
    int(s1, 16)  # no lanza: es hexadecimal válido


def test_hash_is_deterministic_for_same_salt():
    salt = "abc123"
    assert hash_password_with_salt("secret", salt) == hash_password_with_salt("secret", salt)


def test_hash_changes_with_salt():
    assert hash_password_with_salt("secret", "salt1") != hash_password_with_salt("secret", "salt2")


def test_verify_password_roundtrip():
    salt = generate_salt()
    stored = hash_password_with_salt("MyP@ssw0rd", salt)
    assert verify_password(stored, "MyP@ssw0rd", salt) is True
    assert verify_password(stored, "wrong", salt) is False


def test_encode_sha256_known_value():
    # SHA-256 de la cadena vacía.
    assert encode_sha256("") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
