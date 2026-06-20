"""Tests unitarios del hashing de contraseñas (users.services.secrets)."""

import pytest

from src.modules.users.services.secrets import (
    generate_salt,
    hash_password,
    hash_password_with_salt,
    verify_password,
)

pytestmark = pytest.mark.unit


def test_generate_salt_is_legacy_stub():
    """generate_salt() es un stub de compatibilidad; Argon2 gestiona el salt internamente."""
    assert generate_salt() == ""


def test_hash_password_produces_argon2_hash():
    h = hash_password("mypassword")
    assert h.startswith("$argon2")


def test_verify_password_roundtrip_argon2():
    h = hash_password("MyP@ssw0rd")
    valid, needs_rehash = verify_password(h, "MyP@ssw0rd")
    assert valid is True
    assert needs_rehash is False  # hash recién generado, no necesita rehash

    invalid, _ = verify_password(h, "wrong")
    assert invalid is False


def test_verify_password_wrong_password_returns_false():
    h = hash_password("correct")
    valid, _ = verify_password(h, "incorrect")
    assert valid is False


# ---------------------------------------------------------------------------
# Ruta de compatibilidad SHA-256 (hashes heredados)
# ---------------------------------------------------------------------------

def test_hash_password_with_salt_is_deterministic():
    salt = "abc123"
    assert hash_password_with_salt("secret", salt) == hash_password_with_salt("secret", salt)


def test_hash_password_with_salt_differs_with_different_salt():
    assert hash_password_with_salt("secret", "salt1") != hash_password_with_salt("secret", "salt2")


def test_verify_legacy_sha256_hash_valid():
    salt = "abc123"
    stored = hash_password_with_salt("legacy_password", salt)
    valid, needs_rehash = verify_password(stored, "legacy_password", legacy_salt=salt)
    assert valid is True
    assert needs_rehash is True  # hash antiguo debe migrar a Argon2


def test_verify_legacy_sha256_hash_invalid():
    salt = "abc123"
    stored = hash_password_with_salt("legacy_password", salt)
    valid, _ = verify_password(stored, "wrong", legacy_salt=salt)
    assert valid is False
