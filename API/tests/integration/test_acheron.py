"""Tests de integración del módulo Acheron (vaults de secretos)."""

import pytest

pytestmark = pytest.mark.integration


def test_get_vault_requires_authentication(client):
    assert client.get("/acheron/vault").status_code == 401


def test_create_vault_requires_create_attribute(client, regular_user, auth_headers):
    # role_user tiene acheron_read pero no acheron_create.
    resp = client.post("/acheron/vault", headers=auth_headers(regular_user),
                       json={"storables": []})
    assert resp.status_code == 403


def test_get_vault_empty_returns_404(client, regular_user, auth_headers):
    # El usuario tiene acheron_read (baseline) pero no tiene vault creado.
    resp = client.get("/acheron/vault", headers=auth_headers(regular_user))
    assert resp.status_code == 404


def test_add_storable_requires_create_attribute(client, regular_user, auth_headers):
    resp = client.post("/acheron/storables", headers=auth_headers(regular_user), json={
        "kind": "account",
        "username": "u",
        "domain": "d",
        "password": "p",
    })
    assert resp.status_code == 403


# ── PATCH /vault (cambio de contraseña maestra) ──────────────────────────────


def _vault_payload(checker="checker-old", vault_key="vaultkey-old", salt="salt-old"):
    return {
        "checker": checker,
        "vaultKey": vault_key,
        "algorithm": {
            "transformation": "AES/GCM/NoPadding",
            "kdf": "Argon2",
            "kdfIterations": "3",
            "kdfMemoryKiB": "65536",
            "kdfParallelism": "1",
            "salt": salt,
        },
        "accounts": [
            {
                "id": "acc0001",
                "title": "enc-title",
                "createdAt": "2026-01-01T00:00:00.000Z",
                "updatedAt": "2026-01-01T00:00:00.000Z",
                "username": "enc-user",
                "domain": "enc-domain",
                "password": "enc-pass",
            }
        ],
    }


def test_change_vault_password_requires_update_attribute(client, regular_user, auth_headers):
    # role_user tiene acheron_read pero no acheron_update.
    resp = client.patch("/acheron/vault", headers=auth_headers(regular_user), json={
        "checker": "c", "vaultKey": "k", "algorithm": {"salt": "s"},
    })
    assert resp.status_code == 403


def test_change_vault_password_without_vault_returns_404(client, make_user, auth_headers):
    user = make_user(role="role_user", attributes=["acheron_update"])
    resp = client.patch("/acheron/vault", headers=auth_headers(user), json={
        "checker": "c", "vaultKey": "k", "algorithm": {"salt": "s"},
    })
    assert resp.status_code == 404


def test_change_vault_password_invalid_body_is_rejected(client, make_user, auth_headers):
    user = make_user(role="role_user", attributes=["acheron_create", "acheron_update"])
    # Falta vaultKey/algorithm -> error de validación del schema.
    resp = client.patch("/acheron/vault", headers=auth_headers(user), json={"checker": "c"})
    assert resp.status_code in (400, 422)


def test_change_vault_password_updates_metadata_and_keeps_storables(client, make_user, auth_headers):
    user = make_user(role="role_user", attributes=["acheron_create", "acheron_update"])
    headers = auth_headers(user)

    # 1. Crear el vault con un storable.
    created = client.post("/acheron/vault", headers=headers, json=_vault_payload())
    assert created.status_code in (200, 201)

    # 2. Cambiar la contraseña: solo metadatos (checker/vaultKey/algorithm).
    patch = client.patch("/acheron/vault", headers=headers, json={
        "checker": "checker-new",
        "vaultKey": "vaultkey-new",
        "algorithm": {
            "transformation": "AES/GCM/NoPadding",
            "kdf": "Argon2",
            "kdfIterations": "3",
            "kdfMemoryKiB": "65536",
            "kdfParallelism": "1",
            "salt": "salt-new",
        },
    })
    assert patch.status_code == 200

    # 3. El vault refleja los nuevos metadatos y conserva el storable intacto.
    got = client.get("/acheron/vault", headers=headers)
    assert got.status_code == 200
    body = got.get_json()

    assert body["checker"] == "checker-new"
    assert body["vaultKey"] == "vaultkey-new"
    assert body["algorithm"]["salt"] == "salt-new"

    assert len(body["accounts"]) == 1
    account = body["accounts"][0]
    assert account["id"] == "acc0001"
    assert account["password"] == "enc-pass"
    assert account["username"] == "enc-user"


def test_metadata_version_starts_at_one_and_bumps_on_password_change(client, make_user, auth_headers):
    user = make_user(role="role_user", attributes=["acheron_create", "acheron_update"])
    headers = auth_headers(user)

    client.post("/acheron/vault", headers=headers, json=_vault_payload())

    first = client.get("/acheron/vault", headers=headers).get_json()
    assert first["metadataVersion"] == 1

    patch = client.patch("/acheron/vault", headers=headers, json={
        "checker": "checker-new",
        "vaultKey": "vaultkey-new",
        "algorithm": {
            "transformation": "AES/GCM/NoPadding",
            "kdf": "Argon2",
            "kdfIterations": "3",
            "kdfMemoryKiB": "65536",
            "kdfParallelism": "1",
            "salt": "salt-new",
        },
    })
    assert patch.status_code == 200

    second = client.get("/acheron/vault", headers=headers).get_json()
    assert second["metadataVersion"] == 2


# ── GET /generate-password (endpoint público) ────────────────────────────────


def test_generate_password_no_auth_required(client):
    resp = client.get("/acheron/generate-password")
    assert resp.status_code == 200
    assert isinstance(resp.get_json()["password"], str)


def test_generate_password_default_length(client):
    resp = client.get("/acheron/generate-password")
    assert len(resp.get_json()["password"]) == 20


def test_generate_password_respects_length(client):
    resp = client.get("/acheron/generate-password?length=32")
    assert resp.status_code == 200
    assert len(resp.get_json()["password"]) == 32


def test_generate_password_rejects_length_out_of_range(client):
    assert client.get("/acheron/generate-password?length=200").status_code == 422
    assert client.get("/acheron/generate-password?length=2").status_code == 422


def test_generate_password_rejects_all_charsets_disabled(client):
    resp = client.get(
        "/acheron/generate-password"
        "?uppercase=false&lowercase=false&digits=false&symbols=false"
    )
    assert resp.status_code == 422


def test_generate_password_exclude_ambiguous(client):
    resp = client.get("/acheron/generate-password?length=64&excludeAmbiguous=true")
    assert resp.status_code == 200
    password = resp.get_json()["password"]
    assert not set(password) & set("0O1lI")
