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
