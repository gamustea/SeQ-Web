"""Tests de integración del flujo OAuth 2.0."""

import pytest

pytestmark = pytest.mark.integration


def test_password_grant_issues_tokens(client, regular_user):
    resp = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "Bearer"
    assert body["role"] == "role_user"


def test_password_grant_wrong_password(client, regular_user):
    resp = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": "incorrecta",
    })
    assert resp.status_code == 401


def test_password_grant_unknown_user(client):
    resp = client.post("/oauth/token", json={
        "grantType": "password",
        "username": "fantasma",
        "password": "x",
    })
    assert resp.status_code == 401


def test_password_grant_missing_password_is_rejected(client, regular_user):
    resp = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
    })
    assert resp.status_code in (400, 422)


def test_refresh_grant_returns_new_access_token(client, regular_user):
    first = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    }).get_json()

    resp = client.post("/oauth/token", json={
        "grantType": "refresh_token",
        "refresh_token": first["refresh_token"],
    })
    assert resp.status_code == 200
    assert resp.get_json()["access_token"]


def test_revoke_requires_authentication(client):
    assert client.post("/oauth/revoke").status_code == 401


def test_revoke_current_token(client, regular_user, auth_headers):
    headers = auth_headers(regular_user)
    resp = client.post("/oauth/revoke", headers=headers)
    assert resp.status_code == 200

    # Tras revocar, el token ya no autentica.
    after = client.get("/users/me", headers=headers)
    assert after.status_code == 401
