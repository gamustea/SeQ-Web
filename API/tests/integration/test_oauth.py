"""Tests de integración del flujo OAuth 2.0."""

from datetime import datetime, timedelta

import pytest

from src.modules.infrastructure import unit_of_work
from src.modules.users.managers import OAuthTokenManager
from src.modules.users.repositories import UserRepository

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


# ── Detección de cambio de contraseña de acceso ──────────────────────────────


def test_stale_token_after_password_change_returns_password_changed(
    client, regular_user, auth_headers, app
):
    headers = auth_headers(regular_user)
    # El token autentica inicialmente.
    assert client.get("/users/me", headers=headers).status_code == 200

    # Simular un cambio de contraseña: marca posterior al iat del token + revocación.
    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            user = UserRepository(uow).get_by_id(regular_user.id)
            user.password_changed_at = datetime.utcnow() + timedelta(minutes=1)
        OAuthTokenManager().revoke_all_user_tokens(regular_user.id)

    resp = client.get("/users/me", headers=headers)
    assert resp.status_code == 401
    body = resp.get_json()
    assert body["error"] == "password_changed"
    assert body["code"] == 1609


def test_change_password_sets_timestamp_visible_in_me(client, regular_user):
    login = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    }).get_json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}

    me_before = client.get("/users/me", headers=headers).get_json()
    assert "password_changed_at" in me_before  # presente (null) para usuario nuevo

    changed = client.put("/users/change-password", headers=headers,
                         json={"newPassword": "NewSecret123!"})
    assert changed.status_code == 200

    # Los tokens viejos quedan revocados; re-login con la nueva contraseña.
    login2 = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": "NewSecret123!",
    }).get_json()
    headers2 = {"Authorization": f"Bearer {login2['access_token']}"}

    me_after = client.get("/users/me", headers=headers2).get_json()
    assert me_after["password_changed_at"] is not None


def test_refresh_after_password_change_reports_password_changed(client, regular_user, app):
    first = client.post("/oauth/token", json={
        "grantType": "password",
        "username": regular_user.username,
        "password": regular_user.password,
    }).get_json()

    # Simular el cambio de contraseña: marca posterior a la creación del refresh
    # token + revocación (evita la ambigüedad de "mismo segundo").
    with app.app_context():
        with unit_of_work.UnitOfWork() as uow:
            user = UserRepository(uow).get_by_id(regular_user.id)
            user.password_changed_at = datetime.utcnow() + timedelta(minutes=1)
        OAuthTokenManager().revoke_all_user_tokens(regular_user.id)

    resp = client.post("/oauth/token", json={
        "grantType": "refresh_token",
        "refresh_token": first["refresh_token"],
    })
    assert resp.status_code == 401
    assert resp.get_json().get("code") == 1609
