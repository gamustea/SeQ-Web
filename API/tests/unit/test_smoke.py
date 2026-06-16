"""Smoke test: valida que la infraestructura de tests arranca correctamente."""

import pytest


@pytest.mark.integration
def test_app_boots_and_serves_health(client):
    resp = client.get("/system/say-hello")
    assert resp.status_code == 200


@pytest.mark.integration
def test_auth_headers_authenticate(client, regular_user, auth_headers):
    headers = auth_headers(regular_user)
    resp = client.get("/users/me", headers=headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["username"] == regular_user.username
