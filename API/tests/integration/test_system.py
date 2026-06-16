"""Tests de integración del módulo system."""

import pytest

pytestmark = pytest.mark.integration


def test_say_hello_is_public(client):
    resp = client.get("/system/say-hello")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_status_requires_authentication(client):
    assert client.get("/system/status").status_code == 401


def test_status_requires_admin_role(client, regular_user, auth_headers):
    assert client.get("/system/status", headers=auth_headers(regular_user)).status_code == 403


def test_get_config_requires_authentication(client):
    assert client.get("/system").status_code == 401


def test_get_config_requires_admin(client, regular_user, auth_headers):
    assert client.get("/system", headers=auth_headers(regular_user)).status_code == 403


def test_admin_reads_full_config(client, admin_user, auth_headers):
    resp = client.get("/system", headers=auth_headers(admin_user))
    assert resp.status_code == 200
    # SecOpsConfig.json contiene appVersion.
    assert "appVersion" in resp.get_json()


def test_task_endpoints_require_admin(client, regular_user, auth_headers):
    headers = auth_headers(regular_user)
    assert client.get("/system/tasks/status", headers=headers).status_code == 403
    assert client.get("/system/tasks", headers=headers).status_code == 403
