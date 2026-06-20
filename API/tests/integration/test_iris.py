"""Tests de integración del módulo Iris (análisis de cabeceras)."""

import pytest

pytestmark = pytest.mark.integration


def test_analyze_requires_authentication(client):
    assert client.post("/iris/analyze", json={"headers": "From: a@b.com"}).status_code == 401


def test_analyze_requires_create_attribute(client, regular_user, auth_headers):
    # role_user tiene iris_read pero no iris_create.
    resp = client.post("/iris/analyze", headers=auth_headers(regular_user),
                       json={"headers": "From: a@b.com\nSubject: Hi"})
    assert resp.status_code == 403


def test_list_results_empty(client, regular_user, auth_headers):
    resp = client.get("/iris/results?page=1&per_page=10", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    assert resp.get_json()["total"] == 0


def test_status_unknown_analysis_returns_404(client, regular_user, auth_headers):
    resp = client.get("/iris/status?id=999999", headers=auth_headers(regular_user))
    assert resp.status_code == 404


def test_delete_requires_delete_attribute(client, regular_user, auth_headers):
    # role_user no tiene iris_delete -> 403 antes de tocar la BD.
    resp = client.delete("/iris/results/1", headers=auth_headers(regular_user))
    assert resp.status_code == 403
