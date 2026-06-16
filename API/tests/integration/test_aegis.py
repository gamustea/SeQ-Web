"""Tests de integración del módulo Aegis (píldoras de concienciación)."""

import pytest

pytestmark = pytest.mark.integration


def test_generate_requires_authentication(client):
    assert client.post("/aegis/generate", json={"topicId": 1}).status_code == 401


def test_generate_requires_create_attribute(client, regular_user, auth_headers):
    # role_user tiene aegis_read pero no aegis_create.
    resp = client.post("/aegis/generate", headers=auth_headers(regular_user),
                       json={"topicId": 1})
    assert resp.status_code == 403


def test_list_documents_empty(client, regular_user, auth_headers):
    resp = client.get("/aegis/documents", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    assert resp.get_json()["count"] == 0


@pytest.mark.xfail(
    reason="require_attributes captura la excepción de dominio y devuelve 500 "
           "en lugar de 404. Ver IMPROVEMENTS.md.",
    strict=True,
)
def test_status_unknown_document_returns_404(client, regular_user, auth_headers):
    resp = client.get("/aegis/status?id=999999", headers=auth_headers(regular_user))
    assert resp.status_code == 404


def test_brands_catalog_available(client, regular_user, auth_headers):
    resp = client.get("/aegis/brands", headers=auth_headers(regular_user))
    assert resp.status_code == 200
    assert "brands" in resp.get_json()
