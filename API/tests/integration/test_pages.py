"""Tests de integración del blueprint de páginas."""

import pytest

pytestmark = pytest.mark.integration


def test_unknown_page_requires_authentication(client):
    # serve_page exige token; sin él devuelve 401 antes de comprobar si existe.
    resp = client.get("/pages/pagina-que-no-existe")
    assert resp.status_code == 401


def test_unknown_page_returns_404_when_authenticated(client, regular_user, auth_headers):
    resp = client.get("/pages/pagina-que-no-existe", headers=auth_headers(regular_user))
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "not_found"


def test_login_page_served_or_missing(client):
    # /pages/login es público; nunca debe exigir autenticación.
    resp = client.get("/pages/login")
    assert resp.status_code in (200, 404)
