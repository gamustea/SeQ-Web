"""Tests de integración del blueprint de páginas.

Nota: ``serve_page`` NO aplica autenticación pese a documentarlo (ver
IMPROVEMENTS.md); estos tests fijan el comportamiento real actual.
"""

import pytest

pytestmark = pytest.mark.integration


def test_unknown_page_returns_404(client):
    resp = client.get("/pages/pagina-que-no-existe")
    assert resp.status_code == 404
    assert resp.get_json()["error"] == "not_found"


def test_login_page_served_or_missing(client):
    # Según el entorno, login.html puede existir (200) o no (404), pero
    # nunca debe exigir autenticación.
    resp = client.get("/pages/login")
    assert resp.status_code in (200, 404)
