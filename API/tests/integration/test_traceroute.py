"""Tests de integración del traceroute cacheado del módulo Sentinel.

Cubre la frontera de autorización, el cacheo por (usuario, target), el
recálculo forzado, la invalidación por antigüedad y el aislamiento entre
usuarios. El comando real ``traceroute`` se mockea para no depender del binario
ni de la red.
"""

from datetime import datetime, timedelta
from unittest import mock

import pytest

pytestmark = pytest.mark.integration


_TARGET = "93.184.216.34"
_HOPS = [
    {"ttl": 1, "ip": "192.168.1.1", "hostname": "router", "rtt_ms": 1.2},
    {"ttl": 2, "ip": None, "hostname": None, "rtt_ms": None},
    {"ttl": 3, "ip": _TARGET, "hostname": None, "rtt_ms": 10.0},
]

_TRACE_PATH = "src.modules.sentinel.services.traceroute.TracerouteService.trace"


def _create_scan(app, user_id: int, target: str = _TARGET) -> int:
    """Persist a finished NmapScan owned by ``user_id`` and return its id."""
    from src.modules.infrastructure import unit_of_work as uow_mod
    from src.modules.sentinel.repositories import ScanRepository
    from src.modules.sentinel.model import NmapScan

    with app.app_context():
        with uow_mod.UnitOfWork() as uow:
            scan = NmapScan(target=target, user_id=user_id)
            ScanRepository(uow).save(scan)
            return scan.id


def _url(scan_id: int) -> str:
    return f"/sentinel/scan/{scan_id}/traceroute"


# ------------------------------------------------------------------ autorización

def test_traceroute_requires_authentication(client, app, regular_user):
    scan_id = _create_scan(app, regular_user.id)
    assert client.get(_url(scan_id)).status_code == 401


def test_traceroute_scan_not_found(client, regular_user, auth_headers):
    resp = client.get(_url(999999), headers=auth_headers(regular_user))
    assert resp.status_code == 404


# ------------------------------------------------------------------ caché

def test_traceroute_computes_then_serves_from_cache(client, app, regular_user, auth_headers):
    scan_id = _create_scan(app, regular_user.id)
    headers = auth_headers(regular_user)

    with mock.patch(_TRACE_PATH, return_value=_HOPS) as traced:
        first = client.get(_url(scan_id), headers=headers)
        assert first.status_code == 200
        body = first.get_json()
        assert body["hops"] == _HOPS
        assert body["hopCount"] == 3
        assert body["target"] == _TARGET
        assert body["cached"] is False

        # La segunda lectura sale de la BD: no se vuelve a ejecutar el comando.
        second = client.get(_url(scan_id), headers=headers)
        assert second.status_code == 200
        assert second.get_json()["cached"] is True

        assert traced.call_count == 1


def test_refresh_forces_recompute(client, app, regular_user, auth_headers):
    scan_id = _create_scan(app, regular_user.id)
    headers = auth_headers(regular_user)

    with mock.patch(_TRACE_PATH, return_value=_HOPS) as traced:
        client.get(_url(scan_id), headers=headers)  # primer cálculo (cachea)

        refreshed = client.post(f"{_url(scan_id)}/refresh", headers=headers)
        assert refreshed.status_code == 200
        assert refreshed.get_json()["cached"] is False
        assert traced.call_count == 2


def test_stale_cache_is_recomputed(client, app, regular_user, auth_headers):
    scan_id = _create_scan(app, regular_user.id)
    headers = auth_headers(regular_user)

    with mock.patch(_TRACE_PATH, return_value=_HOPS) as traced:
        client.get(_url(scan_id), headers=headers)  # cachea con created_at = now

        # Envejecer la entrada por encima del TTL (24 h por defecto).
        from src.modules.infrastructure import unit_of_work as uow_mod
        from src.modules.sentinel.repositories import TracerouteRepository
        with app.app_context():
            with uow_mod.UnitOfWork() as uow:
                repo = TracerouteRepository(uow)
                trace = repo.get_by_user_and_target(regular_user.id, _TARGET)
                trace.created_at = datetime.utcnow() - timedelta(hours=48)

        again = client.get(_url(scan_id), headers=headers)
        assert again.status_code == 200
        assert again.get_json()["cached"] is False
        assert traced.call_count == 2


# ------------------------------------------------------------------ aislamiento

def test_traceroute_isolation_between_users(client, app, make_user, auth_headers):
    owner = make_user(role="role_user")
    other = make_user(role="role_user")
    scan_id = _create_scan(app, owner.id)

    with mock.patch(_TRACE_PATH, return_value=_HOPS):
        resp = client.get(_url(scan_id), headers=auth_headers(other))
        assert resp.status_code == 404


def test_traceroute_cache_is_scoped_per_user(client, app, make_user, auth_headers):
    # Dos usuarios con el mismo target mantienen cachés independientes.
    user_a = make_user(role="role_user")
    user_b = make_user(role="role_user")
    scan_a = _create_scan(app, user_a.id)
    scan_b = _create_scan(app, user_b.id)

    with mock.patch(_TRACE_PATH, return_value=_HOPS) as traced:
        assert client.get(_url(scan_a), headers=auth_headers(user_a)).status_code == 200
        assert client.get(_url(scan_b), headers=auth_headers(user_b)).status_code == 200
        # Cada usuario calcula la suya pese a compartir target.
        assert traced.call_count == 2
