"""Gate de activación de capacidades activas y su plumbing (plan activo §4).

El corazón del encargo: el modo activo NUNCA corre por omisión, cada check activo
exige habilitación por nombre MÁS doble confirmación, y pedir activo sin confirmar
ABORTA en vez de degradar en silencio.
"""
from __future__ import annotations

import json

import httpx
import pytest
import respx

from idata_sentinel.core.active_gate import ActiveCapabilityGate
from idata_sentinel.core.authorization import AuditLogger, AuthorizationGate, AuthorizationRequest
from idata_sentinel.core.engine import Engine, ScanRequest
from idata_sentinel.core.session import ClientSession, SessionError


class _Active:
    """Doble mínimo de un check activo, para probar el gate sin un check real."""

    def __init__(self, cid: str, active: bool = True) -> None:
        self.id = cid
        self.active = active


# -- ActiveCapabilityGate ---------------------------------------------------


def test_non_active_check_always_passes():
    gate = ActiveCapabilityGate.disabled()
    assert gate.allows(_Active("x", active=False), authorized=False) is True


def test_active_check_needs_authorization_ack_and_name():
    gate = ActiveCapabilityGate(frozenset({"http_methods"}), acknowledged=True)
    check = _Active("http_methods")
    assert gate.allows(check, authorized=True) is True
    assert gate.allows(check, authorized=False) is False          # falta gate legal
    assert ActiveCapabilityGate(frozenset({"http_methods"}), acknowledged=False).allows(
        check, authorized=True) is False                           # falta confirmación
    assert ActiveCapabilityGate(frozenset(), acknowledged=True).allows(
        check, authorized=True) is False                           # no fue nombrado


def test_resolve_expands_all_and_drops_unknown():
    available = ["http_methods", "cors_config"]
    g_all = ActiveCapabilityGate.resolve(["all"], acknowledged=True, available=available)
    assert g_all.enabled == frozenset(available)

    g_named = ActiveCapabilityGate.resolve(
        ["cors_config", "no_existe"], acknowledged=True, available=available)
    assert g_named.enabled == frozenset({"cors_config"})           # desconocido descartado


def test_disabled_gate_enables_nothing():
    gate = ActiveCapabilityGate.disabled()
    assert gate.enabled == frozenset() and gate.acknowledged is False


# -- ClientSession ----------------------------------------------------------


def test_session_attaches_only_within_scope():
    s = ClientSession(kind="cookie", material="sid=abc", scope_hosts=frozenset({"cliente.cl"}))
    assert s.header_for("https://cliente.cl/panel") == {"Cookie": "sid=abc"}
    assert s.header_for("https://app.cliente.cl/x") == {"Cookie": "sid=abc"}  # subdominio
    assert s.header_for("https://otro.com/x") is None                        # fuera de scope


def test_bearer_session_uses_authorization_header():
    s = ClientSession(kind="bearer", material="tok123", scope_hosts=frozenset({"cliente.cl"}))
    assert s.header_for("https://cliente.cl/") == {"Authorization": "Bearer tok123"}


def test_session_material_never_appears_in_repr():
    s = ClientSession(kind="cookie", material="sid=SECRETO", scope_hosts=frozenset({"cliente.cl"}))
    assert "SECRETO" not in repr(s)
    assert "redacted" in repr(s)


def test_session_from_file_roundtrip(tmp_path):
    p = tmp_path / "sesion.json"
    p.write_text(json.dumps({
        "type": "cookie", "value": "sid=abc", "scope_hosts": ["cliente.cl"],
    }), encoding="utf-8")
    s = ClientSession.from_file(p)
    assert s.kind == "cookie" and s.scope_hosts == frozenset({"cliente.cl"})


@pytest.mark.parametrize("payload", [
    {"type": "cookie", "value": "", "scope_hosts": ["x.cl"]},        # material vacío
    {"type": "otro", "value": "v", "scope_hosts": ["x.cl"]},         # tipo inválido
    {"type": "cookie", "value": "v", "scope_hosts": []},             # sin scope
])
def test_session_from_dict_rejects_bad_input(payload):
    with pytest.raises(SessionError):
        ClientSession.from_dict(payload)


# -- integración con el engine (doble gate end-to-end) ----------------------


def _grant() -> AuthorizationRequest:
    return AuthorizationRequest(
        target="https://example.test", allowed_domains=("example.test",),
        authorized_by="Ana, CISO", contract_reference="OC-1", confirmed=True,
    )


def _engine(tmp_path) -> Engine:
    e = Engine(rate_limit_seconds=0.0)
    e.authorization_gate = AuthorizationGate(AuditLogger(tmp_path / "audit_log.json"))
    return e


@respx.mock
async def test_active_context_is_logged_before_execution(tmp_path):
    respx.get(url__regex=r"https://example\.test.*").mock(return_value=httpx.Response(200, text="<html></html>"))
    engine = _engine(tmp_path)

    await engine.scan(ScanRequest(
        target="https://example.test", mode="audit", authorization=_grant(),
        active_checks=frozenset({"http_methods"}), active_acknowledged=True,
    ))

    log = (tmp_path / "audit_log.json").read_text(encoding="utf-8")
    entry = json.loads(log.strip().splitlines()[-1])
    assert entry["decision"] == "granted"
    assert entry["active_checks_enabled"] == ["http_methods"]
    assert entry["active_acknowledged"] is True
    assert entry["authenticated_scan"] is False


@respx.mock
async def test_active_capabilities_are_dropped_when_authorization_fails(tmp_path):
    """Regresión legal: si la autorización falla, el escaneo degrada a pasivo y
    NINGUNA capacidad activa ni sesión sobrevive."""
    respx.get(url__regex=r"https://example\.test.*").mock(return_value=httpx.Response(200, text="<html></html>"))
    engine = _engine(tmp_path)

    captured = {}

    class _Spy:
        name = "vuln_identification"

        async def run(self, params):
            captured["active_checks"] = params.active_checks
            captured["session"] = params.client_session
            return []

    engine.register_module(_Spy())

    # Autorización fuera de scope -> degrada a passive.
    result = await engine.scan(ScanRequest(
        target="https://example.test", mode="audit",
        authorization=AuthorizationRequest(
            target="https://example.test", allowed_domains=("otro.cl",),
            authorized_by="Ana", contract_reference="OC-1", confirmed=True),
        active_checks=frozenset({"http_methods"}), active_acknowledged=True,
        client_session=ClientSession(kind="cookie", material="x", scope_hosts=frozenset({"example.test"})),
    ))

    assert result["mode"] == "passive"
    assert captured["active_checks"] == frozenset()
    assert captured["session"] is None
