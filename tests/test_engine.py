from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.core.authorization import AuditLogger, AuthorizationGate, AuthorizationRequest
from idata_sentinel.core.engine import Engine, ModuleOutput, RunParams, ScanRequest


class _RecordingModule:
    """Módulo de prueba: registra qué recibió, devuelve un hallazgo y un artefacto."""

    def __init__(self, name: str, artifacts: dict | None = None) -> None:
        self.name = name
        self.artifacts = artifacts or {}
        self.seen: list[RunParams] = []

    async def run(self, params: RunParams):
        self.seen.append(params)
        finding = {
            "id": f"{self.name}_finding", "module": self.name, "category": "Test",
            "severity": "low", "likelihood": "low", "status": "fail", "title": "t",
            "finding": "f", "business_impact": "b", "recommendation": "r",
            "evidence": "e", "references": [],
        }
        if self.artifacts:
            return ModuleOutput(findings=[finding], artifacts=self.artifacts)
        return [finding]


def _engine() -> Engine:
    return Engine(rate_limit_seconds=0.0)


@respx.mock
async def test_scan_aggregates_findings_and_artifacts():
    respx.get(url__regex=r"https://example\.test.*").mock(return_value=httpx.Response(404))

    engine = _engine()
    engine.register_module(_RecordingModule("vuln_identification"))
    engine.register_module(_RecordingModule("asset_inventory", {"surface_map": {"apex": "example.test"}}))

    result = await engine.scan(ScanRequest(target="https://example.test"))

    assert set(result["modules"]) == {"vuln_identification", "asset_inventory"}
    assert result["artifacts"]["asset_inventory"]["surface_map"]["apex"] == "example.test"
    assert result["mode"] == "passive"


@respx.mock
async def test_modules_run_in_canonical_order_regardless_of_registration():
    respx.get(url__regex=r"https://example\.test.*").mock(return_value=httpx.Response(404))

    order: list[str] = []

    class _Ordered(_RecordingModule):
        async def run(self, params):
            order.append(self.name)
            return await super().run(params)

    engine = _engine()
    engine.register_module(_Ordered("data_privacy"))
    engine.register_module(_Ordered("vuln_identification"))
    engine.register_module(_Ordered("asset_inventory"))

    await engine.scan(ScanRequest(target="https://example.test"))

    assert order == ["vuln_identification", "asset_inventory", "data_privacy"]


@respx.mock
async def test_later_modules_receive_earlier_findings():
    respx.get(url__regex=r"https://example\.test.*").mock(return_value=httpx.Response(404))

    privacy = _RecordingModule("data_privacy")
    engine = _engine()
    engine.register_module(_RecordingModule("vuln_identification"))
    engine.register_module(privacy)

    await engine.scan(ScanRequest(target="https://example.test"))

    seen_ids = {f["id"] for f in privacy.seen[0].previous_findings}
    assert seen_ids == {"vuln_identification_finding"}


@respx.mock
async def test_robots_is_fetched_once_and_shared():
    route = respx.get("https://example.test/robots.txt").mock(
        return_value=httpx.Response(200, text="User-agent: *\nDisallow: /admin")
    )

    module = _RecordingModule("vuln_identification")
    engine = _engine()
    engine.register_module(module)
    engine.register_module(_RecordingModule("asset_inventory"))

    await engine.scan(ScanRequest(target="https://example.test"))

    assert route.call_count == 1
    assert not module.seen[0].robots.can_fetch("/admin")


@respx.mock
async def test_missing_robots_yields_permissive_policy():
    respx.get("https://example.test/robots.txt").mock(return_value=httpx.Response(404))

    module = _RecordingModule("vuln_identification")
    engine = _engine()
    engine.register_module(module)

    await engine.scan(ScanRequest(target="https://example.test"))
    assert module.seen[0].robots.can_fetch("/cualquier-ruta")


@respx.mock
async def test_module_selection_filters_by_name():
    respx.get(url__regex=r"https://example\.test.*").mock(return_value=httpx.Response(404))

    engine = _engine()
    engine.register_module(_RecordingModule("vuln_identification"))
    engine.register_module(_RecordingModule("asset_inventory"))

    result = await engine.scan(
        ScanRequest(target="https://example.test", modules=["asset_inventory"])
    )
    assert set(result["modules"]) == {"asset_inventory"}


@respx.mock
async def test_unknown_module_name_is_ignored():
    respx.get(url__regex=r"https://example\.test.*").mock(return_value=httpx.Response(404))

    engine = _engine()
    engine.register_module(_RecordingModule("vuln_identification"))

    result = await engine.scan(
        ScanRequest(target="https://example.test", modules=["no_existe"])
    )
    assert result["modules"] == {}


# -- gate de autorización --------------------------------------------------


@respx.mock
async def test_audit_without_authorization_degrades_to_passive():
    respx.get(url__regex=r"https://example\.test.*").mock(return_value=httpx.Response(404))

    module = _RecordingModule("vuln_identification")
    engine = _engine()
    engine.register_module(module)

    result = await engine.scan(ScanRequest(target="https://example.test", mode="audit"))

    assert result["mode"] == "passive"
    assert module.seen[0].authorized is False


@respx.mock
async def test_audit_with_complete_authorization_is_granted(tmp_path):
    respx.get(url__regex=r"https://example\.test.*").mock(return_value=httpx.Response(404))

    engine = _engine()
    engine.authorization_gate = AuthorizationGate(AuditLogger(tmp_path / "audit_log.json"))
    module = _RecordingModule("vuln_identification")
    engine.register_module(module)

    result = await engine.scan(ScanRequest(
        target="https://example.test",
        mode="audit",
        authorization=AuthorizationRequest(
            target="https://example.test",
            allowed_domains=("example.test",),
            authorized_by="Ana Pérez, CISO",
            contract_reference="OC-2026-01",
            confirmed=True,
        ),
    ))

    assert result["mode"] == "audit"
    assert module.seen[0].authorized is True
    assert (tmp_path / "audit_log.json").read_text(encoding="utf-8").count("granted") == 1


@respx.mock
async def test_audit_out_of_scope_is_denied_and_logged(tmp_path):
    respx.get(url__regex=r"https://example\.test.*").mock(return_value=httpx.Response(404))

    engine = _engine()
    engine.authorization_gate = AuthorizationGate(AuditLogger(tmp_path / "audit_log.json"))
    engine.register_module(_RecordingModule("vuln_identification"))

    result = await engine.scan(ScanRequest(
        target="https://example.test",
        mode="audit",
        authorization=AuthorizationRequest(
            target="https://example.test",
            allowed_domains=("otro-cliente.test",),
            authorized_by="Ana Pérez, CISO",
            contract_reference="OC-2026-01",
            confirmed=True,
        ),
    ))

    assert result["mode"] == "passive"
    assert "denied_out_of_scope" in (tmp_path / "audit_log.json").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "kwargs,expected_decision",
    [
        ({"confirmed": False}, "denied_incomplete"),
        ({"authorized_by": ""}, "denied_incomplete"),
        ({"contract_reference": ""}, "denied_incomplete"),
    ],
)
def test_incomplete_authorization_is_rejected(tmp_path, kwargs, expected_decision):
    gate = AuthorizationGate(AuditLogger(tmp_path / "audit_log.json"))
    base = dict(
        target="https://example.test",
        allowed_domains=("example.test",),
        authorized_by="Ana Pérez, CISO",
        contract_reference="OC-1",
        confirmed=True,
    )
    assert gate.authorize(AuthorizationRequest(**{**base, **kwargs})) is False
    assert expected_decision in (tmp_path / "audit_log.json").read_text(encoding="utf-8")


def test_subdomain_of_allowed_domain_is_in_scope(tmp_path):
    gate = AuthorizationGate(AuditLogger(tmp_path / "audit_log.json"))
    assert gate.authorize(AuthorizationRequest(
        target="https://app.example.test",
        allowed_domains=("example.test",),
        authorized_by="Ana Pérez, CISO",
        contract_reference="OC-1",
        confirmed=True,
    )) is True
