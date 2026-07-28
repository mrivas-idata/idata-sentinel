from __future__ import annotations

import httpx
import respx

from idata_sentinel.core.engine import ModuleOutput, RunParams
from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.core.rate_limiter import RateLimiter
from idata_sentinel.modules.data_privacy.compliance import (
    base_id,
    build_compliance_checklist,
)
from idata_sentinel.modules.data_privacy.module import DataPrivacyModule
from idata_sentinel.core.check_base import FINDING_CONTRACT_KEYS

_CONTRACT_KEYS = FINDING_CONTRACT_KEYS

_LEAKY_PAGE = (
    '<script src="https://www.google-analytics.com/analytics.js"></script>'
    '<form action="http://example.test/enviar"><input name="rut"><input name="isapre"></form>'
)


def _params(*, previous=None, mode="passive") -> RunParams:
    return RunParams(
        target="https://example.test",
        host="example.test",
        mode=mode,
        http=HttpClient(),
        rate_limiter=RateLimiter(min_interval=0.0),
        authorized=False,
        authorization=None,
        previous_findings=previous or [],
    )


def _finding(fid: str, *, severity="high", status="fail", module="vuln_identification") -> dict:
    return {
        "id": fid, "module": module, "category": "Test", "severity": severity,
        "likelihood": "high", "status": status, "title": f"Título de {fid}",
        "finding": "f", "business_impact": "b", "recommendation": "r",
        "evidence": "e", "references": [],
    }


# -- runner ----------------------------------------------------------------


@respx.mock
async def test_module_returns_findings_and_compliance_artifact():
    respx.get("https://example.test/").mock(return_value=httpx.Response(200, text=_LEAKY_PAGE))
    output = await DataPrivacyModule().run(_params())

    assert isinstance(output, ModuleOutput)
    assert "compliance_21719" in output.artifacts
    assert output.findings


@respx.mock
async def test_all_findings_conform_to_contract():
    respx.get("https://example.test/").mock(return_value=httpx.Response(200, text=_LEAKY_PAGE))
    output = await DataPrivacyModule().run(_params())

    for f in output.findings:
        assert set(f) == _CONTRACT_KEYS
        assert f["module"] == "data_privacy"
        assert f["severity"] in {"info", "low", "medium", "high", "critical"}
        assert f["status"] in {"pass", "fail", "warning", "info"}


@respx.mock
async def test_page_is_fetched_once_despite_three_checks():
    """Los tres checks comparten el caché del ScanContext: un solo GET a /."""
    route = respx.get("https://example.test/").mock(
        return_value=httpx.Response(200, text=_LEAKY_PAGE))
    await DataPrivacyModule().run(_params())
    assert route.call_count == 1


@respx.mock
async def test_module_survives_unreachable_target():
    respx.get("https://example.test/").mock(side_effect=httpx.ConnectError("caído"))
    output = await DataPrivacyModule().run(_params())

    assert all(f["status"] == "info" for f in output.findings)
    assert output.artifacts["compliance_21719"]["totals"]["with_gaps"] == 0


@respx.mock
async def test_a_crashing_check_is_contained(monkeypatch):
    respx.get("https://example.test/").mock(return_value=httpx.Response(200, text="<html></html>"))

    from idata_sentinel.checks.privacy_signals import PrivacyPolicyCheck

    async def _boom(self, ctx):
        raise RuntimeError("boom")

    monkeypatch.setattr(PrivacyPolicyCheck, "run", _boom)
    output = await DataPrivacyModule().run(_params())

    assert any(f["id"] == "privacy_policy_error" for f in output.findings)


# -- checklist de cumplimiento ---------------------------------------------


def test_base_id_strips_the_location_suffix():
    assert base_id("pii_form_insecure_transport@/contacto#form0") == "pii_form_insecure_transport"
    assert base_id("privacy_policy_missing") == "privacy_policy_missing"


def test_checklist_covers_every_principle_even_without_findings():
    checklist = build_compliance_checklist([])
    names = {p["principle"] for p in checklist["principles"]}

    assert names == {"licitud", "informacion", "finalidad", "proporcionalidad", "seguridad"}
    assert all(p["status"] == "sin_hallazgos" for p in checklist["principles"])
    assert checklist["totals"]["with_gaps"] == 0


def test_fail_marks_a_gap_and_warning_marks_an_observation():
    checklist = build_compliance_checklist([
        _finding("privacy_policy_missing", module="data_privacy"),
        _finding("international_data_transfer", severity="medium", status="warning", module="data_privacy"),
    ])
    by_name = {p["principle"]: p for p in checklist["principles"]}

    assert by_name["informacion"]["status"] == "brecha"
    assert by_name["finalidad"]["status"] == "observacion"
    assert by_name["licitud"]["status"] == "sin_hallazgos"
    assert checklist["totals"] == {"evaluated": 5, "with_gaps": 1, "with_observations": 1, "clean": 3}


def test_security_principle_is_fed_by_other_modules():
    """El deber de seguridad se evidencia con hallazgos del Módulo 1 y 2."""
    checklist = build_compliance_checklist([
        _finding("cert_expired", severity="critical"),
        _finding("asset_without_https@dev.example.test", module="asset_inventory"),
    ])
    seguridad = next(p for p in checklist["principles"] if p["principle"] == "seguridad")

    assert seguridad["status"] == "brecha"
    assert seguridad["gap_count"] == 2
    assert seguridad["findings"][0]["severity"] == "critical"  # ordenado por severidad


def test_informative_findings_do_not_create_gaps():
    checklist = build_compliance_checklist([
        _finding("privacy_policy_present", severity="info", status="pass", module="data_privacy"),
    ])
    assert checklist["totals"]["with_gaps"] == 0


def test_checklist_always_carries_the_legal_disclaimer():
    assert "no constituye una calificación legal" in build_compliance_checklist([])["disclaimer"].lower()


@respx.mock
async def test_previous_findings_flow_into_the_checklist():
    respx.get("https://example.test/").mock(return_value=httpx.Response(200, text="<html></html>"))
    output = await DataPrivacyModule().run(_params(previous=[_finding("cert_expired")]))

    seguridad = next(
        p for p in output.artifacts["compliance_21719"]["principles"] if p["principle"] == "seguridad"
    )
    assert seguridad["status"] == "brecha"
