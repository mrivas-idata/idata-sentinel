"""Comparación contra el baseline de hardening (plan activo §5).

Convierte el campo antes muerto `hardening_baseline` en un comparador real: la
severidad la hereda del baseline y el hallazgo es `confidence="confirmed"` porque
cruza dos señales independientes (lo observado y lo acordado por escrito).
"""
from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.checks.cookies import CookiesCheck
from idata_sentinel.checks.http_headers import HttpHeadersCheck
from idata_sentinel.core.baseline import (
    BaselineError,
    HardeningBaseline,
    compare_headers,
)


def _base() -> dict:
    return {
        "version": 3,
        "defaults": {
            "headers": {
                "strict-transport-security": {
                    "required": True, "must_match": "max-age=[0-9]{8,}", "severity": "high",
                },
                "content-security-policy": {"required": True, "severity": "medium"},
            },
            "cookies": {"require_secure": True, "require_httponly": True, "severity": "medium"},
            "tls": {"min_version": "TLSv1.2", "severity": "high"},
        },
        "paths": {
            "/checkout": {
                "headers": {"strict-transport-security": {"required": True, "severity": "critical"}},
                "methods": {"allowed": ["GET", "POST"], "severity": "high"},
            },
        },
    }


# -- carga y fusión ---------------------------------------------------------


def test_load_reads_version_and_sections():
    b = HardeningBaseline.load(_base())
    assert b.version == 3
    assert "strict-transport-security" in b.header_rules("/")


def test_path_override_wins_over_defaults():
    b = HardeningBaseline.load(_base())
    # En /checkout, HSTS hereda la severidad critical del override…
    assert b.header_rules("/checkout")["strict-transport-security"].severity == "critical"
    # …pero CSP sigue viniendo de defaults (fusión por clave, no reemplazo total).
    assert "content-security-policy" in b.header_rules("/checkout")


def test_cookie_tls_and_methods_policies():
    b = HardeningBaseline.load(_base())
    assert b.cookie_policy("/").require_secure is True
    assert b.tls_min_version("/") == ("TLSv1.2", "high")
    assert b.methods_policy("/checkout").allowed == frozenset({"GET", "POST"})
    assert b.methods_policy("/") is None  # solo definido en /checkout


def test_invalid_regex_and_severity_are_rejected():
    with pytest.raises(BaselineError):
        HardeningBaseline.load({"defaults": {"headers": {"x": {"must_match": "([unclosed"}}}})
    with pytest.raises(BaselineError):
        HardeningBaseline.load({"defaults": {"headers": {"x": {"severity": "apocalíptica"}}}})


# -- comparador puro --------------------------------------------------------


def test_compare_headers_flags_missing_and_value_mismatch():
    rules = HardeningBaseline.load(_base()).header_rules("/")
    observed = {"content-security-policy": "default-src 'self'", "strict-transport-security": "max-age=300"}
    mismatches = {m.key: m.kind for m in compare_headers(observed, rules)}
    assert mismatches == {"strict-transport-security": "value"}  # CSP ok; HSTS presente pero corto


def test_compare_headers_silent_when_compliant():
    rules = HardeningBaseline.load(_base()).header_rules("/")
    observed = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=63072000; includeSubDomains",
    }
    assert compare_headers(observed, rules) == []


# -- integración con los checks ---------------------------------------------


def _with_baseline(ctx, raw: dict):
    ctx._compiled_baseline = HardeningBaseline.load(raw)
    return ctx


@respx.mock
async def test_http_headers_emits_baseline_mismatch_with_inherited_severity(make_ctx):
    # HSTS presente pero débil → mismatch de valor, severidad heredada (high).
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, headers={"strict-transport-security": "max-age=300",
                      "content-security-policy": "default-src 'self'"}, text="<html></html>"))
    ctx = _with_baseline(make_ctx(), _base())

    results = await HttpHeadersCheck().run(ctx)
    m = next(r for r in results if r.id.startswith("header_baseline_mismatch_strict-transport-security"))
    assert m.severity == "high"           # heredada del baseline, no del check
    assert m.confidence == "confirmed"    # dos señales: observado + acordado
    assert m.status == "fail"


@respx.mock
async def test_cookies_emit_baseline_mismatch(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, headers={"set-cookie": "sid=abc; Path=/"}, text="<html></html>"))  # sin Secure/HttpOnly
    ctx = _with_baseline(make_ctx(), _base())

    results = await CookiesCheck().run(ctx)
    m = next(r for r in results if r.id.startswith("cookie_baseline_mismatch"))
    assert m.severity == "medium" and m.confidence == "confirmed"
    assert "Secure" in m.finding and "HttpOnly" in m.finding


@respx.mock
async def test_no_baseline_means_no_mismatch_findings(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, headers={"set-cookie": "sid=abc"}, text="<html></html>"))
    results = await CookiesCheck().run(make_ctx())  # sin baseline compilado
    assert not any(r.id.startswith("cookie_baseline_mismatch") for r in results)


@respx.mock
async def test_malformed_baseline_yields_baseline_invalid_not_fake_mismatches():
    """Un baseline roto se declara no evaluable; jamás se inventan mismatches."""
    from idata_sentinel.core.engine import RunParams
    from idata_sentinel.core.http_client import HttpClient
    from idata_sentinel.core.rate_limiter import RateLimiter
    from idata_sentinel.core.authorization import AuthorizationRequest
    from idata_sentinel.modules.vuln_identification.module import VulnIdentificationModule

    respx.get(url__regex=r"https?://example\.test.*").mock(
        return_value=httpx.Response(200, text="<html></html>"))

    async with HttpClient() as http:
        params = RunParams(
            target="https://example.test", host="example.test", mode="audit",
            http=http, rate_limiter=RateLimiter(min_interval=0.0), authorized=True,
            authorization=AuthorizationRequest(
                target="https://example.test", allowed_domains=("example.test",),
                authorized_by="Ana", contract_reference="OC-1", confirmed=True,
                hardening_baseline={"defaults": {"headers": {"x": {"must_match": "([bad"}}}},
            ),
        )
        findings = await VulnIdentificationModule().run(params)

    invalid = [f for f in findings if f["id"].startswith("baseline_invalid")]
    assert len(invalid) == 1 and invalid[0]["confidence"] == "unverified"
    assert not any("baseline_mismatch" in f["id"] for f in findings)
