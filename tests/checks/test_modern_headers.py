from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.checks.modern_headers import (
    ModernHeadersCheck,
    has_strict_source,
    parse_csp,
)
from idata_sentinel.core.check_base import FINDING_CONTRACT_KEYS

URL = "https://example.test/"


def _ids(results) -> set[str]:
    return {r.id.split("@")[0] for r in results}


async def _run(make_ctx, headers: dict, **ctx_kwargs) -> list:
    respx.get(URL).mock(return_value=httpx.Response(200, headers=headers, text="<html></html>"))
    return await ModernHeadersCheck().run(make_ctx(**ctx_kwargs))


# -- funciones puras -------------------------------------------------------


def test_parse_csp_splits_directives_and_sources():
    policy = parse_csp("default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'; base-uri 'none'")
    assert policy["default-src"] == ["'self'"]
    assert policy["script-src"] == ["'nonce-abc'", "'strict-dynamic'"]
    assert "base-uri" in policy


def test_parse_csp_tolerates_extra_semicolons_and_case():
    assert "default-src" in parse_csp("  DEFAULT-SRC 'self' ;; ")


@pytest.mark.parametrize(
    "sources,expected",
    [
        (["'nonce-abc123'"], True),
        (["'sha256-xyz'"], True),
        (["'strict-dynamic'"], True),
        (["'self'", "https://cdn.test"], False),
        (["'unsafe-inline'"], False),
        ([], False),
    ],
)
def test_has_strict_source(sources, expected):
    assert has_strict_source(sources) is expected


# -- aislamiento de origen -------------------------------------------------


@respx.mock
async def test_coop_missing_is_reported(make_ctx):
    assert "coop_missing" in _ids(await _run(make_ctx, {}))


@respx.mock
async def test_coop_present_is_silent(make_ctx):
    ids = _ids(await _run(make_ctx, {"Cross-Origin-Opener-Policy": "same-origin"}))
    assert "coop_missing" not in ids
    assert "coop_unsafe_none" not in ids


@respx.mock
async def test_coop_unsafe_none_is_flagged_separately(make_ctx):
    results = await _run(make_ctx, {"Cross-Origin-Opener-Policy": "unsafe-none"})
    finding = next(r for r in results if r.id.startswith("coop_unsafe_none"))
    assert finding.status == "warning"


@respx.mock
async def test_corp_missing_and_present(make_ctx):
    assert "corp_missing" in _ids(await _run(make_ctx, {}))
    assert "corp_missing" not in _ids(
        await _run(make_ctx, {"Cross-Origin-Resource-Policy": "same-origin"})
    )


# -- CORS ------------------------------------------------------------------


@respx.mock
async def test_wildcard_with_credentials_is_high(make_ctx):
    results = await _run(make_ctx, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })
    finding = next(r for r in results if r.id.startswith("cors_wildcard_with_credentials"))
    assert (finding.severity, finding.status) == ("high", "fail")


@respx.mock
async def test_null_origin_is_rejected(make_ctx):
    results = await _run(make_ctx, {"Access-Control-Allow-Origin": "null"})
    assert next(r for r in results if r.id.startswith("cors_null_origin")).severity == "medium"


@respx.mock
async def test_plain_wildcard_is_only_a_warning(make_ctx):
    results = await _run(make_ctx, {"Access-Control-Allow-Origin": "*"})
    assert next(r for r in results if r.id.startswith("cors_wildcard")).status == "warning"


@respx.mock
async def test_explicit_origin_is_not_flagged(make_ctx):
    ids = _ids(await _run(make_ctx, {"Access-Control-Allow-Origin": "https://app.example.test"}))
    assert not {i for i in ids if i.startswith("cors_")}


@respx.mock
async def test_absent_cors_headers_produce_nothing(make_ctx):
    assert not {i for i in _ids(await _run(make_ctx, {})) if i.startswith("cors_")}


# -- calidad de la CSP -----------------------------------------------------


@respx.mock
async def test_missing_base_uri_is_the_nonce_bypass(make_ctx):
    results = await _run(make_ctx, {
        "Content-Security-Policy": "default-src 'self'; script-src 'nonce-abc'"
    })
    finding = next(r for r in results if r.id.startswith("csp_missing_base_uri"))
    assert finding.severity == "medium"
    assert "base" in finding.business_impact.lower()


@respx.mock
async def test_complete_strict_csp_passes(make_ctx):
    results = await _run(make_ctx, {
        "Content-Security-Policy":
            "default-src 'none'; script-src 'nonce-abc' 'strict-dynamic'; "
            "object-src 'none'; base-uri 'none'"
    })
    ids = _ids(results)
    assert "csp_missing_base_uri" not in ids
    assert "csp_script_src_permissive" not in ids
    assert next(r for r in results if r.id.startswith("csp_strict_configured")).status == "pass"


@respx.mock
async def test_allowlist_csp_without_nonce_is_permissive(make_ctx):
    results = await _run(make_ctx, {
        "Content-Security-Policy":
            "default-src 'self'; script-src 'self' 'unsafe-inline' https:; base-uri 'none'"
    })
    finding = next(r for r in results if r.id.startswith("csp_script_src_permissive"))
    assert finding.status == "fail"


@respx.mock
async def test_report_only_csp_is_not_enforced(make_ctx):
    results = await _run(make_ctx, {
        "Content-Security-Policy-Report-Only": "default-src 'self'"
    })
    finding = next(r for r in results if r.id.startswith("csp_report_only_not_enforced"))
    assert finding.severity == "medium"


@respx.mock
async def test_absent_csp_is_left_to_the_classic_check(make_ctx):
    assert not {i for i in _ids(await _run(make_ctx, {})) if i.startswith("csp_")}


@respx.mock
async def test_object_src_covered_by_default_src(make_ctx):
    ids = _ids(await _run(make_ctx, {
        "Content-Security-Policy": "default-src 'none'; base-uri 'none'"
    }))
    assert "csp_missing_object_src" not in ids


# -- legado ----------------------------------------------------------------


@respx.mock
async def test_legacy_xss_filter_is_flagged(make_ctx):
    results = await _run(make_ctx, {"X-XSS-Protection": "1; mode=block"})
    assert next(r for r in results if r.id.startswith("xss_protection_legacy")).status == "warning"


@respx.mock
async def test_xss_protection_zero_is_correct(make_ctx):
    assert "xss_protection_legacy" not in _ids(await _run(make_ctx, {"X-XSS-Protection": "0"}))


@respx.mock
async def test_hsts_without_preload_is_informative(make_ctx):
    results = await _run(make_ctx, {"Strict-Transport-Security": "max-age=31536000"})
    finding = next(r for r in results if r.id.startswith("hsts_not_preloaded"))
    assert finding.status == "info"


@respx.mock
async def test_hsts_with_preload_is_silent(make_ctx):
    ids = _ids(await _run(make_ctx, {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"
    }))
    assert "hsts_not_preloaded" not in ids


# -- robustez y contrato ---------------------------------------------------


@respx.mock
async def test_unreachable_target_produces_no_findings(make_ctx):
    respx.get(URL).mock(side_effect=httpx.ConnectError("caído"))
    assert await ModernHeadersCheck().run(make_ctx()) == []


@respx.mock
async def test_audit_mode_adds_client_paths(make_ctx):
    respx.get(URL).mock(return_value=httpx.Response(200, text="ok"))
    respx.get("https://example.test/admin").mock(return_value=httpx.Response(200, text="ok"))

    results = await ModernHeadersCheck().run(
        make_ctx(mode="audit", authorized=True, audit_paths=("/admin",))
    )
    assert any(r.id.endswith("@/admin") for r in results)


@respx.mock
async def test_unauthorized_audit_behaves_as_passive(make_ctx):
    respx.get(URL).mock(return_value=httpx.Response(200, text="ok"))
    results = await ModernHeadersCheck().run(
        make_ctx(mode="audit", authorized=False, audit_paths=("/admin",))
    )
    assert not any(r.id.endswith("@/admin") for r in results)


@respx.mock
async def test_all_results_conform_to_contract(make_ctx):
    results = await _run(make_ctx, {
        "Access-Control-Allow-Origin": "null",
        "Content-Security-Policy": "script-src https:",
        "X-XSS-Protection": "1",
    })
    assert results
    for r in results:
        assert r.module == "vuln_identification"
        assert set(r.to_dict()) == FINDING_CONTRACT_KEYS
