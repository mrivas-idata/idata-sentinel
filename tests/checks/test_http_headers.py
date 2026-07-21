from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.checks.http_headers import HttpHeadersCheck


@pytest.mark.asyncio
@respx.mock
async def test_all_headers_missing_reports_fails(make_ctx):
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(200, headers={"Server": "nginx"}, text="<html></html>")
    )
    ctx = make_ctx()
    results = await HttpHeadersCheck().run(ctx)
    ids = {r.id for r in results}

    assert "hsts_missing" in ids
    assert "csp_missing" in ids
    assert "xfo_missing" in ids
    assert "xcto_missing" in ids
    assert "referrer_policy_missing" in ids
    assert "permissions_policy_missing" in ids
    hsts = next(r for r in results if r.id == "hsts_missing")
    assert hsts.status == "fail"
    assert hsts.severity == "medium"
    assert hsts.likelihood == "high"


@pytest.mark.asyncio
@respx.mock
async def test_secure_headers_produce_no_fail_findings(make_ctx):
    secure_headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    respx.get("https://example.test/").mock(return_value=httpx.Response(200, headers=secure_headers, text="ok"))
    ctx = make_ctx()
    results = await HttpHeadersCheck().run(ctx)

    assert not [r for r in results if r.status == "fail"]


@pytest.mark.asyncio
@respx.mock
async def test_server_version_disclosure(make_ctx):
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(200, headers={"Server": "Apache/2.4.41"}, text="ok")
    )
    ctx = make_ctx()
    results = await HttpHeadersCheck().run(ctx)
    disclosure = next(r for r in results if r.id == "server_version_disclosure")
    assert disclosure.status == "warning"
    assert "2.4.41" in disclosure.evidence


@pytest.mark.asyncio
@respx.mock
async def test_unreachable_target_produces_error_result(make_ctx):
    respx.get("https://example.test/").mock(side_effect=httpx.ConnectError("boom"))
    ctx = make_ctx()
    results = await HttpHeadersCheck().run(ctx)

    assert len(results) == 1
    assert results[0].status == "info"
    assert "http_headers_unreachable" in results[0].id


@pytest.mark.asyncio
@respx.mock
async def test_audit_mode_evaluates_extra_paths(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(200, headers={}, text="ok"))
    respx.get("https://example.test/admin").mock(return_value=httpx.Response(200, headers={}, text="ok"))
    ctx = make_ctx(mode="audit", authorized=True, audit_paths=("/admin",))
    results = await HttpHeadersCheck().run(ctx)

    assert any(r.id.endswith("@/admin") for r in results)


@pytest.mark.asyncio
@respx.mock
async def test_audit_mode_without_authorization_behaves_as_passive(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(200, headers={}, text="ok"))
    ctx = make_ctx(mode="audit", authorized=False, audit_paths=("/admin",))
    results = await HttpHeadersCheck().run(ctx)

    assert not any(r.id.endswith("@/admin") for r in results)
