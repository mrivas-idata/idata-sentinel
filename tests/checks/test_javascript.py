"""Análisis pasivo de JavaScript y recursos (Tier 1.2): mixed content, SRI,
source maps, secretos incrustados y versiones de librerías."""
from __future__ import annotations

import httpx
import respx

from idata_sentinel.checks.javascript import JavaScriptCheck, detect_js_libraries, find_secrets

ROOT = "https://example.test/"


def _ids(results) -> set[str]:
    return {r.id.split("@")[0] for r in results}


def _html(body: str) -> httpx.Response:
    return httpx.Response(200, text=body, headers={"content-type": "text/html"})


# -- funciones puras --------------------------------------------------------


def test_detect_js_libraries_from_filename():
    assert ("jquery", "3.4.1") in detect_js_libraries("/js/jquery-3.4.1.min.js")
    assert ("bootstrap", "4.3.1") in detect_js_libraries("https://cdn.x/bootstrap.4.3.1.js")
    assert detect_js_libraries("/js/app.min.js") == []


def test_find_secrets_high_confidence_and_redaction():
    aws = "AKIAIOSFODNN7EXAMPLE"
    secrets = find_secrets(f"var k = '{aws}';")
    assert secrets and secrets[0][0] == "AWS access key"
    assert aws not in secrets[0][1]  # redactado


def test_find_secrets_ignores_public_by_design_values():
    # Stripe publishable (pk_live) es público por diseño: no debe marcarse.
    assert find_secrets("pk_live_" + "a" * 30) == []


# -- mixed content ----------------------------------------------------------


@respx.mock
async def test_active_mixed_content_is_high(make_ctx):
    respx.get(ROOT).mock(return_value=_html(
        '<script src="http://cdn.insecure/app.js"></script>'))
    results = await JavaScriptCheck().run(make_ctx())
    finding = next(r for r in results if r.id == "mixed_content_active")
    assert finding.severity == "high"


@respx.mock
async def test_passive_mixed_content_is_low(make_ctx):
    respx.get(ROOT).mock(return_value=_html('<img src="http://cdn.insecure/logo.png">'))
    results = await JavaScriptCheck().run(make_ctx())
    assert "mixed_content_passive" in _ids(results)
    assert "mixed_content_active" not in _ids(results)


@respx.mock
async def test_no_mixed_content_on_all_https(make_ctx):
    respx.get(ROOT).mock(return_value=_html('<script src="https://cdn.ok/app.js" integrity="sha384-x"></script>'))
    assert "mixed_content_active" not in _ids(await JavaScriptCheck().run(make_ctx()))


# -- SRI --------------------------------------------------------------------


@respx.mock
async def test_third_party_script_without_integrity_is_flagged(make_ctx):
    respx.get(ROOT).mock(return_value=_html('<script src="https://cdn.tercero/lib.js"></script>'))
    assert "sri_missing" in _ids(await JavaScriptCheck().run(make_ctx()))


@respx.mock
async def test_same_origin_script_does_not_need_sri(make_ctx):
    respx.get(ROOT).mock(return_value=_html('<script src="/js/app.js"></script>'))
    respx.get("https://example.test/js/app.js").mock(return_value=httpx.Response(200, text="ok"))
    assert "sri_missing" not in _ids(await JavaScriptCheck().run(make_ctx()))


@respx.mock
async def test_third_party_with_integrity_is_not_flagged(make_ctx):
    respx.get(ROOT).mock(return_value=_html(
        '<script src="https://cdn.tercero/lib.js" integrity="sha384-abc" crossorigin></script>'))
    assert "sri_missing" not in _ids(await JavaScriptCheck().run(make_ctx()))


# -- librerías + CVE --------------------------------------------------------


@respx.mock
async def test_library_version_detected_and_cve_wired(make_ctx, monkeypatch):
    import idata_sentinel.checks.tech_fingerprint as tf
    monkeypatch.setattr(tf, "_load_cve_hints", lambda: [{
        "product": "jquery", "min_version": "0", "max_version": "3.5.0",
        "cve_ids": ["CVE-TEST-JQ"], "title": "XSS en jQuery <3.5", "cvss_severity": "medium",
    }])
    respx.get(ROOT).mock(return_value=_html('<script src="/js/jquery-3.4.1.min.js"></script>'))
    respx.get("https://example.test/js/jquery-3.4.1.min.js").mock(return_value=httpx.Response(200, text="/*jq*/"))

    results = await JavaScriptCheck().run(make_ctx())
    ids = _ids(results)
    assert "js_library_detected" in ids
    cve = next(r for r in results if r.id.startswith("cve_informational@jquery"))
    assert "CVE-TEST-JQ" in cve.references and cve.status == "info"


# -- secretos y source maps (fetch del JS del sitio) ------------------------


@respx.mock
async def test_secret_in_same_origin_js_is_flagged(make_ctx):
    respx.get(ROOT).mock(return_value=_html('<script src="/js/config.js"></script>'))
    respx.get("https://example.test/js/config.js").mock(
        return_value=httpx.Response(200, text="const key='AIza" + "b" * 35 + "';"))
    results = await JavaScriptCheck().run(make_ctx())
    finding = next(r for r in results if r.id.startswith("secret_in_javascript"))
    assert finding.severity == "high"
    assert "AIza" + "b" * 35 not in finding.evidence  # redactado


@respx.mock
async def test_exposed_source_map_is_flagged(make_ctx):
    respx.get(ROOT).mock(return_value=_html('<script src="/js/app.js"></script>'))
    respx.get("https://example.test/js/app.js").mock(
        return_value=httpx.Response(200, text="console.log(1)\n//# sourceMappingURL=app.js.map"))
    respx.get("https://example.test/js/app.js.map").mock(
        return_value=httpx.Response(200, text='{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}'))
    assert "source_map_exposed" in _ids(await JavaScriptCheck().run(make_ctx()))


@respx.mock
async def test_missing_source_map_is_not_flagged(make_ctx):
    respx.get(ROOT).mock(return_value=_html('<script src="/js/app.js"></script>'))
    respx.get("https://example.test/js/app.js").mock(
        return_value=httpx.Response(200, text="console.log(1)\n//# sourceMappingURL=app.js.map"))
    respx.get("https://example.test/js/app.js.map").mock(return_value=httpx.Response(404))
    assert "source_map_exposed" not in _ids(await JavaScriptCheck().run(make_ctx()))


@respx.mock
async def test_unreachable_root_is_reported(make_ctx):
    respx.get(ROOT).mock(side_effect=httpx.ConnectError("caído"))
    assert "javascript_unreachable" in _ids(await JavaScriptCheck().run(make_ctx()))
