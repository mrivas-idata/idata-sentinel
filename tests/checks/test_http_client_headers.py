from __future__ import annotations

import httpx
import respx

from idata_sentinel.checks.http_headers import HttpHeadersCheck
from idata_sentinel.core.http_client import DEFAULT_HEADERS, USER_AGENT, HttpClient

URL = "https://example.test/"


# -- cabeceras de la petición ---------------------------------------------


@respx.mock
async def test_requests_carry_an_accept_header():
    """Sin `Accept` hay servidores que responden 415 y el escaneo termina
    analizando una página de error en vez del sitio."""
    route = respx.get(URL).mock(return_value=httpx.Response(200, text="ok"))
    async with HttpClient() as http:
        await http.get(URL)

    sent = route.calls[0].request.headers
    assert "text/html" in sent["accept"]
    assert sent["user-agent"] == USER_AGENT


@respx.mock
async def test_user_agent_stays_honest_and_identifiable():
    """La corrección del `Accept` no puede convertirse en evasión: el
    User-Agent sigue declarando quién escanea y dónde reclamar."""
    route = respx.get(URL).mock(return_value=httpx.Response(200, text="ok"))
    async with HttpClient() as http:
        await http.get(URL)

    ua = route.calls[0].request.headers["user-agent"]
    assert ua.startswith("IDATA-Sentinel/")
    assert "idatachile.com" in ua
    assert "Mozilla" not in ua


def test_default_headers_do_not_impersonate_a_browser():
    assert DEFAULT_HEADERS["User-Agent"] == USER_AGENT
    assert set(DEFAULT_HEADERS) == {"User-Agent", "Accept", "Accept-Language"}


# -- salvaguarda ante páginas de error ------------------------------------


@respx.mock
async def test_error_response_is_flagged_before_its_findings(make_ctx):
    respx.get(URL).mock(return_value=httpx.Response(415, headers={"Server": "Apache"}, text="err"))
    results = await HttpHeadersCheck().run(make_ctx())

    warning = next(r for r in results if r.id.startswith("response_is_an_error_page"))
    assert warning.status == "info"
    assert "415" in warning.title
    assert results[0].id.startswith("response_is_an_error_page")  # va primero


@respx.mock
async def test_error_page_findings_are_still_reported(make_ctx):
    """No se suprimen: podrían ser válidos. Solo se contextualizan."""
    respx.get(URL).mock(return_value=httpx.Response(403, text="denegado"))
    ids = {r.id for r in await HttpHeadersCheck().run(make_ctx())}
    assert "hsts_missing" in ids


@respx.mock
async def test_successful_response_carries_no_warning(make_ctx):
    respx.get(URL).mock(return_value=httpx.Response(200, text="<html></html>"))
    ids = {r.id for r in await HttpHeadersCheck().run(make_ctx())}
    assert "response_is_an_error_page" not in ids


@respx.mock
async def test_redirects_are_not_treated_as_errors(make_ctx):
    respx.get(URL).mock(return_value=httpx.Response(301, headers={"Location": "/destino"}))
    respx.get("https://example.test/destino").mock(
        return_value=httpx.Response(200, text="<html></html>")
    )
    ids = {r.id for r in await HttpHeadersCheck().run(make_ctx())}
    assert "response_is_an_error_page" not in ids
