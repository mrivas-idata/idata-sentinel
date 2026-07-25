from __future__ import annotations

import json

import httpx
import respx

from idata_sentinel.checks.subdomains import discover_subdomains, parse_crtsh
from idata_sentinel.core.http_client import HttpClient

DOMAIN = "idata.test"


def _payload(*names: str) -> str:
    return json.dumps([{"name_value": name} for name in names])


def test_parse_crtsh_strips_wildcards_and_dedupes():
    payload = _payload("*.idata.test\nwww.idata.test", "www.idata.test", "idata.test")
    assert parse_crtsh(payload, DOMAIN) == ["idata.test", "www.idata.test"]


def test_parse_crtsh_rejects_names_outside_the_domain():
    payload = _payload("evil.test", "idata.test.evil.test", "api.idata.test")
    assert parse_crtsh(payload, DOMAIN) == ["api.idata.test"]


def test_parse_crtsh_prioritises_shallow_names_when_truncating():
    payload = _payload("a.b.c.idata.test", "www.idata.test", "x.y.idata.test")
    assert parse_crtsh(payload, DOMAIN, limit=2) == ["www.idata.test", "x.y.idata.test"]


def test_parse_crtsh_tolerates_garbage():
    assert parse_crtsh("not json", DOMAIN) == []
    assert parse_crtsh('{"not": "a list"}', DOMAIN) == []
    assert parse_crtsh('["a string entry"]', DOMAIN) == []


@respx.mock
async def test_discover_subdomains_happy_path():
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=httpx.Response(200, text=_payload("api.idata.test"))
    )
    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN)
        assert result.hosts == ["api.idata.test"]
        assert result.ok is True


@respx.mock
async def test_http_error_is_reported_as_a_failed_discovery():
    """Distinguir "no hay subdominios" de "no pude averiguarlo": un fallo
    silencioso produce un inventario incompleto que nadie cuestiona."""
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(503))
    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN)

    assert result.hosts == []
    assert result.ok is False
    assert "503" in result.reason


@respx.mock
async def test_network_error_never_raises_but_is_recorded():
    respx.get(url__startswith="https://crt.sh/").mock(side_effect=httpx.ConnectError("down"))
    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN)

    assert result.ok is False
    assert "no respondió" in result.reason


@respx.mock
async def test_timeout_is_recorded_as_a_failure():
    """crt.sh es lento de verdad: el timeout es el fallo más frecuente."""
    respx.get(url__startswith="https://crt.sh/").mock(side_effect=httpx.ReadTimeout("lento"))
    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN)

    assert result.ok is False
    assert "timeout" in result.reason


@respx.mock
async def test_an_empty_certificate_log_is_a_valid_answer():
    """Un dominio sin certificados registrados no es un fallo."""
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(200, text="[]"))
    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN)

    assert result.hosts == []
    assert result.ok is True


@respx.mock
async def test_unreadable_response_is_a_failure():
    respx.get(url__startswith="https://crt.sh/").mock(
        return_value=httpx.Response(200, text="<html>error interno</html>")
    )
    async with HttpClient() as http:
        assert (await discover_subdomains(http, DOMAIN)).ok is False


@respx.mock
async def test_discovery_uses_a_longer_timeout_than_a_normal_request():
    route = respx.get(url__startswith="https://crt.sh/").mock(
        return_value=httpx.Response(200, text="[]")
    )
    async with HttpClient() as http:
        await discover_subdomains(http, DOMAIN)
    assert route.called
