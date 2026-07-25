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
        assert await discover_subdomains(http, DOMAIN) == ["api.idata.test"]


@respx.mock
async def test_discover_subdomains_returns_empty_when_crtsh_is_down():
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(503))
    async with HttpClient() as http:
        assert await discover_subdomains(http, DOMAIN) == []


@respx.mock
async def test_discover_subdomains_never_raises_on_network_error():
    respx.get(url__startswith="https://crt.sh/").mock(side_effect=httpx.ConnectError("down"))
    async with HttpClient() as http:
        assert await discover_subdomains(http, DOMAIN) == []
