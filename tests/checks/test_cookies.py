from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.checks.cookies import CookiesCheck


@pytest.mark.asyncio
@respx.mock
async def test_insecure_cookie_flags_all_three(make_ctx):
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(200, headers=[("set-cookie", "sessionid=abc123; Path=/")], text="ok")
    )
    ctx = make_ctx()
    results = await CookiesCheck().run(ctx)
    ids = {r.id for r in results}

    assert "cookie_insecure@sessionid" in ids
    assert "cookie_no_httponly@sessionid" in ids
    assert "cookie_weak_samesite@sessionid" in ids


@pytest.mark.asyncio
@respx.mock
async def test_secure_prefix_without_secure_flag_is_flagged(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, headers=[("set-cookie", "__Secure-sid=abc; HttpOnly; SameSite=Lax; Path=/")], text="ok"))
    ids = {r.id for r in await CookiesCheck().run(make_ctx())}
    assert "cookie_prefix_secure_violation@__Secure-sid" in ids


@pytest.mark.asyncio
@respx.mock
async def test_host_prefix_with_domain_is_flagged(make_ctx):
    # __Host- exige Secure + Path=/ + sin Domain; acá declara Domain.
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, headers=[("set-cookie", "__Host-sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.test")],
        text="ok"))
    finding = next(r for r in await CookiesCheck().run(make_ctx())
                   if r.id.startswith("cookie_prefix_host_violation"))
    assert "declara Domain" in finding.finding


@pytest.mark.asyncio
@respx.mock
async def test_correct_host_prefix_cookie_has_no_prefix_finding(make_ctx):
    respx.get("https://example.test/").mock(return_value=httpx.Response(
        200, headers=[("set-cookie", "__Host-sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/")], text="ok"))
    ids = {r.id for r in await CookiesCheck().run(make_ctx())}
    assert not any("cookie_prefix" in i for i in ids)


@pytest.mark.asyncio
@respx.mock
async def test_secure_cookie_produces_no_findings(make_ctx):
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers=[("set-cookie", "sessionid=abc123; Secure; HttpOnly; SameSite=Lax; Path=/")],
            text="ok",
        )
    )
    ctx = make_ctx()
    results = await CookiesCheck().run(ctx)
    assert results == []


@pytest.mark.asyncio
@respx.mock
async def test_samesite_none_without_secure_is_weak(make_ctx):
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200, headers=[("set-cookie", "tracker=xyz; SameSite=None; HttpOnly")], text="ok"
        )
    )
    ctx = make_ctx()
    results = await CookiesCheck().run(ctx)
    ids = {r.id for r in results}
    assert "cookie_weak_samesite@tracker" in ids
    assert "cookie_insecure@tracker" in ids


@pytest.mark.asyncio
@respx.mock
async def test_multiple_cookies_evaluated_independently(make_ctx):
    respx.get("https://example.test/").mock(
        return_value=httpx.Response(
            200,
            headers=[
                ("set-cookie", "a=1; Secure; HttpOnly; SameSite=Strict"),
                ("set-cookie", "b=2; Path=/"),
            ],
            text="ok",
        )
    )
    ctx = make_ctx()
    results = await CookiesCheck().run(ctx)
    assert not [r for r in results if r.id.endswith("@a")]
    assert len([r for r in results if r.id.endswith("@b")]) == 3
