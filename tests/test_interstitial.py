"""Detección de páginas intersticiales anti-bot y degradación del escaneo.

El caso que motivó esto: `https://idatachile.com` devolvía 200 con una página de
6 KB "Please wait while your request is being verified...". El escaneo la tomó
por el sitio y emitió, entre otros, `privacy_policy_missing` en severidad `high`
sobre una página de espera. Un hallazgo así enviado a un prospecto es falso y
verificable por él en dos clics.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.core.engine import Engine, ScanRequest
from idata_sentinel.core.interstitial import detect_interstitial
from idata_sentinel.modules.data_privacy.module import DataPrivacyModule
from idata_sentinel.modules.vuln_identification.module import VulnIdentificationModule

# Reproducción abreviada de lo que sirve idatachile.com tras el WAF.
IDATACHILE_INTERSTITIAL = """<!DOCTYPE html><html lang="en"><head>
<meta charset="utf8"><title>One moment, please...</title>
<script>setTimeout(function(){window.location.reload();}, 5000);</script></head>
<body><div id="text">Please wait while your request is being verified...</div></body></html>"""

#: El mismo WAF, servido en español porque el escáner pide `Accept-Language: es-CL`.
#: Es la forma en que llega contra objetivos chilenos, o sea el caso normal.
IDATACHILE_INTERSTITIAL_ES = """<!DOCTYPE html><html lang="es"><head>
<meta charset="utf8"><title>Un momento…</title></head>
<body><div id="text">Espere mientras se verifica su solicitud…</div></body></html>"""

REAL_PAGE = """<!DOCTYPE html><html lang="es"><head><title>Consultora</title></head>
<body><a href="/politica-de-privacidad">Política de privacidad</a></body></html>"""


def _response(text: str, status: int = 200, headers: dict | None = None) -> httpx.Response:
    return httpx.Response(
        status,
        text=text,
        headers={"content-type": "text/html; charset=utf-8", **(headers or {})},
    )


# -- detección --------------------------------------------------------------


def test_detects_the_idatachile_interstitial():
    signal = detect_interstitial(_response(IDATACHILE_INTERSTITIAL))
    assert signal is not None
    assert signal.status_code == 200
    # La página lleva varias frases reconocibles; cuál dispare es indiferente.
    assert signal.marker


def test_detects_the_interstitial_served_in_spanish():
    """El WAF localiza el desafío según `Accept-Language`, y el cliente pide
    `es-CL`. Contra objetivos chilenos —el mercado de la herramienta— llega en
    español, así que detectarlo solo en inglés no serviría de nada."""
    signal = detect_interstitial(_response(IDATACHILE_INTERSTITIAL_ES))
    assert signal is not None


def test_detects_a_spanish_challenge_by_its_title_alone():
    """Aunque cambie el texto del cuerpo, el título de una página diminuta basta."""
    page = '<html><head><title>Un momento…</title></head><body><p>.</p></body></html>'
    assert detect_interstitial(_response(page)) is not None


@pytest.mark.parametrize(
    "body,provider",
    [
        ("<title>Just a moment...</title><body>x</body>", "Cloudflare"),
        ("<body>Checking your browser before accessing example.cl</body>", "Cloudflare"),
        ("<body>Sucuri WebSite Firewall - Access Denied</body>", "Sucuri"),
        ("<body>Incapsula incident ID: 1234</body>", "Imperva"),
        ("<body>Verifying you are human. This may take a few seconds.</body>", "genérico"),
    ],
)
def test_detects_known_providers(body, provider):
    signal = detect_interstitial(_response(body))
    assert signal is not None and signal.provider == provider


def test_detects_challenge_declared_in_headers():
    signal = detect_interstitial(
        _response("<body>nada reconocible</body>", 403, {"cf-mitigated": "challenge"})
    )
    assert signal is not None and signal.provider == "Cloudflare"


def test_a_normal_page_is_not_an_interstitial():
    assert detect_interstitial(_response(REAL_PAGE)) is None


def test_no_response_is_not_an_interstitial():
    assert detect_interstitial(None) is None


def test_an_article_mentioning_the_phrase_is_not_flagged():
    """Falso positivo que importa evitar: una consultora de ciberseguridad
    escribe sobre challenges anti-bot. Silenciar su escaneo por eso sería peor
    que el problema original."""
    article = (
        "<html><head><title>Cómo funcionan los WAF</title></head><body>"
        + "<p>Relleno editorial. </p>" * 1200
        + "<p>El navegador muestra 'checking your browser before accessing' "
        "mientras se resuelve el desafío.</p></body></html>"
    )
    assert len(article) > 25_000
    assert detect_interstitial(_response(article)) is None


def test_a_large_page_with_a_challenge_status_is_still_flagged():
    body = "<html><body>" + "x" * 30_000 + "Just a moment...</body></html>"
    assert detect_interstitial(_response(body, 503)) is not None


def test_non_html_bodies_are_ignored():
    binary = httpx.Response(200, content=b"\x89PNG\r\n", headers={"content-type": "image/png"})
    assert detect_interstitial(binary) is None


# -- degradación del escaneo ------------------------------------------------


def _engine_with(*modules) -> Engine:
    engine = Engine(rate_limit_seconds=0.0)
    for module in modules:
        engine.register_module(module)
    return engine


@respx.mock
async def test_content_checks_are_not_evaluated_behind_an_interstitial():
    respx.get(url__regex=r"https://example\.test.*").mock(
        return_value=_response(IDATACHILE_INTERSTITIAL)
    )

    result = await _engine_with(
        VulnIdentificationModule(), DataPrivacyModule()
    ).scan(ScanRequest(target="https://example.test"))

    findings = [f for group in result["modules"].values() for f in group]

    # Ni un solo hallazgo accionable medido: no se afirma nada del sitio.
    actionable = [
        f for f in findings
        if f["status"] in ("fail", "warning") and f["confidence"] != "unverified"
    ]
    assert actionable == []

    # Y en concreto, no el falso positivo de severidad `high` que motivó esto.
    assert not any(f["id"].startswith("privacy_policy_missing") for f in findings)


@respx.mock
async def test_the_operator_is_told_the_scan_did_not_see_the_site():
    respx.get(url__regex=r"https://example\.test.*").mock(
        return_value=_response(IDATACHILE_INTERSTITIAL)
    )

    result = await _engine_with(VulnIdentificationModule()).scan(
        ScanRequest(target="https://example.test")
    )

    notice = [
        f for f in result["modules"]["vuln_identification"]
        if f["id"].startswith("scan_blocked_by_interstitial")
    ]
    assert len(notice) == 1
    assert notice[0]["status"] == "warning"
    assert notice[0]["confidence"] == "unverified"  # visible, pero no altera el score


@respx.mock
async def test_infrastructure_checks_still_run_behind_an_interstitial():
    """TLS no depende del contenido servido: sigue siendo medible y su hallazgo
    es legítimo aunque delante haya un challenge."""
    respx.get(url__regex=r"https://example\.test.*").mock(
        return_value=_response(IDATACHILE_INTERSTITIAL)
    )

    result = await _engine_with(VulnIdentificationModule()).scan(
        ScanRequest(target="https://example.test")
    )

    ids = [f["id"] for f in result["modules"]["vuln_identification"]]
    assert not any(i.startswith("tls_ssl_interstitial") for i in ids)


@respx.mock
async def test_a_clean_target_is_unaffected():
    respx.get(url__regex=r"https://example\.test.*").mock(return_value=_response(REAL_PAGE))

    result = await _engine_with(VulnIdentificationModule(), DataPrivacyModule()).scan(
        ScanRequest(target="https://example.test")
    )

    findings = [f for group in result["modules"].values() for f in group]
    assert not any(f["id"].startswith("scan_blocked_by_interstitial") for f in findings)
    assert not any(f["id"].endswith("_interstitial") for f in findings)
