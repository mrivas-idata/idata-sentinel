"""Fingerprint de stack y de componentes WordPress + capa CVE informativa
(plan_implementacion_escaneo_vulnerabilidades.md §2.4)."""
from __future__ import annotations

import httpx
import respx

from idata_sentinel.checks import tech_fingerprint as tf
from idata_sentinel.checks.tech_fingerprint import (
    TechFingerprintCheck,
    detect_components,
    detect_technologies,
)

ROOT = "https://example.test/"


def _ids(results) -> set[str]:
    return {r.id.split("@")[0] if "@" not in r.id else r.id for r in results}


def _resp(body: str = "", headers: dict | None = None) -> httpx.Response:
    return httpx.Response(200, text=body, headers=headers or {})


# -- stack base ------------------------------------------------------------


def test_detects_server_version_from_header():
    d = detect_technologies(_resp(headers={"Server": "nginx/1.18.0"}))
    nginx = next(x for x in d if x.product == "Nginx")
    assert nginx.version == "1.18.0"
    assert nginx.kind == "tech"


def test_detects_wordpress_core_version_from_html():
    body = '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.9.5"></script>'
    d = detect_technologies(_resp(body))
    wp = next(x for x in d if x.product == "WordPress")
    assert wp.version == "6.9.5"


# -- componentes WordPress (la novedad) ------------------------------------


def test_detects_plugins_and_themes_with_versions_from_the_already_fetched_html():
    """El dato ya viene en el HTML raíz: cero requests extra. Reproduce lo visto
    en un escaneo real (Slider Revolution, Contact Form 7)."""
    body = (
        '<link href="/wp-content/plugins/revslider/public/css/rs6.css?ver=6.7.40">'
        '<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=6.1.6">'
        '<link href="/wp-content/themes/uncode/style.css?ver=2.9.1">'
    )
    comps = {(c.kind, c.product): c.version for c in detect_components(_resp(body))}
    assert comps[("plugin", "revslider")] == "6.7.40"
    assert comps[("plugin", "contact-form-7")] == "6.1.6"
    assert comps[("theme", "uncode")] == "2.9.1"


def test_cache_buster_integers_are_not_read_as_versions():
    """Los temas cachean con enteros gigantes tipo `?ver=801499924`. Tratarlos
    como versión inventaría un 'componente v801499924'."""
    body = '<link href="/wp-content/themes/uncode/style.css?ver=801499924">'
    assert detect_components(_resp(body)) == []


def test_highest_version_wins_when_a_component_appears_twice():
    body = (
        '<link href="/wp-content/plugins/uncode-privacy/a.css?ver=2.2.0">'
        '<script src="/wp-content/plugins/uncode-privacy/b.js?ver=2.3.0">'
    )
    comps = detect_components(_resp(body))
    assert len(comps) == 1
    assert comps[0].version == "2.3.0"


def test_a_site_without_wp_components_yields_none():
    assert detect_components(_resp("<html><body>nada</body></html>")) == []


# -- integración del check -------------------------------------------------


@respx.mock
async def test_check_emits_component_disclosure(make_ctx):
    body = '<link href="/wp-content/plugins/revslider/x.css?ver=6.7.40">'
    respx.get(ROOT).mock(return_value=_resp(body))

    results = await TechFingerprintCheck().run(make_ctx())
    finding = next(r for r in results if r.id.startswith("component_version_disclosure@plugin:revslider"))
    assert finding.status == "warning"
    assert finding.severity == "low"
    assert "revslider" in finding.finding


@respx.mock
async def test_unreachable_root_is_reported_not_crashed(make_ctx):
    respx.get(ROOT).mock(side_effect=httpx.ConnectError("caído"))
    results = await TechFingerprintCheck().run(make_ctx())
    assert any(r.id.startswith("tech_fingerprint_unreachable") for r in results)


# -- capa CVE informativa --------------------------------------------------


@respx.mock
async def test_cve_layer_matches_components_by_slug(make_ctx, monkeypatch):
    """La capa CVE cruza por slug del componente. Se inyecta una entrada de
    prueba —la base real es placeholder y su curación es de IDATA."""
    monkeypatch.setattr(tf, "_load_cve_hints", lambda: [{
        "product": "revslider", "min_version": "0", "max_version": "6.7.41",
        "cve_ids": ["CVE-TEST-0001"], "title": "Ejemplo", "cvss_severity": "high",
    }])
    body = '<link href="/wp-content/plugins/revslider/x.css?ver=6.7.40">'
    respx.get(ROOT).mock(return_value=_resp(body))

    results = await TechFingerprintCheck().run(make_ctx())
    cve = next(r for r in results if r.id.startswith("cve_informational@revslider"))
    assert cve.status == "info"              # nunca 'fail': no se verificó explotabilidad
    assert cve.likelihood == "low"           # fijo (plan §2.4)
    assert cve.severity == "medium"          # 'high' de CVSS degradado a máx. medium
    assert "CVE-TEST-0001" in cve.references


@respx.mock
async def test_cve_layer_respects_version_ranges(make_ctx, monkeypatch):
    """Una versión fuera del rango afectado no produce cruce."""
    monkeypatch.setattr(tf, "_load_cve_hints", lambda: [{
        "product": "revslider", "min_version": "0", "max_version": "6.0.0",
        "cve_ids": ["CVE-TEST-0002"], "title": "Ejemplo", "cvss_severity": "high",
    }])
    body = '<link href="/wp-content/plugins/revslider/x.css?ver=6.7.40">'
    respx.get(ROOT).mock(return_value=_resp(body))

    results = await TechFingerprintCheck().run(make_ctx())
    assert not any(r.id.startswith("cve_informational") for r in results)
