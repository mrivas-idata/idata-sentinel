from __future__ import annotations

import base64

from idata_sentinel.reporting.branding import load_branding
from idata_sentinel.reporting.document import DocumentMeta, build_document_context
from idata_sentinel.reporting.pdf_export import render_document_html, render_html
from idata_sentinel.reporting.report_builder import build_report_context

_SAMPLE_SCAN = {
    "target": "https://cliente.test", "mode": "passive",
    "modules": {"vuln_identification": []},
}
_SAMPLE_RISK = {"score": 88, "grade": "B", "module_scores": {"vuln_identification": 88},
                "category_scores": {}}


def test_branding_exposes_company_identity():
    b = load_branding()
    assert b["company_name"] == "IDATA Chile"
    assert b["company_url"].startswith("https://")


def test_logo_is_embedded_as_a_data_uri():
    """Incrustado, no referenciado: WeasyPrint renderiza desde una cadena sin
    URL base, y las vistas previas no pueden pedir recursos externos."""
    uri = load_branding()["logo_data_uri"]

    assert uri.startswith("data:image/png;base64,")
    assert base64.b64decode(uri.split(",", 1)[1])[:8] == b"\x89PNG\r\n\x1a\n"


def test_logo_stays_small_enough_to_embed_everywhere():
    """Se incrusta en cada HTML: si crece, infla todos los entregables."""
    assert len(load_branding()["logo_data_uri"]) < 80_000


def test_logo_is_declared_as_needing_a_light_background():
    """Ninguna variante entregada tiene transparencia real, así que las
    plantillas lo colocan sobre una pastilla clara."""
    assert load_branding()["logo_needs_light_background"] is True


def test_report_cover_shows_the_logo_on_a_light_chip():
    html = render_html(build_report_context(_SAMPLE_SCAN, _SAMPLE_RISK))
    assert 'class="logo-chip"' in html
    assert "data:image/png;base64," in html


def test_document_cover_shows_the_logo():
    html = render_document_html(
        build_document_context("docs/guia_cliente.md", meta=DocumentMeta(title="Guía"))
    )
    assert 'class="logo-chip"' in html
    assert "data:image/png;base64," in html


def test_branding_is_cached():
    assert load_branding() is load_branding()
