from __future__ import annotations

from pathlib import Path

import pytest

from idata_sentinel.reporting.pdf_export import export_pdf, render_html
from idata_sentinel.reporting.report_builder import build_report_context

_SAMPLE_SCAN_RESULT = {
    "target": "https://example.test",
    "mode": "passive",
    "modules": {
        "vuln_identification": [
            {
                "id": "hsts_missing", "module": "vuln_identification", "category": "HTTP Headers",
                "severity": "medium", "likelihood": "high", "status": "fail",
                "title": "Falta cabecera HSTS", "finding": "...", "business_impact": "...",
                "recommendation": "...", "evidence": "...", "references": ["CWE-319"],
            },
            {
                "id": "cert_expired", "module": "vuln_identification", "category": "TLS/SSL",
                "severity": "critical", "likelihood": "high", "status": "fail",
                "title": "Certificado TLS expirado", "finding": "...", "business_impact": "...",
                "recommendation": "...", "evidence": "...", "references": [],
            },
        ]
    },
}
_SAMPLE_RISK = {
    "score": 55, "grade": "F",
    "module_scores": {"vuln_identification": 55},
    "category_scores": {"HTTP Headers": 92, "TLS/SSL": 63},
}


def test_build_report_context_includes_expected_fields():
    ctx = build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK)

    assert ctx["target"] == "https://example.test"
    assert ctx["score"] == 55
    assert ctx["grade"] == "F"
    assert ctx["total_findings"] == 2
    assert ctx["top_findings"][0]["id"] == "cert_expired"  # critical antes que medium

    labels = {m["name"]: m["evaluated"] for m in ctx["module_summaries"]}
    assert labels["vuln_identification"] is True
    assert labels["asset_inventory"] is False  # Módulo 2 aún no existe


def test_render_html_produces_valid_document():
    ctx = build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK)
    html = render_html(ctx)

    assert "<html" in html
    assert "Falta cabecera HSTS" in html
    assert "Certificado TLS expirado" in html
    assert ctx["report_number"] in html
    assert "No evaluado" in html  # secciones de módulos aún no implementados


def test_render_html_escapes_untrusted_content():
    malicious = dict(_SAMPLE_SCAN_RESULT)
    malicious["modules"] = {
        "vuln_identification": [{
            "id": "x", "module": "vuln_identification", "category": "Test",
            "severity": "low", "likelihood": "low", "status": "fail",
            "title": "<script>alert(1)</script>", "finding": "f", "business_impact": "b",
            "recommendation": "r", "evidence": "e", "references": [],
        }]
    }
    ctx = build_report_context(malicious, _SAMPLE_RISK)
    html = render_html(ctx)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


@pytest.mark.integration
def test_export_pdf_writes_file(tmp_path):
    """Requiere las librerías nativas de WeasyPrint (Pango/Cairo/GObject) —
    disponibles en el contenedor de Railway, no necesariamente en el entorno local."""
    ctx = build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK)
    output = tmp_path / "reporte.pdf"
    export_pdf(ctx, output)
    assert output.exists()
    assert output.stat().st_size > 0
