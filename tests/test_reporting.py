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


_SAMPLE_SURFACE = {
    "apex": "example.test",
    "totals": {"discovered": 2, "resolving": 2, "reachable": 2, "https": 1,
               "distinct_ips": 1, "distinct_technologies": 1},
    "assets": [
        {"host": "example.test", "source": "target", "resolves": True, "ips": ["203.0.113.1"],
         "cnames": [], "reachable": True, "scheme": "https", "status_code": 200, "https": True,
         "server": "nginx", "title": "Inicio", "technologies": ["Nginx 1.18.0"],
         "cdn": ["Cloudflare"], "waf": [], "cloud": [], "non_production": None,
         "takeover_service": None, "dns": None},
        {"host": "dev.example.test", "source": "crt.sh", "resolves": True, "ips": ["203.0.113.1"],
         "cnames": [], "reachable": True, "scheme": "http", "status_code": 200, "https": False,
         "server": None, "title": None, "technologies": [], "cdn": [], "waf": [], "cloud": [],
         "non_production": "dev", "takeover_service": None, "dns": None},
    ],
    "technology_index": {"Nginx 1.18.0": ["example.test"]},
    "provider_index": {"cdn": {"Cloudflare": ["example.test"]}, "waf": {}, "cloud": {}},
    "ip_index": {"203.0.113.1": ["example.test", "dev.example.test"]},
    "exposure_summary": {"non_production": ["dev.example.test"], "without_https": ["dev.example.test"],
                         "takeover_risk": [], "without_cdn_or_waf": ["dev.example.test"],
                         "origin_leak": []},
}


def _scan_with_surface() -> dict:
    return {
        **_SAMPLE_SCAN_RESULT,
        "modules": {**_SAMPLE_SCAN_RESULT["modules"], "asset_inventory": []},
        "artifacts": {"asset_inventory": {"surface_map": _SAMPLE_SURFACE}},
    }


def test_surface_map_is_absent_when_module_did_not_run():
    assert build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK)["surface_map"] is None


def test_surface_map_flows_into_the_report_context():
    ctx = build_report_context(_scan_with_surface(), {**_SAMPLE_RISK, "module_scores": {
        "vuln_identification": 55, "asset_inventory": 100}})
    assert ctx["surface_map"]["totals"]["discovered"] == 2


def test_attack_surface_section_renders_the_asset_table():
    ctx = build_report_context(_scan_with_surface(), {**_SAMPLE_RISK, "module_scores": {
        "vuln_identification": 55, "asset_inventory": 100}})
    html = render_html(ctx)

    assert "dev.example.test" in html
    assert "Nginx 1.18.0" in html
    assert "Cloudflare" in html
    assert "Tabla de activos" in html
    assert "requiere el Módulo 2" not in html


def test_compliance_section_renders_the_21719_checklist():
    from idata_sentinel.modules.data_privacy.compliance import build_compliance_checklist

    checklist = build_compliance_checklist([{
        "id": "privacy_policy_missing", "module": "data_privacy", "category": "Datos Personales",
        "severity": "high", "likelihood": "high", "status": "fail",
        "title": "Sin política de privacidad enlazada en el sitio", "finding": "f",
        "business_impact": "b", "recommendation": "Publicar la política", "evidence": "e",
        "references": [],
    }])
    scan = {
        **_SAMPLE_SCAN_RESULT,
        "modules": {**_SAMPLE_SCAN_RESULT["modules"], "data_privacy": []},
        "artifacts": {"data_privacy": {"compliance_21719": checklist}},
    }
    ctx = build_report_context(scan, {**_SAMPLE_RISK, "module_scores": {
        "vuln_identification": 55, "data_privacy": 80}})
    html = render_html(ctx)

    assert "Información al titular" in html
    assert "BRECHA" in html
    assert "Sin política de privacidad enlazada" in html
    assert "no constituye una calificación legal" in html.lower()
    assert "requiere el Módulo 3" not in html


def test_compliance_is_absent_when_module_did_not_run():
    ctx = build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK)
    assert ctx["compliance"] is None
    assert "requiere el Módulo 3" in render_html(ctx)


def test_severity_counts_are_aggregated():
    ctx = build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK)
    assert ctx["severity_counts"]["critical"] == 1
    assert ctx["severity_counts"]["medium"] == 1
    assert ctx["severity_counts"]["low"] == 0


_SAMPLE_MONITORING = {
    "baseline": {"id": 1, "scanned_at": "2026-01-01T00:00:00+00:00", "score": 80},
    "trend": {
        "points": [
            {"scanned_at": "2026-01-01T00:00:00+00:00", "score": 80, "grade": "B"},
            {"scanned_at": "2026-02-01T00:00:00+00:00", "score": 71, "grade": "C"},
            {"scanned_at": "2026-03-01T00:00:00+00:00", "score": 55, "grade": "F"},
        ],
        "current": 55, "previous": 71, "best": 80, "worst": 55, "delta": -16,
    },
    "findings_diff": {"new": [{"id": "cert_expired", "title": "Certificado expirado",
                               "severity": "critical"}],
                      "resolved": [], "unchanged_count": 1, "severity_changes": []},
    "assets_diff": {"new_assets": ["dev.example.test"], "removed_assets": [],
                    "technology_changes": {}},
    "alerts": [{"level": "critical", "title": "1 hallazgo grave nuevo", "summary": "…",
                "target": "https://example.test", "details": {}}],
}


def _scan_with_monitoring() -> dict:
    return {
        **_SAMPLE_SCAN_RESULT,
        "modules": {**_SAMPLE_SCAN_RESULT["modules"], "monitoring": []},
        "artifacts": {"monitoring": {"monitoring": _SAMPLE_MONITORING}},
    }


def test_report_carries_the_shared_visual_tokens():
    ctx = build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK)
    assert ctx["grade_color"] == "#d03b3b"  # nota F -> status critical
    assert [s.key for s in ctx["severity_segments"]] == ["critical", "medium"]
    assert ctx["severity_label"]("high") == "Alto"


def test_trend_sparkline_only_appears_with_history():
    assert build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK)["trend_spark"] is None

    ctx = build_report_context(_scan_with_monitoring(), _SAMPLE_RISK)
    assert ctx["trend_spark"].has_data
    assert (ctx["trend_spark"].min_value, ctx["trend_spark"].max_value) == (55, 80)


def test_monitoring_section_renders_the_diff():
    ctx = build_report_context(_scan_with_monitoring(), {**_SAMPLE_RISK, "module_scores": {
        "vuln_identification": 55, "monitoring": 100}})
    html = render_html(ctx)

    assert "Cambios desde la línea base" in html
    assert "Evolución del score" in html
    assert "<polyline" in html  # sparkline embebido, sin JavaScript


def test_report_severity_bar_uses_labels_not_colour_alone():
    html = render_html(build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK))
    assert "Crítico" in html
    assert "Medio" in html


def test_every_section_is_numbered_and_present():
    ctx = build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK)
    html = render_html(ctx)
    for section in ("Resumen ejecutivo", "Semáforo por línea de servicio", "Hallazgos priorizados",
                    "Mapa de superficie de ataque", "Cumplimiento Ley 21.719", "Anexo técnico",
                    "Próximos pasos", "Alcance y limitaciones"):
        assert section in html, section
    for num in ("02", "03", "04", "05", "06", "07", "08", "09"):
        assert f'class="section-num">{num}<' in html


def test_disclaimer_states_what_a_clean_result_does_not_mean():
    html = render_html(build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK))
    assert "no implica ausencia" in html
    assert "no se comprobó su explotabilidad" in html.lower()


def test_passive_and_audit_reports_declare_different_scope():
    passive = render_html(build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK))
    audit = render_html(build_report_context(
        {**_SAMPLE_SCAN_RESULT, "mode": "audit"}, _SAMPLE_RISK))

    assert "sin enviar" in passive
    assert "escaneo autorizado y registrado" in audit


_COVERAGE_NOTICE = {
    "id": "scan_blocked_by_interstitial@example.test", "module": "vuln_identification",
    "category": "Cobertura del escaneo", "severity": "info", "likelihood": "low",
    "status": "warning", "confidence": "unverified", "verification_status": "unverified",
    "title": "El sitio no pudo evaluarse: hay una página de verificación anti-bot delante",
    "finding": "El servidor entrega una página de verificación anti-bot.",
    "business_impact": "Este informe no describe la postura del sitio.",
    "recommendation": "Requiere modo auditoría con el escáner en lista blanca.",
    "evidence": "HTTP 200, título 'Un momento…'", "references": [],
}


def _scan_with_notice() -> dict:
    modules = {**_SAMPLE_SCAN_RESULT["modules"]}
    modules["vuln_identification"] = [*modules["vuln_identification"], _COVERAGE_NOTICE]
    return {**_SAMPLE_SCAN_RESULT, "modules": modules}


def test_coverage_notice_is_surfaced_and_kept_out_of_the_finding_totals():
    """El aviso encabeza el resumen ejecutivo, pero no es un hallazgo del
    objetivo: contarlo entre los hallazgos inflaría el total y le atribuiría al
    cliente un problema que es una limitación de la medición."""
    ctx = build_report_context(_scan_with_notice(), _SAMPLE_RISK)

    assert ctx["coverage_notice"]["id"].startswith("scan_blocked_by_interstitial")
    assert ctx["total_findings"] == 2  # los mismos que sin el aviso
    assert not any(f["id"].startswith("scan_blocked") for f in ctx["all_findings"])


def test_report_without_interstitial_has_no_coverage_notice():
    assert build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK)["coverage_notice"] is None


def test_coverage_notice_is_rendered_in_the_executive_summary():
    html = render_html(build_report_context(_scan_with_notice(), _SAMPLE_RISK))
    assert "COBERTURA INCOMPLETA" in html
    assert "página de verificación anti-bot" in html


@pytest.mark.integration
def test_export_pdf_writes_file(tmp_path):
    """Requiere las librerías nativas de WeasyPrint (Pango/Cairo/GObject) —
    disponibles en el contenedor de Railway, no necesariamente en el entorno local."""
    ctx = build_report_context(_SAMPLE_SCAN_RESULT, _SAMPLE_RISK)
    output = tmp_path / "reporte.pdf"
    export_pdf(ctx, output)
    assert output.exists()
    assert output.stat().st_size > 0
