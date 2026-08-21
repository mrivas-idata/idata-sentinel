from __future__ import annotations

import warnings

import pytest

warnings.filterwarnings("ignore", category=DeprecationWarning)

from fastapi.testclient import TestClient  # noqa: E402

from idata_sentinel.interfaces.webapp import (  # noqa: E402
    TOKEN_COOKIE,
    _grade_of,
    _group_by_module,
    _resolve_modules,
    _severity_counts,
    _validate_scan_form,
    create_app,
)
from idata_sentinel.reporting.charts import severity_segments, sparkline  # noqa: E402
from idata_sentinel.storage.db import ScanStore  # noqa: E402

TARGET = "https://cliente.test"


def _finding(fid, *, severity="high", status="fail", module="vuln_identification") -> dict:
    return {
        "id": fid, "module": module, "category": "Test", "severity": severity,
        "likelihood": "high", "status": status, "title": f"Título {fid}", "finding": "f",
        "business_impact": "Impacto de negocio", "recommendation": "Corregir",
        "evidence": "evidencia", "references": [],
    }


@pytest.fixture
def store(tmp_path) -> ScanStore:
    return ScanStore(tmp_path / "web.db")


@pytest.fixture
def client(store) -> TestClient:
    return TestClient(create_app(store=store, token=""))


def _seed(store: ScanStore, *, scores=(70, 55)) -> None:
    from idata_sentinel.modules.data_privacy.compliance import build_compliance_checklist

    findings = [
        _finding("cert_expired", severity="critical"),
        _finding("hsts_missing", severity="medium"),
        _finding("spf_missing@cliente.test", severity="medium", module="asset_inventory"),
        _finding("privacy_policy_missing", module="data_privacy"),
        _finding("ok", severity="info", status="pass"),
    ]
    artifacts = {"data_privacy": {"compliance_21719": build_compliance_checklist(findings)},
                 "asset_inventory": {"surface_map": {
        "apex": "cliente.test",
        "totals": {"discovered": 3, "resolving": 3, "reachable": 2, "https": 1,
                   "distinct_ips": 2, "distinct_technologies": 1},
        "assets": [{
            "host": "dev.cliente.test", "source": "crt.sh", "resolves": True,
            "ips": ["203.0.113.9"], "cnames": [], "reachable": True, "scheme": "http",
            "status_code": 200, "https": False, "server": "Apache", "title": "Staging",
            "technologies": ["Apache 2.4.41"], "cdn": [], "waf": [], "cloud": [],
            "non_production": "dev", "takeover_service": None, "dns": None,
        }],
        "technology_index": {}, "provider_index": {"cdn": {}, "waf": {}, "cloud": {}},
        "ip_index": {}, "exposure_summary": {
            "non_production": ["dev.cliente.test"], "without_https": ["dev.cliente.test"],
            "takeover_risk": [], "without_cdn_or_waf": [], "origin_leak": [],
        },
    }}}

    for i, score in enumerate(scores):
        store.record_scan(
            target=TARGET, mode="passive", score=score, grade="C" if score >= 70 else "F",
            findings=findings, artifacts=artifacts,
            scanned_at=f"2026-0{i + 1}-01T09:00:00+00:00",
        )


# -- helpers puros ---------------------------------------------------------


def test_resolve_modules_expands_aliases():
    assert _resolve_modules("vuln,privacy") == ["vuln_identification", "data_privacy"]
    assert _resolve_modules("all") is None


def test_group_by_module():
    grouped = _group_by_module([_finding("a"), _finding("b", module="data_privacy")])
    assert set(grouped) == {"vuln_identification", "data_privacy"}


def test_severity_counts_ignores_non_actionable():
    counts = _severity_counts([
        _finding("a", severity="critical"),
        _finding("b", severity="low", status="warning"),
        _finding("c", severity="high", status="pass"),
    ])
    assert counts["critical"] == 1
    assert counts["low"] == 1
    assert counts["high"] == 0


@pytest.mark.parametrize("score,grade", [(95, "A"), (85, "B"), (75, "C"), (65, "D"), (10, "F")])
def test_grade_of(score, grade):
    assert _grade_of(score) == grade


@pytest.mark.parametrize(
    "kwargs,fragment",
    [
        ({"target": "ejemplo.cl"}, "esquema"),
        ({"mode": "agresivo"}, "Modo inválido"),
        ({"mode": "audit"}, "autorización escrita"),
        ({"mode": "audit", "confirmed": "1", "authorized_by": ""}, "quién autoriza"),
    ],
)
def test_scan_form_validation_rejects_bad_input(kwargs, fragment):
    base = {"target": TARGET, "mode": "passive", "confirmed": "",
            "authorized_by": "Ana, CISO", "contract": "OC-1"}
    assert fragment in _validate_scan_form(**{**base, **kwargs})


def test_valid_passive_and_audit_forms_pass():
    assert _validate_scan_form(TARGET, "passive", "", "", "") is None
    assert _validate_scan_form(TARGET, "audit", "1", "Ana, CISO", "OC-1") is None


# -- geometría de gráficos -------------------------------------------------


def test_severity_segments_skip_empty_levels_and_keep_order():
    segments = severity_segments({"critical": 2, "high": 0, "medium": 1, "low": 0, "info": 0})
    assert [s.key for s in segments] == ["critical", "medium"]
    assert segments[0].percent == 66.7


def test_severity_segments_of_a_clean_scan():
    assert severity_segments({k: 0 for k in ("critical", "high", "medium", "low", "info")}) == []


def test_sparkline_geometry():
    spark = sparkline([10, 50, 30], width=100, height=40, padding=4)
    assert spark.has_data
    assert (spark.min_value, spark.max_value) == (10, 50)
    assert len(spark.points.split(" ")) == 3
    assert spark.last_x == 96.0  # último punto en el borde derecho útil


def test_sparkline_of_a_single_point_is_centred():
    spark = sparkline([42], width=100, height=40)
    assert spark.points == "50.0,20.0"


def test_sparkline_without_data():
    assert sparkline([]).has_data is False


def test_flat_series_does_not_divide_by_zero():
    assert sparkline([50, 50, 50]).has_data


# -- rutas -----------------------------------------------------------------


def test_dashboard_empty_state(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Todavía no hay escaneos registrados" in response.text


def test_dashboard_shows_targets_and_kpis(client, store):
    _seed(store)
    response = client.get("/")

    assert response.status_code == 200
    assert TARGET in response.text
    assert "Score promedio" in response.text
    assert "<polyline" in response.text  # sparkline de tendencia


def test_result_page_renders_every_visual_block(client, store):
    _seed(store)
    response = client.get("/objetivo", params={"target": TARGET})

    assert response.status_code == 200
    for fragment in (
        'class="hero-value"', 'class="meter-fill"', 'class="sev-seg"',
        "Mapa de superficie de ataque", "dev.cliente.test",
        "Cumplimiento Ley 21.719", "Hallazgos priorizados", "Tendencia del score",
    ):
        assert fragment in response.text, fragment


def test_result_page_labels_every_severity_never_colour_alone(client, store):
    """Mitigación documentada del par medio/alto: la etiqueta siempre acompaña al color."""
    _seed(store)
    text = client.get("/objetivo", params={"target": TARGET}).text
    assert "CRÍTICO" in text
    assert "MEDIO" in text


def test_unknown_target_returns_404(client):
    assert client.get("/objetivo", params={"target": "https://nunca.test"}).status_code == 404


def test_help_page_lists_the_four_modules(client):
    response = client.get("/ayuda")
    assert response.status_code == 200
    for label in ("Identificación de vulnerabilidades", "Inventario de activos",
                  "Datos Personales", "Monitoreo continuo"):
        assert label in response.text
    assert "Límites legales" in response.text


def test_new_scan_form_renders(client):
    response = client.get("/nuevo")
    assert response.status_code == 200
    assert "Prospección pasiva" in response.text
    assert "Sin fuzzing de rutas" in response.text


def test_scan_form_rejects_url_without_scheme(client):
    response = client.post("/escanear", data={"target": "ejemplo.cl", "mode": "passive"})
    assert response.status_code == 400
    assert "esquema" in response.text


def test_audit_scan_without_authorization_is_refused(client):
    response = client.post("/escanear", data={"target": TARGET, "mode": "audit"})
    assert response.status_code == 400
    assert "autorización escrita" in response.text


def test_unknown_job_returns_404(client):
    assert client.get("/escaneo/inexistente").status_code == 404


# -- API -------------------------------------------------------------------


def test_health_endpoint(client):
    assert client.get("/api/salud").json() == {"status": "ok", "auth": False}


def test_modules_endpoint_serialises_the_help_catalog(client):
    payload = client.get("/api/modulos").json()
    assert len(payload) == 5
    assert {"key", "label", "what_it_does", "legal"} <= set(payload[0])


def test_target_api_returns_the_stable_contract(client, store):
    _seed(store)
    payload = client.get("/api/objetivo", params={"target": TARGET}).json()

    assert payload["target"] == TARGET
    assert payload["risk"]["score"] <= 100
    assert "vuln_identification" in payload["modules"]
    assert payload["artifacts"]["asset_inventory"]["surface_map"]["apex"] == "cliente.test"


def test_target_api_404_for_unknown_target(client):
    assert client.get("/api/objetivo", params={"target": "https://nunca.test"}).status_code == 404


# -- control de acceso -----------------------------------------------------


def test_open_instance_warns_on_screen(client):
    assert "Sin control de acceso" in client.get("/").text


def test_token_protects_every_page(store):
    protected = TestClient(create_app(store=store, token="s3creto"), follow_redirects=False)
    assert protected.get("/").status_code == 307
    assert protected.get("/api/objetivo", params={"target": TARGET}).status_code == 307


def test_wrong_token_is_rejected(store):
    protected = TestClient(create_app(store=store, token="s3creto"))
    assert protected.post("/acceso", data={"token": "otro"}).status_code == 401


def test_correct_token_grants_access(store):
    protected = TestClient(create_app(store=store, token="s3creto"), follow_redirects=False)
    response = protected.post("/acceso", data={"token": "s3creto"})

    assert response.status_code == 303
    assert response.cookies[TOKEN_COOKIE] == "s3creto"
    protected.cookies.set(TOKEN_COOKIE, "s3creto")
    assert protected.get("/").status_code == 200


def test_protected_instance_hides_the_open_warning(store):
    protected = TestClient(create_app(store=store, token="s3creto"))
    protected.cookies.set(TOKEN_COOKIE, "s3creto")
    assert "Sin control de acceso" not in protected.get("/").text
