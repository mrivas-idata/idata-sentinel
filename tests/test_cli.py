from __future__ import annotations

import json

import httpx
import pytest
import respx
from typer.testing import CliRunner

from idata_sentinel.docs import all_modules, module_help, resolve_key
from idata_sentinel.interfaces.cli import _resolve_modules, app
from idata_sentinel.storage.db import ScanStore

runner = CliRunner()


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "cli.db"


def _mock_target() -> None:
    respx.get(url__regex=r"https://cliente\.test.*").mock(
        return_value=httpx.Response(200, headers={"Server": "nginx/1.18.0"}, text="<html></html>")
    )
    respx.get(url__regex=r"http://cliente\.test.*").mock(side_effect=httpx.ConnectError("sin http"))
    respx.get(url__startswith="https://crt.sh/").mock(return_value=httpx.Response(200, text="[]"))


# -- resolución de módulos -------------------------------------------------


@pytest.mark.parametrize("raw", ["", "all", "ALL", None])
def test_all_means_every_registered_module(raw):
    assert _resolve_modules(raw) is None


def test_aliases_expand_to_internal_names():
    assert _resolve_modules("vuln,assets,privacy") == [
        "vuln_identification", "asset_inventory", "data_privacy"
    ]


def test_internal_names_pass_through_and_spaces_are_tolerated():
    assert _resolve_modules(" vuln_identification , assets ") == [
        "vuln_identification", "asset_inventory"
    ]


# -- catálogo de ayuda -----------------------------------------------------


def test_every_module_has_complete_help():
    modules = all_modules()
    assert {m.key for m in modules} == {
        "vuln_identification", "asset_inventory", "data_privacy", "monitoring",
        "search_visibility",
    }
    for m in modules:
        assert m.tagline and m.purpose and m.legal
        assert m.what_it_does and m.key_findings and m.examples


def test_help_lookup_accepts_key_and_alias():
    assert resolve_key("assets") == "asset_inventory"
    assert resolve_key("asset_inventory") == "asset_inventory"
    assert resolve_key("no-existe") is None
    assert module_help("no-existe") is None


def test_help_serialises_for_the_web_app():
    payload = module_help("privacy").to_dict()
    assert payload["label"] == "Datos Personales (Ley 21.719)"
    assert isinstance(payload["what_it_does"], list)


def test_help_command_lists_all_modules():
    result = runner.invoke(app, ["help"])
    assert result.exit_code == 0
    for alias in ("vuln", "assets", "privacy", "monitor"):
        assert alias in result.stdout


def test_help_command_details_a_module():
    result = runner.invoke(app, ["help", "assets"])
    assert result.exit_code == 0
    assert "Inventario de activos" in result.stdout
    assert "Certificate Transparency" in result.stdout
    assert "Límites legales" in result.stdout


def test_help_command_rejects_an_unknown_module():
    result = runner.invoke(app, ["help", "inexistente"])
    assert result.exit_code == 1
    assert "desconocido" in result.stdout


def test_privacy_help_carries_the_legal_disclaimer():
    assert "no constituye una calificación legal" in module_help("privacy").legal.lower()


def test_assets_help_states_takeover_is_never_claimed():
    assert "nunca se reclama" in module_help("assets").legal.lower()


# -- scan ------------------------------------------------------------------


def test_scan_rejects_an_invalid_mode():
    result = runner.invoke(app, ["scan", "https://cliente.test", "--mode", "agresivo"])
    assert result.exit_code == 1
    assert "Modo inválido" in result.stdout


def test_active_check_requires_audit_mode():
    result = runner.invoke(app, [
        "scan", "https://cliente.test", "--active-check", "http_methods", "--rate-limit", "0",
    ])
    assert result.exit_code == 1
    assert "solo corren en modo audit" in result.stdout


def test_active_check_without_ack_aborts_and_logs(tmp_path, monkeypatch):
    """Regresión del corazón del encargo: pedir activo sin confirmar ABORTA (no
    degrada en silencio) y deja rastro en el audit_log."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "cli.db"
    result = runner.invoke(app, [
        "scan", "https://cliente.test", "--mode", "audit",
        "--i-have-authorization", "--authorized-by", "Ana, CISO", "--contract", "OC-1",
        "--allowed-domain", "cliente.test",
        "--active-check", "http_methods",   # sin --i-understand-active
        "--db", str(db), "--rate-limit", "0",
    ])
    assert result.exit_code == 1
    assert "falta la confirmación" in result.stdout

    log = (tmp_path / "audit_log.json").read_text(encoding="utf-8")
    entry = json.loads(log.strip().splitlines()[-1])
    assert entry["decision"] == "denied_active_unacknowledged"
    assert entry["active_checks_enabled"] == ["http_methods"]


@respx.mock
def test_active_scan_end_to_end_runs_named_check_and_reports(tmp_path, monkeypatch):
    """End-to-end del modo activo: audit autorizado + --active-check nombrado +
    doble confirmación → la técnica activa corre y su hallazgo llega al JSON."""
    monkeypatch.chdir(tmp_path)
    _mock_target()
    # OPTIONS a la raíz anuncia TRACE → hallazgo activo http_trace_enabled.
    respx.route(method="OPTIONS", url="https://cliente.test/").mock(
        return_value=httpx.Response(200, headers={"Allow": "GET, OPTIONS, TRACE"}))
    out = tmp_path / "activo.json"

    result = runner.invoke(app, [
        "scan", "https://cliente.test", "--mode", "audit", "--modules", "vuln",
        "--i-have-authorization", "--authorized-by", "Ana, CISO", "--contract", "OC-9",
        "--allowed-domain", "cliente.test",
        "--active-check", "http_methods", "--i-understand-active",
        "--rate-limit", "0", "--json", str(out),
    ])

    assert result.exit_code == 0, result.stdout
    assert "Técnicas activas que se ejecutarán" in result.stdout
    payload = json.loads(out.read_text(encoding="utf-8"))
    ids = {f["id"].split("@")[0] for f in payload["modules"]["vuln_identification"]}
    assert "http_trace_enabled" in ids

    # La autorización y el alcance activo quedaron registrados.
    log = (tmp_path / "audit_log.json").read_text(encoding="utf-8")
    entry = json.loads(log.strip().splitlines()[-1])
    assert entry["decision"] == "granted"
    assert entry["active_checks_enabled"] == ["http_methods"]


@respx.mock
def test_audit_without_active_check_stays_passive_in_behaviour(tmp_path, monkeypatch):
    """El modo audit SIN --active-check no ejecuta ninguna técnica activa."""
    monkeypatch.chdir(tmp_path)
    _mock_target()
    options_route = respx.route(method="OPTIONS", url__regex=r"https://cliente\.test.*").mock(
        return_value=httpx.Response(200, headers={"Allow": "TRACE"}))
    out = tmp_path / "sin-activo.json"

    runner.invoke(app, [
        "scan", "https://cliente.test", "--mode", "audit", "--modules", "vuln",
        "--i-have-authorization", "--authorized-by", "Ana", "--contract", "OC-9",
        "--allowed-domain", "cliente.test", "--rate-limit", "0", "--json", str(out),
    ])

    payload = json.loads(out.read_text(encoding="utf-8"))
    ids = {f["id"].split("@")[0] for f in payload["modules"]["vuln_identification"]}
    assert "http_trace_enabled" not in ids   # ninguna técnica activa corrió
    assert not options_route.called          # ni siquiera se emitió el OPTIONS


@respx.mock
def test_scan_prints_score_and_findings():
    _mock_target()
    result = runner.invoke(app, ["scan", "https://cliente.test", "--modules", "vuln", "--rate-limit", "0"])

    assert result.exit_code == 0
    # "Seguridad", no "Score": desde que hay dos ejes puntuables, una nota sin
    # rótulo no dice cuál de los dos es.
    assert "Seguridad:" in result.stdout
    assert "Hallazgos" in result.stdout
    # Sin el módulo de visibilidad en el escaneo, no se inventa su nota.
    assert "Visibilidad:" not in result.stdout


@respx.mock
def test_scan_exports_json(tmp_path):
    _mock_target()
    out = tmp_path / "resultado.json"
    result = runner.invoke(
        app, ["scan", "https://cliente.test", "--modules", "vuln", "--rate-limit", "0", "--json", str(out)]
    )

    assert result.exit_code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["target"] == "https://cliente.test"
    assert payload["risk"]["score"] <= 100
    assert "vuln_identification" in payload["modules"]


@respx.mock
def test_scan_with_record_persists_and_creates_a_baseline(db_path):
    _mock_target()
    result = runner.invoke(
        app, ["scan", "https://cliente.test", "--modules", "vuln", "--record", "--db", str(db_path), "--rate-limit", "0"]
    )

    assert result.exit_code == 0
    store = ScanStore(db_path)
    baseline = store.baseline("https://cliente.test")
    assert baseline is not None
    assert baseline.is_baseline is True


@respx.mock
def test_second_recorded_scan_reports_no_changes(db_path):
    _mock_target()
    args = ["scan", "https://cliente.test", "--modules", "vuln", "--record", "--db", str(db_path), "--rate-limit", "0"]
    runner.invoke(app, args)
    result = runner.invoke(app, args)

    assert result.exit_code == 0
    assert len(ScanStore(db_path).history("https://cliente.test")) == 2


@respx.mock
def test_scan_without_record_writes_nothing(db_path):
    _mock_target()
    runner.invoke(app, ["scan", "https://cliente.test", "--modules", "vuln", "--rate-limit", "0"])
    assert not db_path.exists()


# -- monitor ---------------------------------------------------------------


def test_monitor_add_list_and_remove(db_path):
    added = runner.invoke(
        app, ["monitor", "add", "https://cliente.test", "--schedule", "daily", "--db", str(db_path)]
    )
    assert added.exit_code == 0
    assert "Monitor creado" in added.stdout

    listed = runner.invoke(app, ["monitor", "list", "--db", str(db_path)])
    assert "cliente.test" in listed.stdout
    assert "daily" in listed.stdout

    removed = runner.invoke(app, ["monitor", "remove", "https://cliente.test", "--db", str(db_path)])
    assert "Monitor eliminado" in removed.stdout


def test_monitor_add_with_email_and_overview(db_path):
    from idata_sentinel.storage.db import ScanStore
    runner.invoke(app, [
        "monitor", "add", "https://cliente.test", "--schedule", "weekly",
        "--email", "cliente@empresa.cl", "--db", str(db_path)])
    # el monitor guardó el email…
    assert ScanStore(db_path).get_monitor("https://cliente.test").notify_email == "cliente@empresa.cl"
    # …y aparece en list.
    listed = runner.invoke(app, ["monitor", "list", "--db", str(db_path)])
    assert "email" in listed.stdout

    # overview con historial muestra score y nota.
    ScanStore(db_path).record_scan(
        target="https://cliente.test", mode="passive", score=72, grade="C", findings=[])
    overview = runner.invoke(app, ["monitor", "overview", "--db", str(db_path)])
    assert overview.exit_code == 0
    assert "72" in overview.stdout and "Cartera" in overview.stdout


def test_monitor_add_rejects_an_invalid_schedule(db_path):
    result = runner.invoke(
        app, ["monitor", "add", "https://cliente.test", "--schedule", "cuando sea", "--db", str(db_path)]
    )
    assert result.exit_code == 1
    assert "Cadencia inválida" in result.stdout


def test_monitor_list_without_monitors(db_path):
    result = runner.invoke(app, ["monitor", "list", "--db", str(db_path)])
    assert "Sin monitores configurados" in result.stdout


def test_monitor_remove_unknown_target(db_path):
    result = runner.invoke(app, ["monitor", "remove", "https://nunca.test", "--db", str(db_path)])
    assert "No había un monitor" in result.stdout


def test_monitor_status_without_history(db_path):
    result = runner.invoke(app, ["monitor", "status", "https://nunca.test", "--db", str(db_path)])
    assert "Sin escaneos registrados" in result.stdout


def test_monitor_status_shows_the_trend(db_path):
    store = ScanStore(db_path)
    store.record_scan(target="https://cliente.test", mode="passive", score=60, grade="D",
                      findings=[], scanned_at="2026-01-01T00:00:00+00:00")
    store.record_scan(target="https://cliente.test", mode="passive", score=85, grade="B",
                      findings=[], scanned_at="2026-02-01T00:00:00+00:00")

    result = runner.invoke(app, ["monitor", "status", "https://cliente.test", "--db", str(db_path)])
    assert "Tendencia" in result.stdout
    assert "mejoró 25" in result.stdout


def test_monitor_run_without_due_monitors(db_path):
    ScanStore(db_path)
    result = runner.invoke(app, ["monitor", "run", "--db", str(db_path), "--rate-limit", "0"])
    assert result.exit_code == 0
    assert "Ningún monitor vencido" in result.stdout


def test_serve_refuses_to_expose_an_open_scanner(db_path, monkeypatch):
    """Un escáner abierto a Internet es una herramienta de abuso contra terceros."""
    monkeypatch.delenv("IDATA_SENTINEL_TOKEN", raising=False)
    result = runner.invoke(app, ["serve", "--host", "0.0.0.0", "--db", str(db_path)])

    assert result.exit_code == 1
    assert "Negado" in result.stdout


@respx.mock
def test_monitor_run_executes_a_due_monitor(db_path):
    _mock_target()
    ScanStore(db_path).add_monitor(target="https://cliente.test", schedule="daily", modules="vuln")

    result = runner.invoke(app, ["monitor", "run", "--db", str(db_path), "--rate-limit", "0"])

    assert result.exit_code == 0
    assert "Re-escaneando" in result.stdout
    assert ScanStore(db_path).latest_scan("https://cliente.test") is not None
