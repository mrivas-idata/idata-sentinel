from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.core.engine import ModuleOutput, RunParams
from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.core.rate_limiter import RateLimiter
from idata_sentinel.modules.monitoring.alerts import (
    CollectingNotifier,
    EmailConfig,
    EmailNotifier,
    WebhookNotifier,
    build_alerts,
    build_digest,
    dispatch,
)
from idata_sentinel.modules.monitoring.diff import (
    AssetsDiff,
    FindingsDiff,
    build_trend,
    diff_assets,
    diff_findings,
)
from idata_sentinel.modules.monitoring.module import MonitoringModule
from idata_sentinel.modules.monitoring.scheduler import MonitorScheduler
from idata_sentinel.storage.db import ScanStore
from idata_sentinel.core.check_base import FINDING_CONTRACT_KEYS

TARGET = "https://cliente.test"


def _f(fid: str, *, severity="high", status="fail", title=None) -> dict:
    return {
        "id": fid, "module": "vuln_identification", "category": "Test", "severity": severity,
        "likelihood": "high", "status": status, "title": title or f"Título {fid}",
        "finding": "f", "business_impact": "b", "recommendation": "Corregir", "evidence": "e",
        "references": [],
    }


def _surface(*hosts: str, technologies: dict | None = None) -> dict:
    technologies = technologies or {}
    return {
        "apex": "cliente.test",
        "assets": [{"host": h, "technologies": technologies.get(h, [])} for h in hosts],
    }


@pytest.fixture
def store(tmp_path) -> ScanStore:
    return ScanStore(tmp_path / "monitor.db")


def _params(*, findings=None, artifacts=None) -> RunParams:
    return RunParams(
        target=TARGET, host="cliente.test", mode="passive",
        http=HttpClient(), rate_limiter=RateLimiter(min_interval=0.0),
        authorized=False, authorization=None,
        previous_findings=findings or [],
        module_artifacts=artifacts or {},
    )


# -- diff de hallazgos -----------------------------------------------------


def test_diff_classifies_new_resolved_and_unchanged():
    diff = diff_findings(
        baseline=[_f("a"), _f("b")],
        current=[_f("b"), _f("c")],
    )
    assert [f["id"] for f in diff.new] == ["c"]
    assert [f["id"] for f in diff.resolved] == ["a"]
    assert len(diff.unchanged) == 1
    assert diff.has_changes


def test_diff_ignores_informative_findings():
    diff = diff_findings(
        baseline=[_f("a", status="info", severity="info")],
        current=[_f("b", status="pass", severity="info")],
    )
    assert not diff.has_changes


def test_diff_detects_severity_escalation():
    diff = diff_findings(baseline=[_f("a", severity="low")], current=[_f("a", severity="critical")])
    change = diff.severity_changes[0]

    assert (change.before, change.after) == ("low", "critical")
    assert change.worsened is True


def test_diff_detects_severity_improvement():
    diff = diff_findings(baseline=[_f("a", severity="critical")], current=[_f("a", severity="low")])
    assert diff.severity_changes[0].worsened is False


def test_diff_orders_new_findings_by_severity():
    diff = diff_findings(baseline=[], current=[_f("a", severity="low"), _f("b", severity="critical")])
    assert [f["id"] for f in diff.new] == ["b", "a"]


def test_identical_scans_report_no_changes():
    findings = [_f("a"), _f("b")]
    assert not diff_findings(findings, findings).has_changes


def test_findings_diff_serialises_for_the_report():
    payload = diff_findings([_f("a")], [_f("b")]).to_dict()
    assert payload["new"][0]["id"] == "b"
    assert payload["resolved"][0]["id"] == "a"


# -- diff de activos -------------------------------------------------------


def test_asset_diff_detects_new_and_removed_hosts():
    diff = diff_assets(_surface("www.cliente.test"), _surface("www.cliente.test", "api.cliente.test"))
    assert diff.new_assets == ["api.cliente.test"]
    assert diff.removed_assets == []
    assert diff.has_changes


def test_asset_diff_detects_technology_changes():
    diff = diff_assets(
        _surface("www.cliente.test", technologies={"www.cliente.test": ["Nginx 1.18.0"]}),
        _surface("www.cliente.test", technologies={"www.cliente.test": ["Nginx 1.25.0"]}),
    )
    assert diff.technology_changes["www.cliente.test"] == {
        "added": ["Nginx 1.25.0"], "removed": ["Nginx 1.18.0"]
    }


def test_asset_diff_is_empty_without_both_surfaces():
    assert not diff_assets(None, _surface("a.cliente.test")).has_changes
    assert not diff_assets(_surface("a.cliente.test"), None).has_changes


# -- tendencia -------------------------------------------------------------


class _FakeRecord:
    def __init__(self, score, grade="B", scanned_at="2026-01-01T00:00:00+00:00"):
        self.score, self.grade, self.scanned_at = score, grade, scanned_at


def test_trend_computes_delta_best_and_worst():
    trend = build_trend([_FakeRecord(60), _FakeRecord(80), _FakeRecord(75)])
    assert (trend["current"], trend["previous"], trend["delta"]) == (75, 80, -5)
    assert (trend["best"], trend["worst"]) == (80, 60)


def test_trend_of_a_single_scan_has_no_delta():
    trend = build_trend([_FakeRecord(60)])
    assert trend["delta"] == 0
    assert trend["previous"] is None


def test_trend_of_empty_history():
    assert build_trend([])["current"] is None


# -- alertas ---------------------------------------------------------------


def test_severe_new_findings_raise_a_critical_alert():
    alerts = build_alerts(
        target=TARGET,
        findings_diff=diff_findings([], [_f("cert_expired", severity="critical")]),
        assets_diff=AssetsDiff(),
        trend={"delta": 0},
    )
    assert alerts[0].level == "critical"
    assert "cert_expired" in alerts[0].details["findings"]


def test_low_severity_new_finding_does_not_alert():
    alerts = build_alerts(
        target=TARGET,
        findings_diff=diff_findings([], [_f("x", severity="low")]),
        assets_diff=AssetsDiff(),
        trend={"delta": 0},
    )
    assert alerts == []


def test_new_assets_and_score_drop_raise_warnings():
    alerts = build_alerts(
        target=TARGET,
        findings_diff=FindingsDiff(),
        assets_diff=AssetsDiff(new_assets=["dev.cliente.test"]),
        trend={"delta": -15, "previous": 80, "current": 65},
    )
    levels = [a.level for a in alerts]
    titles = " ".join(a.title for a in alerts)

    assert levels == ["warning", "warning"]
    assert "activo(s) nuevo(s)" in titles
    assert "cayó 15 puntos" in titles


def test_score_improvement_is_informative():
    alerts = build_alerts(
        target=TARGET, findings_diff=FindingsDiff(), assets_diff=AssetsDiff(),
        trend={"delta": 12, "previous": 70, "current": 82},
    )
    assert [a.level for a in alerts] == ["info"]


def test_expiring_certificate_raises_an_alert():
    alerts = build_alerts(
        target=TARGET, findings_diff=FindingsDiff(), assets_diff=AssetsDiff(), trend={"delta": 0},
        expiring_certs=[{"id": "cert_expiring_soon", "finding": "vence en 12 días"}],
    )
    assert "Certificado por vencer" in alerts[0].title


def test_worsened_finding_raises_a_warning():
    alerts = build_alerts(
        target=TARGET,
        findings_diff=diff_findings([_f("a", severity="low")], [_f("a", severity="high")]),
        assets_diff=AssetsDiff(), trend={"delta": 0},
    )
    assert any("empeoraron" in a.title for a in alerts)


@respx.mock
async def test_webhook_notifier_posts_the_alert():
    route = respx.post("https://hook.test/alert").mock(return_value=httpx.Response(200))
    alert = build_alerts(
        target=TARGET, findings_diff=diff_findings([], [_f("x", severity="critical")]),
        assets_diff=AssetsDiff(), trend={"delta": 0},
    )[0]

    async with HttpClient() as http:
        assert await WebhookNotifier("https://hook.test/alert", http).send(alert) is True

    assert route.called
    assert route.calls[0].request.content


@respx.mock
async def test_webhook_failure_never_raises():
    respx.post("https://hook.test/alert").mock(side_effect=httpx.ConnectError("caído"))
    alert = build_alerts(
        target=TARGET, findings_diff=diff_findings([], [_f("x", severity="critical")]),
        assets_diff=AssetsDiff(), trend={"delta": 0},
    )[0]

    async with HttpClient() as http:
        assert await WebhookNotifier("https://hook.test/alert", http).send(alert) is False


async def test_dispatch_sends_every_alert_to_every_notifier():
    a, b = CollectingNotifier(), CollectingNotifier()
    alerts = build_alerts(
        target=TARGET,
        findings_diff=diff_findings([], [_f("x", severity="critical")]),
        assets_diff=AssetsDiff(new_assets=["dev.cliente.test"]), trend={"delta": 0},
    )
    assert await dispatch(alerts, [a, b]) == 4
    assert len(a.sent) == len(b.sent) == 2


# -- digest por correo -----------------------------------------------------


def test_email_config_from_env_is_none_without_host():
    assert EmailConfig.from_env(env={}) is None


def test_email_config_from_env_reads_smtp_settings():
    cfg = EmailConfig.from_env(env={
        "IDATA_SMTP_HOST": "smtp.test", "IDATA_SMTP_PORT": "465",
        "IDATA_SMTP_USER": "u@test", "IDATA_SMTP_PASSWORD": "p", "IDATA_SMTP_FROM": "from@test",
    })
    assert (cfg.host, cfg.port, cfg.sender) == ("smtp.test", 465, "from@test")


def test_build_digest_summarises_all_alerts_in_one_message():
    alerts = build_alerts(
        target=TARGET,
        findings_diff=diff_findings([], [_f("cert_expired", severity="critical", title="Cert vencido")]),
        assets_diff=AssetsDiff(new_assets=["dev.cliente.test"]), trend={"delta": -12, "previous": 80, "current": 68},
    )
    subject, text, html = build_digest(TARGET, alerts, {"delta": -12, "previous": 80, "current": 68})
    assert "CRÍTICO" in subject and "cliente.test" in subject
    assert "Cert vencido" in text and "dev.cliente.test" in text
    assert "80" in text and "68" in text          # tendencia del score
    assert "<html" not in html and "<div" in html  # cuerpo HTML válido


async def test_email_notifier_sends_one_digest_for_all_alerts():
    captured = []

    def _fake_send(message):
        captured.append(message)

    notifier = EmailNotifier(
        EmailConfig("smtp.test", 587, "u", "p", "from@test"),
        recipient="cliente@test", sender_fn=_fake_send,
    )
    alerts = build_alerts(
        target=TARGET,
        findings_diff=diff_findings([], [_f("x", severity="critical")]),
        assets_diff=AssetsDiff(new_assets=["dev.cliente.test"]), trend={"delta": 0},
    )
    # dispatch enruta: una llamada de digest, no una por alerta.
    delivered = await dispatch(alerts, [notifier], target=TARGET, trend={"delta": 0})

    assert delivered == 1
    assert len(captured) == 1                       # UN correo con todo
    assert captured[0]["To"] == "cliente@test"


async def test_email_notifier_failure_never_raises():
    def _boom(message):
        raise RuntimeError("smtp caído")

    notifier = EmailNotifier(
        EmailConfig("smtp.test", 587, "u", "p", "from@test"),
        recipient="cliente@test", sender_fn=_boom,
    )
    alert = build_alerts(
        target=TARGET, findings_diff=diff_findings([], [_f("x", severity="critical")]),
        assets_diff=AssetsDiff(), trend={"delta": 0})
    assert await notifier.send_digest(TARGET, alert, {}) is False


# -- runner ----------------------------------------------------------------


async def test_first_scan_reports_baseline_creation(store):
    output = await MonitoringModule(store).run(_params(findings=[_f("a")]))

    assert isinstance(output, ModuleOutput)
    assert output.findings[0]["id"].startswith("monitoring_baseline_created")
    assert output.artifacts["monitoring"]["baseline"] is None


async def test_new_finding_since_last_scan_is_reported(store):
    store.record_scan(target=TARGET, mode="passive", score=90, grade="A", findings=[_f("a")])
    output = await MonitoringModule(store).run(_params(findings=[_f("a"), _f("b")]))

    new = next(f for f in output.findings if f["id"].startswith("new_finding_since_last_scan"))
    assert new["severity"] == "high"
    assert new["recommendation"] == "Corregir"


async def test_persistent_finding_does_not_re_alert_each_run(store):
    """Regresión del bug de cadencia: el diff era contra la LÍNEA BASE, así que un
    hallazgo que persistía se re-anunciaba y re-alertaba en cada corrida. Ahora el
    diff es contra el escaneo ANTERIOR: si ya estaba, no vuelve a alertar."""
    # Corrida 1 (baseline) tenía [a]; corrida 2 introdujo [a, b] (b es nuevo, alertó).
    # Mismo score en ambas para aislar el chequeo de findings (sin alerta de tendencia).
    store.record_scan(target=TARGET, mode="passive", score=80, grade="B", findings=[_f("a")])
    store.record_scan(target=TARGET, mode="passive", score=80, grade="B",
                      findings=[_f("a"), _f("b", severity="critical")])
    # Corrida 3: sigue [a, b]. b ya no es "nuevo" respecto de la corrida anterior.
    notifier = CollectingNotifier()
    output = await MonitoringModule(store, notifiers=[notifier]).run(
        _params(findings=[_f("a"), _f("b", severity="critical")]))

    assert not any(f["id"].startswith("new_finding_since_last_scan") for f in output.findings)
    assert notifier.sent == []  # no re-alerta lo ya conocido
    assert any(f["id"].startswith("no_changes_since_last_scan") for f in output.findings)


async def test_resolved_findings_are_reported_as_a_pass(store):
    store.record_scan(target=TARGET, mode="passive", score=60, grade="D", findings=[_f("a"), _f("b")])
    output = await MonitoringModule(store).run(_params(findings=[_f("a")]))

    resolved = next(f for f in output.findings if f["id"].startswith("findings_resolved"))
    assert resolved["status"] == "pass"


async def test_worsened_finding_is_reported(store):
    store.record_scan(
        target=TARGET, mode="passive", score=90, grade="A", findings=[_f("a", severity="low")]
    )
    output = await MonitoringModule(store).run(_params(findings=[_f("a", severity="critical")]))

    worsened = next(f for f in output.findings if f["id"].startswith("finding_worsened"))
    assert worsened["severity"] == "critical"


async def test_new_asset_is_reported_and_alerted(store):
    store.record_scan(
        target=TARGET, mode="passive", score=90, grade="A", findings=[],
        artifacts={"asset_inventory": {"surface_map": _surface("www.cliente.test")}},
    )
    notifier = CollectingNotifier()
    output = await MonitoringModule(store, notifiers=[notifier]).run(_params(
        artifacts={"asset_inventory": {"surface_map": _surface("www.cliente.test", "dev.cliente.test")}},
    ))

    assert any(f["id"].startswith("new_assets_detected") for f in output.findings)
    assert output.artifacts["monitoring"]["assets_diff"]["new_assets"] == ["dev.cliente.test"]
    assert any("activo(s) nuevo(s)" in a.title for a in notifier.sent)


async def test_technology_change_is_reported(store):
    store.record_scan(
        target=TARGET, mode="passive", score=90, grade="A", findings=[],
        artifacts={"asset_inventory": {"surface_map": _surface(
            "www.cliente.test", technologies={"www.cliente.test": ["Nginx 1.18.0"]})}},
    )
    output = await MonitoringModule(store).run(_params(
        artifacts={"asset_inventory": {"surface_map": _surface(
            "www.cliente.test", technologies={"www.cliente.test": ["Nginx 1.25.0"]})}},
    ))
    assert any(f["id"].startswith("technology_changed") for f in output.findings)


async def test_stable_posture_reports_no_changes(store):
    store.record_scan(target=TARGET, mode="passive", score=90, grade="A", findings=[_f("a")])
    output = await MonitoringModule(store).run(_params(findings=[_f("a")]))

    assert len(output.findings) == 1
    assert output.findings[0]["id"].startswith("no_changes_since_last_scan")
    assert output.findings[0]["status"] == "pass"


async def test_score_drop_is_reported(store):
    store.record_scan(target=TARGET, mode="passive", score=90, grade="A", findings=[],
                      scanned_at="2026-01-01T00:00:00+00:00")
    store.record_scan(target=TARGET, mode="passive", score=60, grade="D", findings=[],
                      scanned_at="2026-02-01T00:00:00+00:00")
    output = await MonitoringModule(store).run(_params())

    assert any(f["id"].startswith("risk_score_dropped") for f in output.findings)


async def test_all_monitoring_findings_conform_to_contract(store):
    store.record_scan(target=TARGET, mode="passive", score=90, grade="A", findings=[_f("a")])
    output = await MonitoringModule(store).run(_params(findings=[_f("b", severity="critical")]))

    for f in output.findings:
        assert set(f) == FINDING_CONTRACT_KEYS
        assert f["module"] == "monitoring"


# -- scheduler -------------------------------------------------------------


async def test_scheduler_runs_only_due_monitors(store):
    store.add_monitor(target=TARGET, schedule="daily", created_at="2026-01-01T00:00:00+00:00")
    store.add_monitor(target="https://otro.test", schedule="daily",
                      created_at="2026-01-01T00:00:00+00:00")
    store.mark_monitor_run("https://otro.test", at="2026-01-02T00:00:00+00:00")

    ran: list[str] = []

    async def _run(monitor):
        ran.append(monitor.target)

    scheduler = MonitorScheduler(store=store, run_scan=_run)
    executed = await scheduler.run_due(now="2026-01-02T06:00:00+00:00")

    assert ran == [TARGET]
    assert executed == [TARGET]
    assert store.get_monitor(TARGET).last_run_at == "2026-01-02T06:00:00+00:00"


async def test_scheduler_isolates_a_failing_monitor(store):
    store.add_monitor(target=TARGET, schedule="daily", created_at="2026-01-01T00:00:00+00:00")
    store.add_monitor(target="https://otro.test", schedule="daily",
                      created_at="2026-01-01T00:00:00+00:00")

    async def _run(monitor):
        if monitor.target == TARGET:
            raise RuntimeError("boom")

    executed = await MonitorScheduler(store=store, run_scan=_run).run_due(
        now="2026-01-03T00:00:00+00:00"
    )
    assert executed == ["https://otro.test"]
    assert store.get_monitor(TARGET).last_run_at is None


async def test_serve_forever_stops_after_the_requested_iterations(store):
    calls: list[int] = []

    async def _run(monitor):  # pragma: no cover - sin monitores vencidos
        calls.append(1)

    scheduler = MonitorScheduler(store=store, run_scan=_run, poll_seconds=0)
    await scheduler.serve_forever(iterations=2)
    assert calls == []
