from __future__ import annotations

import pytest

from idata_sentinel.storage.db import MonitorRecord, ScanStore
from idata_sentinel.storage.retention import apply_retention

TARGET = "https://cliente.test"


@pytest.fixture
def store(tmp_path) -> ScanStore:
    return ScanStore(tmp_path / "test.db")


def _finding(fid: str, *, status="fail", severity="high") -> dict:
    return {
        "id": fid, "module": "vuln_identification", "category": "Test", "severity": severity,
        "likelihood": "high", "status": status, "title": f"Título {fid}", "finding": "f",
        "business_impact": "b", "recommendation": "r", "evidence": "e", "references": [],
    }


def _record(store: ScanStore, *, score=80, at="2026-01-01T00:00:00+00:00", findings=None):
    return store.record_scan(
        target=TARGET, mode="passive", score=score, grade="B",
        findings=findings or [_finding("hsts_missing")], scanned_at=at,
    )


# -- escaneos --------------------------------------------------------------


def test_first_scan_becomes_the_baseline(store):
    first = _record(store)
    second = _record(store, at="2026-02-01T00:00:00+00:00")

    assert first.is_baseline is True
    assert second.is_baseline is False
    assert store.baseline(TARGET).id == first.id


def test_findings_and_artifacts_round_trip(store):
    store.record_scan(
        target=TARGET, mode="audit", score=42, grade="F",
        findings=[_finding("cert_expired")],
        artifacts={"asset_inventory": {"surface_map": {"apex": "cliente.test", "assets": []}}},
        scanned_at="2026-01-01T00:00:00+00:00",
    )
    record = store.latest_scan(TARGET)

    assert record.findings[0]["id"] == "cert_expired"
    assert record.surface_map()["apex"] == "cliente.test"
    assert record.mode == "audit"


def test_surface_map_is_none_without_the_asset_module(store):
    _record(store)
    assert store.latest_scan(TARGET).surface_map() is None


def test_latest_scan_returns_the_most_recent(store):
    _record(store, score=80)
    _record(store, score=55, at="2026-03-01T00:00:00+00:00")
    assert store.latest_scan(TARGET).score == 55


def test_latest_scan_before_id_skips_newer_records(store):
    first = _record(store, score=80)
    second = _record(store, score=55, at="2026-03-01T00:00:00+00:00")
    assert store.latest_scan(TARGET, before_id=second.id).id == first.id


def test_history_is_chronological(store):
    _record(store, score=60, at="2026-01-01T00:00:00+00:00")
    _record(store, score=70, at="2026-02-01T00:00:00+00:00")
    _record(store, score=90, at="2026-03-01T00:00:00+00:00")

    assert [r.score for r in store.history(TARGET)] == [60, 70, 90]


def test_history_limit_keeps_the_newest(store):
    for i, score in enumerate([10, 20, 30, 40]):
        _record(store, score=score, at=f"2026-0{i + 1}-01T00:00:00+00:00")
    assert [r.score for r in store.history(TARGET, limit=2)] == [30, 40]


def test_set_baseline_moves_the_reference(store):
    _record(store)
    second = _record(store, score=95, at="2026-02-01T00:00:00+00:00")

    store.set_baseline(TARGET, second.id)
    assert store.baseline(TARGET).id == second.id


def test_targets_lists_distinct_scanned_targets(store):
    _record(store)
    store.record_scan(target="https://otro.test", mode="passive", score=100, grade="A", findings=[])
    assert store.targets() == ["https://cliente.test", "https://otro.test"]


def test_unknown_target_has_no_baseline_or_history(store):
    assert store.baseline("https://nunca.test") is None
    assert store.history("https://nunca.test") == []


# -- monitores -------------------------------------------------------------


def test_add_and_get_monitor(store):
    store.add_monitor(target=TARGET, schedule="daily", webhook_url="https://hook.test/x")
    monitor = store.get_monitor(TARGET)

    assert monitor.schedule == "daily"
    assert monitor.webhook_url == "https://hook.test/x"
    assert monitor.active is True


def test_add_monitor_twice_updates_instead_of_duplicating(store):
    store.add_monitor(target=TARGET, schedule="daily")
    store.add_monitor(target=TARGET, schedule="monthly")

    assert len(store.list_monitors()) == 1
    assert store.get_monitor(TARGET).schedule == "monthly"


def test_invalid_schedule_is_rejected(store):
    with pytest.raises(ValueError, match="Cadencia inválida"):
        store.add_monitor(target=TARGET, schedule="cada rato")


def test_remove_monitor(store):
    store.add_monitor(target=TARGET)
    assert store.remove_monitor(TARGET) is True
    assert store.remove_monitor(TARGET) is False


def test_monitor_never_run_is_due():
    monitor = MonitorRecord(
        target=TARGET, schedule="weekly", mode="passive", webhook_url=None,
        created_at="2026-01-01T00:00:00+00:00", last_run_at=None, active=True,
    )
    assert monitor.is_due(now="2026-01-01T00:00:00+00:00") is True


@pytest.mark.parametrize(
    "schedule,now,expected",
    [
        ("daily", "2026-01-02T00:00:00+00:00", True),
        ("daily", "2026-01-01T12:00:00+00:00", False),
        ("weekly", "2026-01-08T00:00:00+00:00", True),
        ("weekly", "2026-01-05T00:00:00+00:00", False),
        ("monthly", "2026-02-01T00:00:00+00:00", True),
    ],
)
def test_monitor_due_respects_its_cadence(schedule, now, expected):
    monitor = MonitorRecord(
        target=TARGET, schedule=schedule, mode="passive", webhook_url=None,
        created_at="2026-01-01T00:00:00+00:00", last_run_at="2026-01-01T00:00:00+00:00", active=True,
    )
    assert monitor.is_due(now=now) is expected


def test_inactive_monitor_is_never_due():
    monitor = MonitorRecord(
        target=TARGET, schedule="daily", mode="passive", webhook_url=None,
        created_at="2026-01-01T00:00:00+00:00", last_run_at=None, active=False,
    )
    assert monitor.is_due(now="2027-01-01T00:00:00+00:00") is False


def test_due_monitors_filters_and_mark_run_clears_it(store):
    store.add_monitor(target=TARGET, schedule="daily", created_at="2026-01-01T00:00:00+00:00")
    assert [m.target for m in store.due_monitors(now="2026-01-02T00:00:00+00:00")] == [TARGET]

    store.mark_monitor_run(TARGET, at="2026-01-02T00:00:00+00:00")
    assert store.due_monitors(now="2026-01-02T06:00:00+00:00") == []


def test_list_monitors_can_filter_inactive(store):
    store.add_monitor(target=TARGET)
    assert len(store.list_monitors(only_active=True)) == 1


# -- retención -------------------------------------------------------------


def test_retention_deletes_old_scans_but_keeps_the_baseline(store):
    _record(store, at="2020-01-01T00:00:00+00:00")            # baseline antiguo
    _record(store, at="2020-06-01T00:00:00+00:00")            # antiguo, no baseline
    _record(store, at="2026-07-01T00:00:00+00:00")            # reciente

    result = apply_retention(store, days=365, now="2026-07-25T00:00:00+00:00")

    assert result.deleted == 1
    assert result.kept_baselines == 1
    assert store.baseline(TARGET) is not None
    assert len(store.history(TARGET)) == 2


def test_retention_is_a_noop_when_everything_is_recent(store):
    _record(store, at="2026-07-01T00:00:00+00:00")
    result = apply_retention(store, days=365, now="2026-07-25T00:00:00+00:00")
    assert result.deleted == 0
