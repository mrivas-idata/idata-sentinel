from __future__ import annotations

import pytest

from idata_sentinel.scoring.risk_engine import calculate


def _f(fid="x", *, severity="high", likelihood="high", status="fail", category="HTTP Headers",
       module="vuln_identification") -> dict:
    return {
        "id": fid, "module": module, "category": category, "severity": severity,
        "likelihood": likelihood, "status": status, "title": fid, "finding": "f",
        "business_impact": "b", "recommendation": "r", "evidence": "e", "references": [],
    }


def test_clean_scan_scores_one_hundred():
    risk = calculate({"vuln_identification": []})
    assert (risk.score, risk.grade) == (100, "A")


@pytest.mark.parametrize(
    "severity,likelihood,expected",
    [
        ("critical", "high", 75),    # 100 - 25 * 1.0
        ("critical", "medium", 82),  # 100 - 25 * 0.7 = 82.5 -> 82 (banker's rounding)
        ("high", "high", 85),        # 100 - 15 * 1.0
        ("high", "low", 94),         # 100 - 15 * 0.4
        ("medium", "medium", 94),    # 100 - 8 * 0.7 = 94.4
        ("low", "low", 99),          # 100 - 3 * 0.4 = 98.8 -> 99
        ("info", "high", 100),       # info no penaliza
    ],
)
def test_severity_times_likelihood_matches_the_plan(severity, likelihood, expected):
    risk = calculate({"vuln_identification": [_f(severity=severity, likelihood=likelihood)]})
    assert risk.score == expected


@pytest.mark.parametrize(
    "score_findings,expected_grade",
    [([], "A"), ([_f(severity="medium", likelihood="medium")], "A")],
)
def test_grade_a_for_healthy_targets(score_findings, expected_grade):
    assert calculate({"vuln_identification": score_findings}).grade == expected_grade


@pytest.mark.parametrize(
    "count,expected_score,expected_grade",
    [(1, 85, "B"), (2, 70, "C"), (3, 55, "F"), (5, 25, "F")],
)
def test_grade_degrades_with_accumulated_findings(count, expected_score, expected_grade):
    findings = [_f(f"f{i}", severity="high", likelihood="high") for i in range(count)]
    risk = calculate({"vuln_identification": findings})
    assert (risk.score, risk.grade) == (expected_score, expected_grade)


def test_grade_d_band():
    """60-69 = D: dos `high` más un `medium` dan 62."""
    findings = [
        _f("a", severity="high"), _f("b", severity="high"),
        _f("c", severity="medium", likelihood="high"),
    ]
    risk = calculate({"vuln_identification": findings})
    assert (risk.score, risk.grade) == (62, "D")


def test_score_never_goes_below_zero():
    findings = [_f(f"f{i}", severity="critical") for i in range(20)]
    assert calculate({"vuln_identification": findings}).score == 0


def test_passing_and_informative_findings_do_not_penalise():
    findings = [
        _f("ok", severity="info", status="pass"),
        _f("nota", severity="critical", status="info"),  # "no evaluable", no es hallazgo
    ]
    assert calculate({"vuln_identification": findings}).score == 100


def test_module_scores_are_independent():
    risk = calculate({
        "vuln_identification": [_f(severity="critical")],
        "asset_inventory": [],
    })
    assert risk.module_scores == {"vuln_identification": 75, "asset_inventory": 100}


def test_category_scores_group_across_modules():
    risk = calculate({
        "vuln_identification": [_f("a", category="TLS/SSL", severity="critical")],
        "asset_inventory": [_f("b", category="DNS y Correo", severity="medium",
                               likelihood="medium", module="asset_inventory")],
    })
    assert risk.category_scores["TLS/SSL"] == 75
    assert risk.category_scores["DNS y Correo"] == 94


def test_global_score_accumulates_every_module():
    risk = calculate({
        "vuln_identification": [_f("a", severity="high")],
        "data_privacy": [_f("b", severity="high", module="data_privacy")],
    })
    assert risk.score == 70  # 100 - 15 - 15


def test_to_dict_exposes_the_full_breakdown():
    payload = calculate({"vuln_identification": [_f(severity="high")]}).to_dict()
    assert set(payload) == {"score", "grade", "module_scores", "category_scores"}
    assert payload["grade"] == "B"


def test_empty_input_is_a_perfect_score():
    risk = calculate({})
    assert (risk.score, risk.grade, risk.module_scores) == (100, "A", {})
