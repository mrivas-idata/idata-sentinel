from __future__ import annotations

import pytest

from idata_sentinel.scoring.risk_engine import calculate


def _f(fid="x", *, severity="high", likelihood="high", status="fail", category="HTTP Headers",
       module="vuln_identification", confidence="high") -> dict:
    return {
        "id": fid, "module": module, "category": category, "severity": severity,
        "likelihood": likelihood, "status": status, "title": fid, "finding": "f",
        "business_impact": "b", "recommendation": "r", "evidence": "e", "references": [],
        "confidence": confidence,
    }


def test_clean_scan_scores_one_hundred():
    risk = calculate({"vuln_identification": []})
    assert (risk.score, risk.grade) == (100, "A")


@pytest.mark.parametrize(
    "severity,likelihood,expected",
    [
        # El primer hallazgo aporta su peso íntegro (decay^0 = 1); sobre eso actúa
        # el techo por severidad, que es lo que fija la nota en los casos graves.
        ("critical", "high", 59),    # 100 - 25 = 75, techo critical -> 59
        ("critical", "medium", 59),  # 100 - 17.5 = 82, techo critical -> 59
        ("high", "high", 74),        # 100 - 15 = 85, techo high -> 74
        ("high", "low", 74),         # 100 - 6 = 94, techo high -> 74
        ("medium", "medium", 89),    # 100 - 5.6 = 94, techo medium -> 89
        ("low", "low", 99),          # 100 - 1.2 = 98.8 -> 99, `low` no tiene techo
        ("info", "high", 100),       # info no penaliza
    ],
)
def test_severity_times_likelihood_matches_the_plan(severity, likelihood, expected):
    risk = calculate({"vuln_identification": [_f(severity=severity, likelihood=likelihood)]})
    assert risk.score == expected


def test_a_single_critical_finding_fails_the_target():
    """El techo por severidad existe para esto: el retorno decreciente no puede
    indultar un certificado vencido por ser el único hallazgo del escaneo."""
    assert calculate({"vuln_identification": [_f(severity="critical")]}).grade == "F"


def test_grade_a_requires_a_clean_scan():
    assert calculate({"vuln_identification": []}).grade == "A"
    # Un solo `medium` ya impide la nota máxima.
    assert calculate({"vuln_identification": [_f(severity="medium", likelihood="medium")]}).grade == "B"


@pytest.mark.parametrize(
    "count,expected_score,expected_grade",
    [(1, 74, "C"), (2, 74, "C"), (3, 65, "D"), (5, 54, "F")],
)
def test_grade_degrades_with_accumulated_findings(count, expected_score, expected_grade):
    findings = [_f(f"f{i}", severity="high", likelihood="high") for i in range(count)]
    risk = calculate({"vuln_identification": findings})
    assert (risk.score, risk.grade) == (expected_score, expected_grade)


def test_accumulation_has_diminishing_returns():
    """Cada hallazgo idéntico adicional penaliza menos que el anterior.

    Es la propiedad que impide que una cola larga de hallazgos menores hunda la
    nota igual que un hallazgo grave. Se mide con severidad `low`, la única sin
    techo: con `medium` o peor el techo aplasta las primeras caídas y taparía lo
    que este test comprueba.
    """
    scores = [
        calculate({"m": [_f(f"f{i}", severity="low") for i in range(n)]}).score
        for n in range(1, 6)
    ]
    drops = [a - b for a, b in zip(scores, scores[1:])]
    assert drops == sorted(drops, reverse=True)
    assert all(d >= 0 for d in drops)


def test_many_low_findings_never_reach_failing_grade():
    """Veinte hallazgos `low` no equivalen a uno `critical`."""
    findings = [_f(f"f{i}", severity="low", likelihood="low") for i in range(20)]
    assert calculate({"vuln_identification": findings}).grade in ("A", "B")


def test_grade_d_band():
    """60-69 = D: dos `high` más un `medium` dan 66.

    El `medium` arranca su propia serie (aporta sus 8 puntos íntegros) en vez de
    heredar el decay de los dos `high` que lo preceden, que es lo que antes lo
    dejaba en 4,5 puntos y la nota en 69.
    """
    findings = [
        _f("a", severity="high"), _f("b", severity="high"),
        _f("c", severity="medium", likelihood="high"),
    ]
    risk = calculate({"vuln_identification": findings})
    assert (risk.score, risk.grade) == (66, "D")


def test_decay_is_counted_per_severity_not_globally(monkeypatch):
    """Un hallazgo aporta lo mismo esté solo o detrás de una cola de otra clase.

    Con una sola cuenta global el hallazgo nº 10 valía ya el 7,5% de su peso y el
    nº 20 el 0,2%: quince hallazgos reales sumaban 1 punto entre todos, y "faltan
    las ocho cabeceras" puntuaba casi igual que "falta una". Contando por clase,
    la cola de `low` agota su propia serie sin descontar el `medium`.

    Los techos por severidad se anulan para poder observarlo: con ellos activos el
    score se satura en 89 y el efecto queda invisible — el mismo motivo por el que
    `test_accumulation_has_diminishing_returns` se mide sobre `low`.
    """
    import idata_sentinel.scoring.risk_engine as engine

    weights = {**engine._load_weights(), "severity_caps": {}}
    monkeypatch.setattr(engine, "_load_weights", lambda: weights)

    lows = [_f(f"l{i}", severity="low", likelihood="high") for i in range(10)]
    medium = _f("m", severity="medium", likelihood="high")

    aporte_solo = 100 - calculate({"m": [medium]}).score
    aporte_tras_la_cola = calculate({"m": lows}).score - calculate({"m": [*lows, medium]}).score

    assert aporte_solo == aporte_tras_la_cola == 8


def test_each_severity_class_is_capped_by_its_own_series():
    """`peso / (1 - decay)` = peso × 4 acota cada clase.

    Es lo que impide que la corrección anterior se pase de largo: por muchos
    `low` que se acumulen, entre todos no pueden restar más de 12 puntos.
    """
    muchos_low = [_f(f"l{i}", severity="low", likelihood="high") for i in range(200)]
    assert calculate({"m": muchos_low}).score >= 88


def test_score_never_goes_below_zero():
    findings = [_f(f"f{i}", severity="critical") for i in range(20)]
    assert calculate({"vuln_identification": findings}).score == 0


def test_passing_and_informative_findings_do_not_penalise():
    findings = [
        _f("ok", severity="info", status="pass"),
        _f("nota", severity="critical", status="info"),  # "no evaluable", no es hallazgo
    ]
    assert calculate({"vuln_identification": findings}).score == 100


def test_unverified_findings_do_not_penalise():
    """Un hallazgo que no llegó a medirse no afirma nada del objetivo.

    Es el caso del intersticial anti-bot: no es un problema del cliente, es que
    no se pudo mirar. Penalizarlo convertiría una limitación nuestra en su nota.
    """
    findings = [_f("bloqueado", severity="critical", status="warning", confidence="unverified")]
    assert calculate({"vuln_identification": findings}).score == 100


def test_module_scores_are_independent():
    risk = calculate({
        "vuln_identification": [_f(severity="critical")],
        "asset_inventory": [],
    })
    assert risk.module_scores == {"vuln_identification": 59, "asset_inventory": 100}


def test_category_scores_group_across_modules():
    risk = calculate({
        "vuln_identification": [_f("a", category="TLS/SSL", severity="critical")],
        "asset_inventory": [_f("b", category="DNS y Correo", severity="medium",
                               likelihood="medium", module="asset_inventory")],
    })
    assert risk.category_scores["TLS/SSL"] == 59
    assert risk.category_scores["DNS y Correo"] == 89


def test_global_score_is_never_worse_than_the_worst_module():
    """Regresión: el score global sumaba linealmente las penalizaciones de todos
    los módulos, así que quedaba por debajo de *cada* subscore y empeoraba solo
    por correr más módulos. Todos los escaneos reales daban F."""
    risk = calculate({
        "vuln_identification": [_f("a", severity="high")],
        "data_privacy": [_f("b", severity="high", module="data_privacy")],
    })
    assert risk.score >= min(risk.module_scores.values())


def test_adding_a_clean_module_does_not_lower_the_global_score():
    findings = {"vuln_identification": [_f("a", severity="high"), _f("b", severity="medium")]}
    solo = calculate(findings).score
    with_clean_module = calculate({**findings, "asset_inventory": []}).score
    assert with_clean_module == solo


def test_to_dict_exposes_the_full_breakdown():
    payload = calculate({"vuln_identification": [_f(severity="high")]}).to_dict()
    assert set(payload) == {"score", "grade", "module_scores", "category_scores"}
    assert payload["grade"] == "C"


def test_empty_input_is_a_perfect_score():
    risk = calculate({})
    assert (risk.score, risk.grade, risk.module_scores) == (100, "A", {})
