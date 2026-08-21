"""Motor de riesgo y scoring (plan maestro §7): severidad × probabilidad → score 0-100 + letra."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from idata_sentinel.core.engine import SECURITY, VISIBILITY  # noqa: F401 — reexport

_WEIGHTS_PATH = Path(__file__).resolve().parent / "weights.yaml"


@lru_cache(maxsize=1)
def _load_weights() -> dict:
    return yaml.safe_load(_WEIGHTS_PATH.read_text(encoding="utf-8"))


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


@dataclass
class RiskScore:
    score: int
    grade: str
    module_scores: dict[str, int]
    category_scores: dict[str, int]

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "module_scores": self.module_scores,
            "category_scores": self.category_scores,
        }


def _finding_weight(finding: dict, weights: dict) -> float:
    severity_weight = weights["severity_weights"].get(finding["severity"], 0)
    likelihood_mult = weights["likelihood_multipliers"].get(finding["likelihood"], 0.0)
    return severity_weight * likelihood_mult


def _actionable(findings: list[dict]) -> list[dict]:
    """Hallazgos que penalizan: accionables **y** efectivamente medidos.

    Un resultado `unverified` no afirma nada sobre el objetivo (ver
    `check_base.CheckResult.is_measured`), así que no puede bajar la nota: un
    intersticial anti-bot o un timeout de DNS no son problemas del cliente.
    """
    return [
        f
        for f in findings
        if f["status"] in ("fail", "warning") and f.get("confidence") != "unverified"
    ]


def _severity_cap(actionable: list[dict], weights: dict) -> int:
    caps = weights.get("severity_caps") or {}
    present = {f["severity"] for f in actionable}
    applicable = [cap for severity, cap in caps.items() if severity in present]
    return min(applicable, default=100)


def _score_from_findings(findings: list[dict], weights: dict) -> int:
    actionable = _actionable(findings)
    if not actionable:
        return 100

    decay = weights.get("accumulation_decay", 1.0)

    # El retorno decreciente se cuenta por separado dentro de cada severidad (ver
    # `weights.yaml`): con una única cuenta global la cola larga se evaporaba y
    # "faltan las ocho cabeceras" puntuaba casi igual que "falta una".
    by_severity: dict[str, list[float]] = {}
    for finding in actionable:
        by_severity.setdefault(finding["severity"], []).append(_finding_weight(finding, weights))

    penalty = sum(
        weight * (decay**position)
        for group in by_severity.values()
        for position, weight in enumerate(sorted(group, reverse=True))
    )

    score = max(0, round(100 - penalty))
    return min(score, _severity_cap(actionable, weights))


def modules_for_domain(scan_result: dict, domain: str) -> dict[str, list[dict]]:
    """Hallazgos de un eje de puntuación, con retrocompatibilidad.

    Un escaneo guardado antes de que existieran los ejes no trae
    `modules_by_domain`: todo lo que contiene es de seguridad, que era el único
    eje que había. Devolverlo tal cual mantiene idéntica la nota de todo el
    histórico ya almacenado, que es lo que se consulta desde la app web.
    """
    by_domain = scan_result.get("modules_by_domain")
    if by_domain is None:
        return scan_result.get("modules", {}) if domain == SECURITY else {}
    return by_domain.get(domain, {})


def calculate(results_by_module: dict[str, list[dict]]) -> RiskScore:
    weights = _load_weights()
    all_findings = [f for findings in results_by_module.values() for f in findings]

    module_scores = {
        module: _score_from_findings(findings, weights) for module, findings in results_by_module.items()
    }

    category_findings: dict[str, list[dict]] = {}
    for f in all_findings:
        category_findings.setdefault(f["category"], []).append(f)
    category_scores = {
        category: _score_from_findings(findings, weights) for category, findings in category_findings.items()
    }

    global_score = _score_from_findings(all_findings, weights)
    return RiskScore(
        score=global_score,
        grade=_grade(global_score),
        module_scores=module_scores,
        category_scores=category_scores,
    )
