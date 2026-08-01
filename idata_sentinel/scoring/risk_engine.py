"""Motor de riesgo y scoring (plan maestro §7): severidad × probabilidad → score 0-100 + letra."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

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
    ordered = sorted((_finding_weight(f, weights) for f in actionable), reverse=True)
    penalty = sum(weight * (decay**position) for position, weight in enumerate(ordered))

    score = max(0, round(100 - penalty))
    return min(score, _severity_cap(actionable, weights))


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
