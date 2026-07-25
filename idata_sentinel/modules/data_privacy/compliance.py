"""Checklist de cumplimiento Ley 21.719 (plan maestro §5).

Traduce hallazgos técnicos de **todos** los módulos a un semáforo por principio.
Deliberadamente no emite un veredicto legal: entrega evidencia priorizada para
que el equipo legal de IDATA la use en el servicio de Datos Personales.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "ley_21719.yaml"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

DISCLAIMER = (
    "Semáforo basado en señales técnicas observables al momento del escaneo. "
    "No constituye una calificación legal de cumplimiento ni sustituye la "
    "asesoría del servicio de Datos Personales de IDATA."
)


@lru_cache(maxsize=1)
def _load_principles() -> list[dict]:
    return yaml.safe_load(_DATA_PATH.read_text(encoding="utf-8")) or []


def base_id(finding_id: str) -> str:
    """'pii_form_insecure_transport@/contacto#form0' -> 'pii_form_insecure_transport'."""
    return finding_id.split("@", 1)[0]


def _status_for(matched: list[dict]) -> str:
    if any(f["status"] == "fail" for f in matched):
        return "brecha"
    if any(f["status"] == "warning" for f in matched):
        return "observacion"
    return "sin_hallazgos"


def build_compliance_checklist(all_findings: list[dict]) -> dict:
    """`all_findings`: hallazgos de todos los módulos, en formato de contrato."""
    by_base: dict[str, list[dict]] = {}
    for finding in all_findings:
        by_base.setdefault(base_id(finding["id"]), []).append(finding)

    principles = []
    for entry in _load_principles():
        matched = [
            f
            for fid in entry.get("findings", [])
            for f in by_base.get(fid, [])
            if f["status"] in ("fail", "warning")
        ]
        matched.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 5))
        principles.append({
            "principle": entry["principle"],
            "label": entry["label"],
            "description": " ".join(entry.get("description", "").split()),
            "status": _status_for(matched),
            "gap_count": len(matched),
            "findings": [
                {"id": f["id"], "title": f["title"], "severity": f["severity"],
                 "recommendation": f["recommendation"]}
                for f in matched
            ],
        })

    gaps = sum(1 for p in principles if p["status"] == "brecha")
    observations = sum(1 for p in principles if p["status"] == "observacion")
    return {
        "principles": principles,
        "totals": {
            "evaluated": len(principles),
            "with_gaps": gaps,
            "with_observations": observations,
            "clean": len(principles) - gaps - observations,
        },
        "disclaimer": DISCLAIMER,
    }
