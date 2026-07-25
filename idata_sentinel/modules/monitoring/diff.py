"""Comparación entre un escaneo y su línea base (plan maestro §6).

Funciones puras: reciben dos listas de hallazgos (y dos mapas de superficie) y
devuelven qué cambió. Sin I/O, para que el diff sea trivialmente testeable.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ACTIONABLE = ("fail", "warning")


def _actionable(findings: list[dict]) -> dict[str, dict]:
    return {f["id"]: f for f in findings if f.get("status") in ACTIONABLE}


@dataclass(frozen=True)
class SeverityChange:
    id: str
    title: str
    before: str
    after: str

    @property
    def worsened(self) -> bool:
        return _SEVERITY_ORDER.get(self.after, 5) < _SEVERITY_ORDER.get(self.before, 5)


@dataclass(frozen=True)
class FindingsDiff:
    new: list[dict] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)
    unchanged: list[dict] = field(default_factory=list)
    severity_changes: list[SeverityChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.resolved or self.severity_changes)

    def to_dict(self) -> dict:
        return {
            "new": [{"id": f["id"], "title": f["title"], "severity": f["severity"]} for f in self.new],
            "resolved": [{"id": f["id"], "title": f["title"], "severity": f["severity"]} for f in self.resolved],
            "unchanged_count": len(self.unchanged),
            "severity_changes": [
                {"id": c.id, "title": c.title, "before": c.before, "after": c.after, "worsened": c.worsened}
                for c in self.severity_changes
            ],
        }


def diff_findings(baseline: list[dict], current: list[dict]) -> FindingsDiff:
    before = _actionable(baseline)
    after = _actionable(current)

    new = [after[i] for i in after if i not in before]
    resolved = [before[i] for i in before if i not in after]
    unchanged = [after[i] for i in after if i in before]

    changes = [
        SeverityChange(
            id=i, title=after[i]["title"], before=before[i]["severity"], after=after[i]["severity"]
        )
        for i in after
        if i in before and before[i]["severity"] != after[i]["severity"]
    ]

    key = lambda f: _SEVERITY_ORDER.get(f["severity"], 5)  # noqa: E731
    return FindingsDiff(
        new=sorted(new, key=key),
        resolved=sorted(resolved, key=key),
        unchanged=unchanged,
        severity_changes=changes,
    )


@dataclass(frozen=True)
class AssetsDiff:
    new_assets: list[str] = field(default_factory=list)
    removed_assets: list[str] = field(default_factory=list)
    technology_changes: dict[str, dict[str, list[str]]] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_assets or self.removed_assets or self.technology_changes)

    def to_dict(self) -> dict:
        return {
            "new_assets": self.new_assets,
            "removed_assets": self.removed_assets,
            "technology_changes": self.technology_changes,
        }


def diff_assets(baseline: dict | None, current: dict | None) -> AssetsDiff:
    """Compara dos mapas de superficie. Un activo nuevo es la señal más valiosa
    del monitoreo: significa superficie de ataque que nadie declaró."""
    if not baseline or not current:
        return AssetsDiff()

    before = {a["host"]: a for a in baseline.get("assets", [])}
    after = {a["host"]: a for a in current.get("assets", [])}

    technology_changes: dict[str, dict[str, list[str]]] = {}
    for host in sorted(set(before) & set(after)):
        old_tech = set(before[host].get("technologies", []))
        new_tech = set(after[host].get("technologies", []))
        if old_tech != new_tech:
            technology_changes[host] = {
                "added": sorted(new_tech - old_tech),
                "removed": sorted(old_tech - new_tech),
            }

    return AssetsDiff(
        new_assets=sorted(set(after) - set(before)),
        removed_assets=sorted(set(before) - set(after)),
        technology_changes=technology_changes,
    )


def build_trend(history: list) -> dict:
    """Serie de score en el tiempo, para el gráfico de evolución del cliente (§6)."""
    points = [{"scanned_at": r.scanned_at, "score": r.score, "grade": r.grade} for r in history]
    scores = [p["score"] for p in points]
    return {
        "points": points,
        "current": scores[-1] if scores else None,
        "previous": scores[-2] if len(scores) > 1 else None,
        "best": max(scores) if scores else None,
        "worst": min(scores) if scores else None,
        "delta": (scores[-1] - scores[-2]) if len(scores) > 1 else 0,
    }
