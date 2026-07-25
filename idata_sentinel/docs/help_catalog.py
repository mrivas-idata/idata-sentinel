"""Catálogo de ayuda por módulo (data/module_help.yaml).

Fuente única para la CLI, la app web y el reporte: si la ayuda vive en un solo
lugar, las tres interfaces no pueden contradecirse.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

_HELP_PATH = Path(__file__).resolve().parent.parent / "data" / "module_help.yaml"


@dataclass(frozen=True)
class ModuleHelp:
    key: str
    alias: str
    label: str
    phase: str
    tagline: str
    purpose: str
    what_it_does: tuple[str, ...]
    key_findings: tuple[str, ...]
    legal: str
    examples: tuple[str, ...]
    report_section: str

    def to_dict(self) -> dict:
        return {
            "key": self.key, "alias": self.alias, "label": self.label, "phase": self.phase,
            "tagline": self.tagline, "purpose": self.purpose,
            "what_it_does": list(self.what_it_does), "key_findings": list(self.key_findings),
            "legal": self.legal, "examples": list(self.examples),
            "report_section": self.report_section,
        }


def _collapse(text: str) -> str:
    return " ".join((text or "").split())


@lru_cache(maxsize=1)
def all_modules() -> tuple[ModuleHelp, ...]:
    raw = yaml.safe_load(_HELP_PATH.read_text(encoding="utf-8")) or []
    return tuple(
        ModuleHelp(
            key=entry["key"],
            alias=entry.get("alias", entry["key"]),
            label=entry["label"],
            phase=entry.get("phase", ""),
            tagline=_collapse(entry.get("tagline", "")),
            purpose=_collapse(entry.get("purpose", "")),
            what_it_does=tuple(entry.get("what_it_does", ())),
            key_findings=tuple(entry.get("key_findings", ())),
            legal=_collapse(entry.get("legal", "")),
            examples=tuple(entry.get("examples", ())),
            report_section=entry.get("report_section", ""),
        )
        for entry in raw
    )


def resolve_key(name: str) -> str | None:
    """Acepta el nombre interno o el alias corto de la CLI."""
    name = (name or "").strip().lower()
    for module in all_modules():
        if name in (module.key, module.alias):
            return module.key
    return None


def module_help(name: str) -> ModuleHelp | None:
    key = resolve_key(name)
    return next((m for m in all_modules() if m.key == key), None) if key else None
