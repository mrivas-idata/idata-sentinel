"""Feed de CVE: sincroniza `data/cve_hints.yaml` desde una fuente pública (OSV.dev).

El escaneo sigue siendo 100% offline: NUNCA consulta la red en tiempo de escaneo
(plan §2.4). Este módulo es una herramienta de *mantenimiento* que se corre aparte
(`idata-sentinel cve-sync`, o un cron) para poblar la base local con CVEs reales,
de modo que el fingerprinting de stack y de librerías JS deje de apoyarse en
entradas placeholder.

Fuente: OSV.dev — base agregada, gratuita y sin API key, con excelente cobertura
del ecosistema npm (las librerías JS que detecta `checks/javascript.py`). Otros
ecosistemas se pueden sumar a `OSV_PRODUCTS`.

Diseño clave: las entradas curadas a mano por el equipo de IDATA se **preservan**;
solo se refrescan las que este feed generó (marcadas con `source: osv`). Así el
sync nunca pisa el trabajo manual.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import httpx
import yaml

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_CVE_HINTS_PATH = _DATA_DIR / "cve_hints.yaml"

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

#: (slug local, ecosistema OSV, nombre de paquete). El slug debe coincidir con el
#: que emiten los checks (`checks/javascript.py` → jquery, bootstrap, …).
OSV_PRODUCTS: tuple[tuple[str, str, str], ...] = (
    ("jquery", "npm", "jquery"),
    ("jquery-ui", "npm", "jquery-ui"),
    ("bootstrap", "npm", "bootstrap"),
    ("angular", "npm", "angular"),
    ("vue", "npm", "vue"),
    ("react", "npm", "react"),
    ("lodash", "npm", "lodash"),
    ("moment", "npm", "moment"),
    ("dompurify", "npm", "dompurify"),
)

_HEADER = """# Base local, offline, de CVEs — SOLO informativa.
# IDATA Sentinel NUNCA verifica explotabilidad; esto solo cruza versión detectada
# contra rangos conocidos como referencia para el cliente.
#
# `product` admite el nombre del stack ("WordPress", "Apache") o el *slug* de un
# plugin/tema WordPress o de una librería JS ("revslider", "jquery"). La
# coincidencia no distingue mayúsculas.
#
# Entradas con `source: osv` las genera `idata-sentinel cve-sync` desde OSV.dev y
# se refrescan en cada sync. Las entradas SIN `source` (o `source: manual`) las
# cura el equipo de IDATA y el sync NO las toca.
#
# rango de versión: [min_version, max_version) — max_version null = sin tope conocido.
"""

_SEVERITY_WORDS = {"critical", "high", "medium", "moderate", "low"}


@dataclass(frozen=True)
class SyncResult:
    products_queried: int
    products_failed: list[str]
    entries_from_feed: int
    entries_preserved: int


async def _default_fetch(ecosystem: str, package: str) -> list[dict]:
    payload = {"package": {"name": package, "ecosystem": ecosystem}}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(OSV_QUERY_URL, json=payload)
        resp.raise_for_status()
        return resp.json().get("vulns", []) or []


def _version_from_events(events: list[dict], key: str) -> str | None:
    for event in events:
        if key in event:
            return str(event[key])
    return None


def _cve_ids(vuln: dict) -> list[str]:
    ids = [vuln.get("id", "")] + list(vuln.get("aliases", []))
    # Preferir CVE-… al frente; conservar GHSA como respaldo.
    cves = [i for i in ids if i.upper().startswith("CVE-")]
    others = [i for i in ids if i and not i.upper().startswith("CVE-")]
    return list(dict.fromkeys([*cves, *others]))


def _severity_label(vuln: dict) -> str:
    db = vuln.get("database_specific") or {}
    raw = str(db.get("severity", "")).lower()
    if raw in _SEVERITY_WORDS:
        return "medium" if raw == "moderate" else raw
    # Fallback: puntaje base CVSS numérico si viniera explícito.
    for sev in vuln.get("severity", []) or []:
        score = str(sev.get("score", ""))
        m = re.search(r"\b(\d+\.\d+)\b", score)
        if m:
            v = float(m.group(1))
            return "critical" if v >= 9 else "high" if v >= 7 else "medium" if v >= 4 else "low"
    return "medium"


def osv_vuln_to_hint(slug: str, vuln: dict) -> dict | None:
    """Transforma una vuln de OSV en una entrada de `cve_hints.yaml`, o `None` si
    no trae un rango de versión utilizable."""
    cve_ids = _cve_ids(vuln)
    if not cve_ids:
        return None
    min_v, max_v = "0", None
    for affected in vuln.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            events = rng.get("events", []) or []
            introduced = _version_from_events(events, "introduced")
            fixed = _version_from_events(events, "fixed")
            if fixed:  # solo sirve el rango si sabemos hasta dónde llega
                min_v = introduced if introduced and introduced != "0" else "0"
                max_v = fixed
                break
        if max_v is not None:
            break
    if max_v is None:
        return None
    title = (vuln.get("summary") or vuln.get("details") or "Vulnerabilidad conocida")[:200]
    return {
        "product": slug,
        "min_version": str(min_v),
        "max_version": str(max_v),
        "cve_ids": cve_ids,
        "title": title,
        "cvss_severity": _severity_label(vuln),
        "source": "osv",
    }


def _load_existing(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return yaml.safe_load(path.read_text(encoding="utf-8")) or []


async def sync_cve_hints(
    *, path: Path = _CVE_HINTS_PATH, products=OSV_PRODUCTS, fetch=_default_fetch,
) -> SyncResult:
    """Refresca las entradas `source: osv` desde OSV, preservando las manuales."""
    existing = _load_existing(path)
    preserved = [e for e in existing if str(e.get("source", "")).lower() != "osv"]

    feed_entries: list[dict] = []
    failed: list[str] = []
    for slug, ecosystem, package in products:
        try:
            vulns = await fetch(ecosystem, package)
        except Exception:  # una fuente caída no aborta el sync completo
            failed.append(slug)
            continue
        for vuln in vulns:
            hint = osv_vuln_to_hint(slug, vuln)
            if hint is not None:
                feed_entries.append(hint)

    _write(path, preserved + feed_entries)
    return SyncResult(
        products_queried=len(products),
        products_failed=failed,
        entries_from_feed=len(feed_entries),
        entries_preserved=len(preserved),
    )


def _write(path: Path, entries: list[dict]) -> None:
    body = yaml.safe_dump(entries, allow_unicode=True, sort_keys=False, default_flow_style=False)
    path.write_text(_HEADER + "\n" + body, encoding="utf-8")
