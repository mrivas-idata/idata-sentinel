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

#: OSV.dev NO cubre WordPress ni sus plugins; para eso se usa wpvulnerability.net,
#: base gratuita y sin API key con datos de core, plugins y temas de WordPress.
WPVULN_BASE = "https://www.wpvulnerability.net"

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

#: (slug local, tipo). El slug del plugin debe coincidir con el que emite el
#: fingerprint de componentes WordPress (`checks/tech_fingerprint.py`). `core` se
#: guarda bajo el producto "wordpress" (la coincidencia es case-insensitive).
WP_PRODUCTS: tuple[tuple[str, str], ...] = (
    ("wordpress", "core"),
    ("contact-form-7", "plugin"),
    ("uncode-privacy", "plugin"),
    ("country-phone-field-contact-form-7", "plugin"),
    ("elementor", "plugin"),
    ("woocommerce", "plugin"),
    ("wordpress-seo", "plugin"),  # Yoast SEO
    ("akismet", "plugin"),
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


async def _default_wpvuln_fetch(kind: str, slug: str) -> list[dict]:
    """Vulnerabilidades de WordPress core o de un plugin/tema desde
    wpvulnerability.net. Devuelve la lista `data.vulnerability` (o vacía)."""
    path = "/core" if kind == "core" else f"/{kind}/{slug}"
    headers = {"User-Agent": "IDATA-Sentinel/1.0 (+https://idatachile.com)"}
    async with httpx.AsyncClient(timeout=45.0, headers=headers) as client:
        resp = await client.get(f"{WPVULN_BASE}{path}")
        resp.raise_for_status()
        data = (resp.json() or {}).get("data") or {}
        return data.get("vulnerability") or []


def _wpvuln_severity(vuln: dict) -> str:
    impact = (vuln.get("impact") or {}).get("cvss") or {}
    score = impact.get("score")
    if isinstance(score, (int, float)):
        return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    vector = str(impact.get("vector") or "")
    # Sin puntaje explícito: alto si compromete confidencialidad o integridad.
    if "C:H" in vector or "I:H" in vector:
        return "high"
    return "medium"


def wpvuln_to_hint(slug: str, vuln: dict) -> dict | None:
    """Transforma una vuln de wpvulnerability.net en una entrada de cve_hints.

    Solo se conservan las que tienen un CVE real (el pedido es "CVEs reales"). El
    rango se toma del `operator`; el borde `le`/`ge` se trata como exclusivo, un
    sub-reporte conservador que nunca sobre-afirma sobre la versión límite.
    """
    op = vuln.get("operator") or {}
    max_version = op.get("max_version")
    if not max_version:
        return None
    cve_ids = [s.get("id") for s in (vuln.get("source") or [])
               if str(s.get("id", "")).upper().startswith("CVE-")]
    if not cve_ids:
        return None
    min_version = op.get("min_version") or "0"
    return {
        "product": slug,
        "min_version": str(min_version),
        "max_version": str(max_version),
        "cve_ids": cve_ids,
        "title": (vuln.get("name") or "Vulnerabilidad conocida")[:200],
        "cvss_severity": _wpvuln_severity(vuln),
        "source": "wpvulnerability",
    }


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


#: Etiquetas de `source` que gestiona el feed (se refrescan en cada sync). Las
#: entradas sin `source` (curadas a mano) NUNCA se tocan.
_FEED_SOURCES = frozenset({"osv", "wpvulnerability"})


async def sync_cve_hints(
    *,
    path: Path = _CVE_HINTS_PATH,
    products=OSV_PRODUCTS,
    fetch=_default_fetch,
    wp_products=WP_PRODUCTS,
    wpvuln_fetch=_default_wpvuln_fetch,
) -> SyncResult:
    """Refresca las entradas del feed (OSV para npm, wpvulnerability para
    WordPress), preservando las curadas a mano."""
    existing = _load_existing(path)
    preserved = [e for e in existing if str(e.get("source", "")).lower() not in _FEED_SOURCES]

    feed_entries: list[dict] = []
    failed: list[str] = []

    for slug, ecosystem, package in products:
        try:
            vulns = await fetch(ecosystem, package)
        except Exception:  # una fuente caída no aborta el sync completo
            failed.append(slug)
            continue
        feed_entries.extend(h for h in (osv_vuln_to_hint(slug, v) for v in vulns) if h)

    for slug, kind in wp_products:
        try:
            vulns = await wpvuln_fetch(kind, slug)
        except Exception:
            failed.append(slug)
            continue
        feed_entries.extend(h for h in (wpvuln_to_hint(slug, v) for v in vulns) if h)

    _write(path, preserved + feed_entries)
    return SyncResult(
        products_queried=len(products) + len(wp_products),
        products_failed=failed,
        entries_from_feed=len(feed_entries),
        entries_preserved=len(preserved),
    )


def _write(path: Path, entries: list[dict]) -> None:
    body = yaml.safe_dump(entries, allow_unicode=True, sort_keys=False, default_flow_style=False)
    path.write_text(_HEADER + "\n" + body, encoding="utf-8")
