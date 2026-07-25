"""Detección de CDN, WAF y proveedor cloud por activo (plan maestro §4 — Módulo 2).

Puramente observacional: se leen cabeceras, cookies y el CNAME que el activo ya
publica. No se envían payloads para "provocar" al WAF ni se intenta evadirlo.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Mapping

import yaml

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@lru_cache(maxsize=1)
def _load_signatures() -> list[dict]:
    return yaml.safe_load((_DATA_DIR / "cloud_signatures.yaml").read_text(encoding="utf-8")) or []


@dataclass(frozen=True)
class CloudProfile:
    cdn: tuple[str, ...] = ()
    waf: tuple[str, ...] = ()
    cloud: tuple[str, ...] = ()
    evidence: tuple[str, ...] = field(default=())

    @property
    def is_empty(self) -> bool:
        return not (self.cdn or self.waf or self.cloud)

    def to_dict(self) -> dict:
        return {"cdn": list(self.cdn), "waf": list(self.waf), "cloud": list(self.cloud)}


def _matches(
    signature: dict,
    headers: Mapping[str, str],
    cookie_names: set[str],
    cnames: tuple[str, ...],
) -> str | None:
    """Devuelve la evidencia textual del match, o None."""
    for header in signature.get("headers", []):
        if header.lower() in headers:
            return f"header {header}"

    server = headers.get("server", "").lower()
    for pattern in signature.get("server_patterns", []):
        if pattern.lower() in server:
            return f"Server: {server[:60]}"

    for cookie in signature.get("cookies", []):
        if any(cookie.lower() in name for name in cookie_names):
            return f"cookie {cookie}"

    for suffix in signature.get("cname_suffixes", []):
        for cname in cnames:
            if cname.rstrip(".").lower().endswith(suffix.lower()):
                return f"CNAME {cname.rstrip('.')}"

    return None


def detect_providers(
    headers: Mapping[str, str] | None = None,
    *,
    set_cookies: Iterable[str] = (),
    cnames: tuple[str, ...] = (),
) -> CloudProfile:
    normalized = {k.lower(): v for k, v in (headers or {}).items()}
    cookie_names = {
        raw.split("=", 1)[0].strip().lower() for raw in set_cookies if "=" in raw
    }

    found: dict[str, list[str]] = {"cdn": [], "waf": [], "cloud": []}
    evidence: list[str] = []
    for signature in _load_signatures():
        kind = signature.get("kind", "cloud")
        if kind not in found:
            continue
        hit = _matches(signature, normalized, cookie_names, cnames)
        if hit:
            name = signature["name"]
            if name not in found[kind]:
                found[kind].append(name)
                evidence.append(f"{name}: {hit}")

    return CloudProfile(
        cdn=tuple(found["cdn"]),
        waf=tuple(found["waf"]),
        cloud=tuple(found["cloud"]),
        evidence=tuple(evidence),
    )


_ORIGIN_IP_HEADERS = ("x-real-ip", "x-backend-server", "x-served-by-origin", "x-origin-server")
_PRIVATE_IP = re.compile(r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b")


def leaked_origin(headers: Mapping[str, str] | None = None) -> str | None:
    """Cabeceras de balanceador mal configuradas que revelan la IP interna del
    origen — permite saltarse el CDN/WAF atacando directamente al backend."""
    normalized = {k.lower(): v for k, v in (headers or {}).items()}
    for header in _ORIGIN_IP_HEADERS:
        value = normalized.get(header, "")
        if value and _PRIVATE_IP.search(value):
            return f"{header}: {value}"
    return None
