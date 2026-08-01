"""Comparación contra el baseline de hardening acordado con el cliente
(plan_implementacion_escaneo_activo.md §5).

Un hallazgo pasivo dice "falta HSTS". Un hallazgo de baseline dice "el cliente
**acordó** HSTS con `max-age≥63072000` en `/checkout`, y el servidor entrega
`max-age=300`". El segundo es más accionable: compara contra un compromiso
concreto, no contra una buena práctica genérica.

Hasta ahora `ScanContext.hardening_baseline` se pasaba pero **ningún check lo
leía**. Este módulo lo convierte en un comparador real. Es una función pura,
separada del I/O: se testea sin red, igual que la evaluación de TLS.

`must_match` es una regex de **validación** sobre el valor ya recibido, nunca de
ataque: no genera tráfico ni induce comportamiento en el objetivo.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from idata_sentinel.core.check_base import Severity

MismatchKind = Literal["missing", "value"]


class BaselineError(ValueError):
    """El baseline no se pudo interpretar. Se trata como 'no evaluable', nunca se
    inventan mismatches a partir de un baseline roto."""


@dataclass(frozen=True)
class BaselineRule:
    key: str
    required: bool
    must_match: re.Pattern | None
    severity: Severity

    def describe(self) -> str:
        if self.must_match is not None:
            return f"{self.key} con valor que cumpla /{self.must_match.pattern}/"
        return f"{self.key} presente"


@dataclass(frozen=True)
class Mismatch:
    key: str
    expected: BaselineRule
    got: str | None
    kind: MismatchKind


@dataclass(frozen=True)
class CookiePolicy:
    require_secure: bool
    require_httponly: bool
    require_samesite: bool
    severity: Severity


@dataclass(frozen=True)
class MethodsPolicy:
    allowed: frozenset[str]
    severity: Severity


_VALID_SEVERITY = {"info", "low", "medium", "high", "critical"}


def _severity(raw, default: Severity = "medium") -> Severity:
    value = str(raw or default).lower()
    if value not in _VALID_SEVERITY:
        raise BaselineError(f"Severidad inválida en baseline: {raw!r}")
    return value  # type: ignore[return-value]


@dataclass(frozen=True)
class HardeningBaseline:
    version: int
    _defaults: dict
    _paths: dict

    @classmethod
    def load(cls, raw: dict) -> "HardeningBaseline":
        if not isinstance(raw, dict):
            raise BaselineError("El baseline debe ser un objeto.")
        version = raw.get("version", 1)
        if not isinstance(version, int):
            raise BaselineError("El campo 'version' del baseline debe ser entero.")
        defaults = raw.get("defaults") or {}
        paths = raw.get("paths") or {}
        if not isinstance(defaults, dict) or not isinstance(paths, dict):
            raise BaselineError("Las secciones 'defaults' y 'paths' deben ser objetos.")
        # Se compila todo al cargar para fallar temprano ante una regex inválida,
        # no a mitad del escaneo.
        obj = cls(version=version, _defaults=defaults, _paths=paths)
        for path in (None, *paths.keys()):
            obj.header_rules(path or "/")
        return obj

    def _section(self, path: str, section: str) -> dict:
        """Fusión superficial por clave: la sección de la ruta gana sobre defaults."""
        base = dict((self._defaults.get(section) or {}))
        override = ((self._paths.get(path) or {}).get(section)) or {}
        base.update(override)
        return base

    def has_path(self, path: str) -> bool:
        return path in self._paths

    def header_rules(self, path: str) -> dict[str, BaselineRule]:
        out: dict[str, BaselineRule] = {}
        for key, spec in self._section(path, "headers").items():
            if not isinstance(spec, dict):
                raise BaselineError(f"Regla de cabecera inválida para {key!r}.")
            pattern = spec.get("must_match")
            try:
                compiled = re.compile(pattern, re.IGNORECASE) if pattern else None
            except re.error as e:
                raise BaselineError(f"Regex inválida en baseline para {key!r}: {e}") from e
            out[key.lower()] = BaselineRule(
                key=key.lower(),
                required=bool(spec.get("required", True)),
                must_match=compiled,
                severity=_severity(spec.get("severity")),
            )
        return out

    def cookie_policy(self, path: str) -> CookiePolicy | None:
        spec = self._section(path, "cookies")
        if not spec:
            return None
        return CookiePolicy(
            require_secure=bool(spec.get("require_secure", False)),
            require_httponly=bool(spec.get("require_httponly", False)),
            require_samesite=bool(spec.get("require_samesite", False)),
            severity=_severity(spec.get("severity")),
        )

    def tls_min_version(self, path: str = "/") -> tuple[str, Severity] | None:
        spec = self._section(path, "tls")
        if not spec or "min_version" not in spec:
            return None
        return str(spec["min_version"]), _severity(spec.get("severity"))

    def methods_policy(self, path: str) -> MethodsPolicy | None:
        spec = self._section(path, "methods")
        if not spec or "allowed" not in spec:
            return None
        return MethodsPolicy(
            allowed=frozenset(m.upper() for m in spec["allowed"]),
            severity=_severity(spec.get("severity")),
        )


def for_context(ctx) -> HardeningBaseline | None:
    """Baseline ya compilado y cacheado en el contexto por el runner del módulo,
    o `None` si el cliente no entregó baseline (o era inválido)."""
    return getattr(ctx, "_compiled_baseline", None)


def redact_value(value: str | None, limit: int = 200) -> str:
    """Trunca el valor observado para la evidencia. Un `Set-Cookie` u otra
    cabecera puede arrastrar material sensible; nunca se vuelca completo."""
    if value is None:
        return ""
    return value[:limit]


def compare_headers(observed: Mapping[str, str], rules: dict[str, BaselineRule]) -> list[Mismatch]:
    """Desviaciones de las cabeceras observadas respecto del baseline. Solo lee
    los valores ya recibidos; no genera tráfico."""
    out: list[Mismatch] = []
    lowered = {k.lower(): v for k, v in observed.items()}
    for key, rule in rules.items():
        value = lowered.get(key)
        if value is None:
            if rule.required:
                out.append(Mismatch(key, rule, got=None, kind="missing"))
        elif rule.must_match is not None and not rule.must_match.search(value):
            out.append(Mismatch(key, rule, got=value, kind="value"))
    return out
