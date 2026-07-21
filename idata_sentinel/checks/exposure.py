"""Exposición de información: errores verbosos, metadatos, formularios sin HTTPS
(plan_implementacion_escaneo_vulnerabilidades.md §2.6)."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.modules.vuln_identification.context import ScanContext

_VERBOSE_ERROR_SIGNATURES = (
    "traceback (most recent call last)",
    "warning: ",
    "fatal error:",
    "at java.",
    "system.exception",
    "sqlstate",
)
_FORM_RE = re.compile(r'<form\b[^>]*\baction\s*=\s*["\']?([^"\'>\s]*)', re.IGNORECASE)
_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)
_SENSITIVE_FILE_PATHS = ("/.env", "/.git/HEAD")


class ExposureCheck(BaseCheck):
    id = "exposure"
    category = "Exposición de información"
    modes = frozenset({"passive", "audit"})

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        out: list[CheckResult] = []
        targets = ctx.audit_targets()
        if ctx.mode == "audit" and ctx.authorized:
            targets = tuple(dict.fromkeys((*targets, *ctx.audit_endpoints)))

        for path in targets:
            outcome = await ctx.get_outcome(path)
            if not outcome.ok:
                continue
            resp = outcome.response
            body = resp.text
            out.extend(self._check_verbose_errors(body, path))
            out.extend(self._check_metadata(body, resp.headers, path))
            out.extend(self._check_insecure_forms(body, resp, path))

        for sensitive_path in _SENSITIVE_FILE_PATHS:
            outcome = await ctx.get_outcome(sensitive_path)
            if outcome.ok and outcome.response.status_code == 200 and outcome.response.text.strip():
                out.append(self._result(
                    sub_id=f"metadata_exposed{sensitive_path.replace('/', '_')}",
                    severity="low", likelihood="low", status="warning",
                    title=f"Archivo sensible accesible: {sensitive_path}",
                    finding=f"{sensitive_path} responde 200 con contenido.",
                    business_impact="Posible fuga de configuración/metadatos internos.",
                    recommendation=f"Restringir el acceso público a {sensitive_path}.",
                    evidence=outcome.response.text[:200], references=("CWE-538",),
                ))
        return out

    def _check_verbose_errors(self, body: str, path: str) -> list[CheckResult]:
        body_lower = body.lower()
        for sig in _VERBOSE_ERROR_SIGNATURES:
            if sig in body_lower:
                return [self._result(
                    sub_id=f"verbose_error_exposed@{path}", severity="medium", likelihood="medium",
                    status="fail", title=f"Error verboso expuesto en {path}",
                    finding=f"La respuesta contiene una firma de error/stack trace ('{sig}').",
                    business_impact="Fuga de detalles internos (rutas, stack, framework) útiles para un atacante.",
                    recommendation="Deshabilitar modo debug/verbose en producción; páginas de error genéricas.",
                    evidence=body[:500], references=("CWE-209",),
                )]
        return []

    def _check_metadata(self, body: str, headers, path: str) -> list[CheckResult]:
        out: list[CheckResult] = []
        if headers.get("x-debug"):
            out.append(self._result(
                sub_id=f"metadata_exposed_xdebug@{path}", severity="low", likelihood="low", status="warning",
                title=f"Header de debug presente en {path}", finding=f"X-Debug: {headers.get('x-debug')}",
                business_impact="Señal de que el entorno puede estar en modo debug.",
                recommendation="Deshabilitar headers/output de debug en producción.",
                evidence=headers.get("x-debug", ""), references=("CWE-489",),
            ))
        match = _GENERATOR_RE.search(body)
        if match:
            out.append(self._result(
                sub_id=f"metadata_exposed_generator@{path}", severity="low", likelihood="low", status="warning",
                title=f"Meta generator expone plataforma en {path}", finding=f"generator: {match.group(1)}",
                business_impact="Facilita reconocimiento de tecnología/versión.",
                recommendation="Eliminar la meta tag generator en producción.",
                evidence=match.group(0)[:200], references=("CWE-200",),
            ))
        return out

    def _check_insecure_forms(self, body: str, resp, path: str) -> list[CheckResult]:
        out: list[CheckResult] = []
        for match in _FORM_RE.finditer(body):
            action = match.group(1) or ""
            absolute = urljoin(str(resp.url), action)
            if urlparse(absolute).scheme == "http":
                out.append(self._result(
                    sub_id=f"form_insecure_transport@{path}", severity="high", likelihood="high",
                    status="fail", title=f"Formulario envía datos sin HTTPS en {path}",
                    finding=f"<form action='{action}'> resuelve a un endpoint HTTP: {absolute}",
                    business_impact="Credenciales/datos capturados viajan en texto claro.",
                    recommendation="Servir el formulario y su action exclusivamente sobre HTTPS.",
                    evidence=match.group(0)[:300], references=("CWE-319",),
                ))
        return out
