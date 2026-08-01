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

#: Rutas sensibles a comprobar y la firma que confirma que la respuesta ES el
#: archivo, no una página de la app. Un SPA responde 200 con su index.html a
#: cualquier ruta desconocida, así que sin verificar el contenido `/.env`
#: "accesible" es un falso positivo constante (visto en un escaneo real).
_SENSITIVE_FILES = (
    # (ruta, firma que valida el contenido)
    ("/.env", re.compile(r"^\s*(?:[A-Z][A-Z0-9_]*\s*=|#)", re.MULTILINE)),
    ("/.git/HEAD", re.compile(r"^\s*(?:ref:\s|[0-9a-f]{40})")),
    # `/.git/config` es la segunda señal del mismo problema y la que lo confirma:
    # si además de HEAD responde el config, no hay un archivo suelto mal servido
    # sino el directorio `.git` completo publicado. Es ruta canónica conocida,
    # no fuzzing (§2.5).
    ("/.git/config", re.compile(r"^\s*\[(?:core|remote|branch)\b", re.MULTILINE)),
)
_HTML_SIGNATURE = re.compile(r"<(?:!doctype\s+html|html\b|head\b|body\b)", re.IGNORECASE)


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

        for sensitive_path, signature in _SENSITIVE_FILES:
            out.extend(self._check_sensitive_file(await ctx.get_outcome(sensitive_path),
                                                  sensitive_path, signature))
        return out

    def _check_sensitive_file(self, outcome, path: str, signature) -> list[CheckResult]:
        if not outcome.ok or outcome.response.status_code != 200:
            return []
        body = outcome.response.text.strip()
        if not body:
            return []

        # Un catch-all que sirve el index.html a cualquier ruta desconocida NO es
        # una fuga: es lo normal en un SPA. Solo se reporta si el contenido tiene
        # la firma real del archivo esperado.
        if _HTML_SIGNATURE.search(body[:500]) or not signature.search(body):
            return []

        # `critical`, no `medium`: aquí no hay nada que deducir ni explotar
        # después — el archivo ya está publicado y su contenido confirmado. Un
        # `.git` servido permite reconstruir el código fuente y todo el
        # historial, incluidas credenciales que hayan pasado por cualquier
        # commit; un `.env`, las credenciales directamente. `likelihood=high`
        # porque no requiere condiciones: basta con pedir la URL.
        return [self._result(
            sub_id=f"sensitive_file_exposed{path.replace('/', '_')}",
            severity="critical", likelihood="high", status="fail",
            title=f"Archivo sensible accesible: {path}",
            finding=f"{path} responde 200 y su contenido coincide con el del archivo real.",
            business_impact=(
                "Un archivo de configuración o de control de versiones expuesto suele "
                "contener credenciales, claves de API o la estructura interna del proyecto: "
                "es material de ataque directo, sin explotación previa. En el caso de un "
                "repositorio git publicado, el código fuente y su historial completo son "
                "recuperables por cualquiera."
            ),
            recommendation=f"Bloquear el acceso público a {path} en el servidor web.",
            evidence=body[:200], references=("CWE-538",),
        )]

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
