"""CORS por endpoint declarado — check activo (plan_implementacion_escaneo_activo.md §6.2).

Repite el `GET` a cada endpoint declarado añadiendo una cabecera `Origin:` de
prueba y lee `Access-Control-Allow-Origin` (ACAO) y `Access-Control-Allow-Credentials`
(ACAC). Detecta el patrón peligroso: ACAO **refleja** el Origin arbitrario **y**
ACAC=`true` → cualquier sitio puede leer respuestas autenticadas del dominio.

Por qué es NO destructivo: enviar una cabecera `Origin` es lo que hace **cualquier
navegador** en una petición cross-origin legítima. Es una petición HTTP ordinaria
de lectura; no altera estado, no inyecta nada ejecutable, no adivina nada.
Observamos cómo el servidor **decide** su política CORS.

Límite anti-fuzzing: **una sola** petición de sonda por endpoint, con un Origin fijo.
No se enumeran orígenes ni se prueba una lista.
"""
from __future__ import annotations

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.modules.vuln_identification.context import ScanContext

#: Origin de sonda: un dominio de IDATA que el objetivo no debería reconocer. Si
#: lo refleja, su política CORS confía en cualquier origen.
PROBE_ORIGIN = "https://idata-cors-probe.example"


class CorsConfigCheck(BaseCheck):
    id = "cors_config"
    category = "CORS"
    modes = frozenset({"audit"})
    active = True

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        if not ctx.active_enabled(self):
            return []

        out: list[CheckResult] = []
        for path in ctx.audit_targets():
            outcome = await ctx.get_outcome(
                path, headers={"Origin": PROBE_ORIGIN}, authenticated=True,
            )
            if not outcome.ok:
                continue
            out.extend(self._evaluate(outcome.response, path))
        return out

    def _suffixed(self, base: str, path: str) -> str:
        return base if path == "/" else f"{base}@{path}"

    def _evaluate(self, resp, path: str) -> list[CheckResult]:
        acao = resp.headers.get("access-control-allow-origin")
        if not acao:
            return []  # sin CORS habilitado no hay hallazgo
        acac = (resp.headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
        evidence = f"ACAO: {acao}; ACAC: {acac}"

        if acao == PROBE_ORIGIN and acac:
            return [self._result(
                sub_id=self._suffixed("cors_reflects_arbitrary_origin", path),
                severity="high", likelihood="medium", status="fail",
                title="CORS refleja cualquier origen con credenciales",
                finding=(
                    f"En {path}, el servidor reflejó el Origin de prueba en ACAO y permite "
                    f"credenciales (ACAC=true): cualquier sitio puede leer respuestas autenticadas."
                ),
                business_impact="Un sitio malicioso puede leer datos del usuario autenticado "
                                "(robo de información cross-site).",
                recommendation="Restringir ACAO a una allowlist de orígenes; no combinar reflejo con ACAC=true.",
                evidence=evidence, references=("CWE-942", "OWASP CORS"),
            )]
        if acao == "*":
            return [self._result(
                sub_id=self._suffixed("cors_wildcard_origin", path),
                severity="medium", likelihood="medium", status="warning",
                title="CORS abierto a cualquier origen",
                finding=f"En {path}, ACAO es '*': cualquier origen puede leer las respuestas.",
                business_impact="Aceptable para datos públicos; peligroso si el endpoint sirve datos "
                                "sensibles o específicos del usuario.",
                recommendation="Restringir ACAO a los orígenes que realmente necesitan acceso.",
                evidence=evidence, references=("CWE-942",),
            )]
        if acao.strip().lower() == "null":
            return [self._result(
                sub_id=self._suffixed("cors_null_origin_allowed", path),
                severity="medium", likelihood="medium", status="warning",
                title="CORS permite el origen 'null'",
                finding=f"En {path}, ACAO es 'null', que orígenes sandbox pueden falsificar.",
                business_impact="Contextos con Origin 'null' (iframes sandbox, archivos locales) pueden "
                                "acceder a las respuestas.",
                recommendation="No permitir el origen 'null' en la política CORS.",
                evidence=evidence, references=("CWE-942",),
            )]
        return []
