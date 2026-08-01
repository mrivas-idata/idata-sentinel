"""Endpoints sensibles exigen autenticación — check activo
(plan_implementacion_escaneo_activo.md §6.3).

Para cada endpoint que **el cliente declaró** como sensible/autenticado
(`ctx.audit_endpoints`), hace **una** petición `GET` **sin credenciales** y
verifica que el servidor responde `401`/`403` (o redirige a login). Si responde
`200` con contenido de aplicación real, emite un hallazgo: un recurso que debía
estar protegido es accesible sin autenticación.

Por qué NO es un ataque: **no adivinamos ni probamos credenciales** — hacemos
exactamente lo contrario: comprobamos que **sin** credenciales el recurso está
cerrado. Es la verificación de un control, no su vulneración. Solo actuamos sobre
endpoints que **el dueño listó**; jamás los descubrimos por diccionario.
"""
from __future__ import annotations

import re

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.modules.vuln_identification.context import ScanContext

#: Un SPA responde 200 con su index.html a rutas desconocidas: eso NO es un fallo
#: de auth. Se exige que el 200 traiga contenido de aplicación real (no el shell).
_HTML_SHELL = re.compile(r"<(?:!doctype\s+html|html\b|head\b|body\b)", re.IGNORECASE)
_LOGIN_HINT = re.compile(r"log[- ]?in|iniciar sesi|acceder|/login|/signin|/auth", re.IGNORECASE)


class AuthEnforcementCheck(BaseCheck):
    id = "auth_enforcement"
    category = "Control de acceso"
    modes = frozenset({"audit"})
    active = True

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        if not ctx.active_enabled(self):
            return []
        # Solo endpoints declarados por el cliente: nunca se descubren.
        if not (ctx.mode == "audit" and ctx.authorized and ctx.audit_endpoints):
            return []

        out: list[CheckResult] = []
        for endpoint in ctx.audit_endpoints:
            # Petición ANÓNIMA a propósito (authenticated=False): verificamos el cierre.
            outcome = await ctx.get_outcome(endpoint, follow_redirects=False, authenticated=False)
            if not outcome.ok:
                out.append(self._error_result(
                    sub_id=f"auth_enforcement_unreachable@{endpoint}",
                    reason=f"{endpoint} no respondió: "
                           f"{outcome.error.value if outcome.error else 'desconocido'}",
                ))
                continue
            out.append(self._evaluate(outcome.response, endpoint))
        return out

    def _evaluate(self, resp, endpoint: str) -> CheckResult:
        status = resp.status_code
        location = resp.headers.get("location", "")

        # Cierre correcto: 401/403, o redirect a login.
        if status in (401, 403) or (300 <= status < 400 and _LOGIN_HINT.search(location)):
            return self._result(
                sub_id=f"sensitive_endpoint_auth_ok@{endpoint}",
                severity="info", likelihood="low", status="info",
                title=f"Endpoint sensible protegido: {endpoint}",
                finding=f"{endpoint} responde {status} sin credenciales: el control de acceso está activo.",
                business_impact="Evidencia positiva: el recurso exige autenticación.",
                recommendation="Sin acción.", evidence=f"status={status}", references=(),
            )

        body = resp.text if 200 <= status < 300 else ""
        looks_like_shell = bool(_HTML_SHELL.search(body[:500])) if body else False
        if 200 <= status < 300 and not looks_like_shell and body.strip():
            return self._result(
                sub_id=f"sensitive_endpoint_no_auth@{endpoint}",
                severity="high", likelihood="medium", status="fail",
                title=f"Endpoint sensible accesible sin autenticación: {endpoint}",
                finding=(
                    f"{endpoint}, declarado sensible por el cliente, responde {status} con contenido "
                    f"de aplicación a una petición sin credenciales."
                ),
                business_impact="Un recurso que debía exigir login es accesible por cualquiera: "
                                "posible exposición de datos o funciones privadas.",
                recommendation="Exigir autenticación en este endpoint antes de servir contenido.",
                evidence=f"status={status}, {len(body)} bytes de contenido no-shell",
                references=("CWE-306", "OWASP A01"),
            )

        # 200 con shell de SPA, u otras respuestas: no concluyente.
        return self._error_result(
            sub_id=f"auth_enforcement_inconclusive@{endpoint}",
            reason=(
                f"{endpoint} respondió {status}"
                + (" con el shell de un SPA" if looks_like_shell else "")
                + ": no se puede afirmar si el control de acceso falla."
            ),
            evidence=f"status={status}",
        )
