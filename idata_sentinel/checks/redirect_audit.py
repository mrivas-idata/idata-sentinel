"""Auditoría de cadenas de redirección — check activo
(plan_implementacion_escaneo_activo.md §6.4).

Sigue de forma **controlada** (máx. N saltos, sin bucles) la cadena de redirección
de cada endpoint declarado y reporta: downgrade HTTPS→HTTP en algún salto, y saltos
a hosts fuera del scope autorizado.

Por qué NO es destructivo: seguir `Location:` es el comportamiento normal de
cualquier cliente HTTP. **No** se inyectan parámetros de redirección para provocar
un open redirect (eso sería un ataque); solo se observa la cadena que el servidor
produce espontáneamente para la ruta tal cual la declaró el cliente.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.modules.vuln_identification.context import ScanContext

_MAX_HOPS = 10


class RedirectAuditCheck(BaseCheck):
    id = "redirect_audit"
    category = "Redirecciones"
    modes = frozenset({"audit"})
    active = True

    def __init__(self, *, allowed_domains: tuple[str, ...] = ()) -> None:
        # El scope autorizado se inyecta desde el contexto en run(); este default
        # permite instanciar el check sin argumentos (registry).
        self._allowed = allowed_domains

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        if not ctx.active_enabled(self):
            return []

        allowed = self._allowed or self._scope_from_ctx(ctx)
        out: list[CheckResult] = []
        for path in ctx.audit_targets():
            out.extend(await self._trace(ctx, path, allowed))
        return out

    @staticmethod
    def _scope_from_ctx(ctx: ScanContext) -> tuple[str, ...]:
        # Sin allowlist explícita, el scope es el dominio registrable del objetivo:
        # así un salto entre subdominios del mismo dominio no se marca fuera de scope.
        from idata_sentinel.core.domains import registrable_domain

        apex = registrable_domain(ctx.host)
        return (apex,) if apex else (ctx.host,)

    def _suffixed(self, base: str, path: str) -> str:
        return base if path == "/" else f"{base}@{path}"

    async def _trace(self, ctx: ScanContext, path: str, allowed: tuple[str, ...]) -> list[CheckResult]:
        out: list[CheckResult] = []
        current = ctx._absolute_url(path)
        seen: set[str] = set()

        for _ in range(_MAX_HOPS):
            outcome = await ctx.get_outcome(current, follow_redirects=False, authenticated=True)
            if not outcome.ok:
                return out
            resp = outcome.response
            if not (300 <= resp.status_code < 400):
                return out  # fin de la cadena
            location = resp.headers.get("location", "")
            if not location:
                return out
            target = urljoin(current, location)

            if _is_downgrade(current, target):
                out.append(self._result(
                    sub_id=self._suffixed("redirect_downgrade_https", path),
                    severity="high", likelihood="medium", status="fail",
                    title="Redirección degrada HTTPS a HTTP",
                    finding=f"La cadena de {path} salta de HTTPS a HTTP: {current} → {target}",
                    business_impact="El tráfico queda en claro tras el salto: expone datos y sesión.",
                    recommendation="Mantener HTTPS en toda la cadena de redirección.",
                    evidence=f"{current} -> {target}", references=("CWE-319",),
                ))

            if not _in_scope(target, allowed):
                out.append(self._result(
                    sub_id=self._suffixed("redirect_offscope_host", path),
                    severity="low", likelihood="low", status="warning",
                    title="Redirección sale del scope autorizado",
                    finding=f"La cadena de {path} redirige a un host fuera de scope: {target}",
                    business_impact="Un salto a un dominio no autorizado puede indicar dependencia de "
                                    "terceros o un open redirect a investigar.",
                    recommendation="Verificar que el destino de la redirección sea intencional y confiable.",
                    evidence=f"{current} -> {target}", references=("CWE-601",),
                ))
                return out  # fuera de scope: no seguimos la cadena

            if target in seen:
                out.append(self._result(
                    sub_id=self._suffixed("redirect_loop_detected", path),
                    severity="low", likelihood="medium", status="warning",
                    title="Bucle de redirección detectado",
                    finding=f"La cadena de {path} cicla sobre {target}.",
                    business_impact="Una cadena que cicla deja la ruta inaccesible para los usuarios.",
                    recommendation="Corregir la configuración de redirección que provoca el ciclo.",
                    evidence=f"ciclo en {target}", references=(),
                ))
                return out
            seen.add(target)
            current = target

        return out


def _is_downgrade(current: str, target: str) -> bool:
    return urlparse(current).scheme == "https" and urlparse(target).scheme == "http"


def _in_scope(url: str, allowed: tuple[str, ...]) -> bool:
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    return any(host == a.lower().rstrip(".") or host.endswith("." + a.lower().rstrip("."))
               for a in allowed)
