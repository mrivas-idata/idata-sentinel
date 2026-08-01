"""Métodos HTTP permitidos — check activo (plan_implementacion_escaneo_activo.md §6.1).

Envía un `OPTIONS` a cada ruta declarada y lee la cabecera `Allow`. Reporta
métodos peligrosos **anunciados**: `TRACE`/`TRACK` (Cross-Site Tracing) y métodos
de escritura (`PUT`/`DELETE`/`PATCH`) fuera de una API.

Por qué es NO destructivo: `OPTIONS` es, por definición del RFC 9110, un método
**seguro** cuyo único propósito es *preguntar* qué se permite. Nunca se **invocan**
los métodos peligrosos; solo se lee lo que el servidor **declara**. Nosotros
preguntamos "¿aceptas PUT?"; un ataque **hace** `PUT`. Jamás damos el segundo paso.
"""
from __future__ import annotations

from idata_sentinel.core.baseline import for_context
from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.modules.vuln_identification.context import ScanContext

_DANGEROUS_TRACE = ("TRACE", "TRACK")
_WRITE_METHODS = ("PUT", "DELETE", "PATCH")


def _advertised_methods(resp) -> frozenset[str]:
    """Métodos que el servidor declara en `Allow` (o en la variante CORS)."""
    raw = resp.headers.get("allow") or resp.headers.get("access-control-allow-methods") or ""
    return frozenset(m.strip().upper() for m in raw.split(",") if m.strip())


class HttpMethodsCheck(BaseCheck):
    id = "http_methods"
    category = "Métodos HTTP"
    modes = frozenset({"audit"})
    active = True

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        if not ctx.active_enabled(self):  # defensa en profundidad (§4.5)
            return []

        out: list[CheckResult] = []
        for path in ctx.audit_targets():
            outcome = await ctx.get_outcome(path, method="OPTIONS", authenticated=True)
            if not outcome.ok:
                out.append(self._error_result(
                    sub_id=self._suffixed("http_methods_unreachable", path),
                    reason=f"OPTIONS a {path} no obtuvo respuesta: "
                           f"{outcome.error.value if outcome.error else 'desconocido'}",
                ))
                continue
            resp = outcome.response
            if resp.status_code in (405, 501):
                # El servidor no soporta OPTIONS: no evaluable, no es un hallazgo.
                out.append(self._error_result(
                    sub_id=self._suffixed("http_methods_not_supported", path),
                    reason=f"El servidor respondió {resp.status_code} a OPTIONS en {path}: "
                           f"no declara sus métodos.",
                ))
                continue
            out.extend(self._evaluate(resp, path, ctx))
        return out

    def _suffixed(self, base: str, path: str) -> str:
        return base if path == "/" else f"{base}@{path}"

    def _evaluate(self, resp, path: str, ctx: ScanContext) -> list[CheckResult]:
        methods = _advertised_methods(resp)
        out: list[CheckResult] = []
        evidence = f"Allow: {', '.join(sorted(methods)) or '(vacío)'}"

        trace = methods & frozenset(_DANGEROUS_TRACE)
        if trace:
            out.append(self._result(
                sub_id=self._suffixed("http_trace_enabled", path),
                severity="medium", likelihood="medium", status="fail",
                title="Método TRACE/TRACK habilitado",
                finding=f"El servidor anuncia {', '.join(sorted(trace))} en {path}.",
                business_impact="Habilita Cross-Site Tracing (XST): un atacante puede leer cabeceras "
                                "sensibles como cookies a través de TRACE.",
                recommendation="Deshabilitar TRACE/TRACK en el servidor web.",
                evidence=evidence, references=("CWE-693", "OWASP XST"),
            ))

        write = methods & frozenset(_WRITE_METHODS)
        if write:
            out.append(self._result(
                sub_id=self._suffixed("http_write_methods_advertised", path),
                severity="low", likelihood="low", status="warning",
                title="Métodos de escritura anunciados",
                finding=f"El servidor anuncia {', '.join(sorted(write))} en {path}.",
                business_impact="Si estos métodos no están controlados por autenticación, podrían "
                                "permitir modificar recursos. IDATA Sentinel no los invoca ni lo verifica.",
                recommendation="Confirmar que estos métodos exigen autorización o deshabilitarlos si no se usan.",
                evidence=evidence, references=("CWE-650",),
            ))

        out.extend(self._baseline_mismatch(methods, path, ctx, evidence))
        return out

    def _baseline_mismatch(self, methods, path: str, ctx: ScanContext, evidence: str) -> list[CheckResult]:
        baseline = for_context(ctx)
        if baseline is None:
            return []
        policy = baseline.methods_policy(path)
        if policy is None:
            return []
        extra = methods - policy.allowed
        if not extra:
            return []
        return [self._result(
            sub_id=self._suffixed("methods_baseline_mismatch", path),
            severity=policy.severity, likelihood="medium", status="fail", confidence="confirmed",
            title="Métodos HTTP fuera del baseline acordado",
            finding=(
                f"El baseline v{baseline.version} permite {sorted(policy.allowed)} en {path}; "
                f"el servidor anuncia además {sorted(extra)}."
            ),
            business_impact="La superficie de métodos excede el estándar acordado con el cliente.",
            recommendation=f"Restringir los métodos de {path} a los acordados.",
            evidence=evidence, references=("baseline",),
        )]
