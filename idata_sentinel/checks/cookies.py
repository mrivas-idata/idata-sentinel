"""Flags de cookies (plan_implementacion_escaneo_vulnerabilidades.md §2.3)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.modules.vuln_identification.context import ScanContext

_NAME_RE = re.compile(r"^\s*([^=;]+)=")


@dataclass
class _ParsedCookie:
    name: str
    flags: set[str]
    attrs: dict[str, str]


def _parse_setcookie(raw: str) -> _ParsedCookie:
    name_match = _NAME_RE.match(raw)
    name = name_match.group(1).strip() if name_match else raw.strip()
    parts = raw.split(";")[1:]
    flags: set[str] = set()
    attrs: dict[str, str] = {}
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, value = part.partition("=")
            attrs[key.strip().lower()] = value.strip().lower()
        else:
            flags.add(part.lower())
    return _ParsedCookie(name=name, flags=flags, attrs=attrs)


class CookiesCheck(BaseCheck):
    id = "cookies"
    category = "Cookies"
    modes = frozenset({"passive", "audit"})

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        out: list[CheckResult] = []
        # Rutas públicas: petición anónima. Endpoints declarados por el cliente:
        # petición con la sesión provista (§6.5) para ver las cookies de sesión
        # reales —las de mayor impacto—. Sin sesión, `authenticated=True` es inocuo.
        anon_targets = ctx.audit_targets()
        auth_targets: tuple[str, ...] = ()
        if ctx.mode == "audit" and ctx.authorized:
            auth_targets = tuple(e for e in ctx.audit_endpoints if e not in anon_targets)

        for path, authenticated in (
            *((p, False) for p in anon_targets),
            *((p, True) for p in auth_targets),
        ):
            outcome = await ctx.get_outcome(path, authenticated=authenticated)
            if not outcome.ok:
                continue
            for raw in outcome.response.headers.get_list("set-cookie"):
                cookie = _parse_setcookie(raw)
                out.extend(self._evaluate(cookie, path, outcome.response.url.scheme))
                out.extend(self._baseline_mismatch(cookie, path, ctx))
        return out

    def _baseline_mismatch(self, cookie: _ParsedCookie, path: str, ctx: ScanContext) -> list[CheckResult]:
        """Compara los flags de la cookie contra la política de cookies acordada
        en el baseline (plan activo §5). Severidad heredada del baseline."""
        from idata_sentinel.core.baseline import for_context

        baseline = for_context(ctx)
        if baseline is None:
            return []
        policy = baseline.cookie_policy(path)
        if policy is None:
            return []
        missing: list[str] = []
        if policy.require_secure and "secure" not in cookie.flags:
            missing.append("Secure")
        if policy.require_httponly and "httponly" not in cookie.flags:
            missing.append("HttpOnly")
        if policy.require_samesite and "samesite" not in cookie.attrs:
            missing.append("SameSite")
        if not missing:
            return []
        suffix = f"@{cookie.name}" if path == "/" else f"@{cookie.name}{path}"
        return [self._result(
            sub_id=f"cookie_baseline_mismatch{suffix}",
            severity=policy.severity, likelihood="medium", status="fail", confidence="confirmed",
            title=f"Cookie '{cookie.name}' fuera del baseline acordado",
            finding=(
                f"El baseline v{baseline.version} exige {', '.join(missing)} en las cookies de "
                f"{path}; la cookie '{cookie.name}' no lo cumple."
            ),
            business_impact="Las cookies no cumplen el estándar de hardening comprometido con el cliente.",
            recommendation=f"Agregar {', '.join(missing)} a la cookie '{cookie.name}'.",
            evidence=cookie.name, references=("baseline",),
        )]

    def _evaluate(self, cookie: _ParsedCookie, path: str, scheme: str) -> list[CheckResult]:
        out: list[CheckResult] = []
        suffix = f"@{cookie.name}" if path == "/" else f"@{cookie.name}{path}"

        if scheme == "https" and "secure" not in cookie.flags:
            out.append(self._result(
                sub_id=f"cookie_insecure{suffix}", severity="medium", likelihood="high", status="fail",
                title=f"Cookie '{cookie.name}' sin flag Secure",
                finding=f"La cookie '{cookie.name}' no tiene el flag Secure en un sitio HTTPS.",
                business_impact="La cookie puede viajar en claro si ocurre un downgrade a HTTP.",
                recommendation="Agregar el flag Secure a la cookie.",
                evidence=cookie.name, references=("OWASP Secure Cookie", "CWE-614"),
            ))

        if "httponly" not in cookie.flags:
            out.append(self._result(
                sub_id=f"cookie_no_httponly{suffix}", severity="medium", likelihood="medium", status="fail",
                title=f"Cookie '{cookie.name}' sin flag HttpOnly",
                finding=f"La cookie '{cookie.name}' es accesible desde JavaScript (sin HttpOnly).",
                business_impact="Robo de cookie vía XSS si existiera una vulnerabilidad de ese tipo.",
                recommendation="Agregar el flag HttpOnly a cookies de sesión/autenticación.",
                evidence=cookie.name, references=("OWASP HttpOnly", "CWE-1004"),
            ))

        samesite = cookie.attrs.get("samesite")
        if not samesite or (samesite == "none" and "secure" not in cookie.flags):
            out.append(self._result(
                sub_id=f"cookie_weak_samesite{suffix}", severity="low", likelihood="medium", status="fail",
                title=f"Cookie '{cookie.name}' con SameSite débil o ausente",
                finding=f"SameSite de '{cookie.name}': {samesite or 'ausente'}.",
                business_impact="Mayor exposición a CSRF / envío no intencional cross-site.",
                recommendation="Configurar SameSite=Lax o Strict (None solo junto con Secure).",
                evidence=cookie.name, references=("OWASP SameSite", "CWE-352"),
            ))

        return out
