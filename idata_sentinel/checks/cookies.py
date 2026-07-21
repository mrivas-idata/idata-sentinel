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
        targets = ctx.audit_targets()
        if ctx.mode == "audit" and ctx.authorized:
            targets = tuple(dict.fromkeys((*targets, *ctx.audit_endpoints)))

        for path in targets:
            outcome = await ctx.get_outcome(path)
            if not outcome.ok:
                continue
            raw_cookies = outcome.response.headers.get_list("set-cookie")
            for raw in raw_cookies:
                out.extend(self._evaluate(_parse_setcookie(raw), path, outcome.response.url.scheme))
        return out

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
