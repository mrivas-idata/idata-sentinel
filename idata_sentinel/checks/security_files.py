"""Archivos de seguridad: security.txt, robots.txt, directory listing
(plan_implementacion_escaneo_vulnerabilidades.md §2.5)."""
from __future__ import annotations

import re

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.modules.vuln_identification.context import ScanContext

_SENSITIVE_DISALLOW_RE = re.compile(
    r"disallow:\s*/?(admin|backup|config|private|db|\.git|staging|test)", re.IGNORECASE
)
_DIR_LISTING_SIGNATURES = (
    "index of /",
    "directory listing for",
    "<title>index of",
)


class SecurityFilesCheck(BaseCheck):
    id = "security_files"
    category = "Archivos de seguridad"
    modes = frozenset({"passive", "audit"})

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        out: list[CheckResult] = []
        out.extend(await self._check_security_txt(ctx))
        out.extend(await self._check_robots(ctx))
        out.extend(await self._check_directory_listing(ctx))
        return out

    async def _check_security_txt(self, ctx: ScanContext) -> list[CheckResult]:
        for candidate in ("/.well-known/security.txt", "/security.txt"):
            outcome = await ctx.get_outcome(candidate)
            if outcome.ok and outcome.response.status_code == 200:
                return [self._result(
                    sub_id="security_txt_present", severity="info", likelihood="low", status="pass",
                    title="security.txt presente", finding=f"Se encontró {candidate} (RFC 9116).",
                    business_impact="Buena práctica: facilita reporte responsable de vulnerabilidades.",
                    recommendation="Mantener actualizado (fecha de expiración, contacto).",
                    evidence=candidate, references=("RFC 9116",),
                )]
        return [self._result(
            sub_id="security_txt_missing", severity="info", likelihood="low", status="info",
            title="security.txt ausente", finding="No se encontró security.txt en las rutas estándar.",
            business_impact="No es una vulnerabilidad; es una buena práctica ausente.",
            recommendation="Publicar /.well-known/security.txt según RFC 9116.",
            evidence="/.well-known/security.txt, /security.txt", references=("RFC 9116",),
        )]

    async def _check_robots(self, ctx: ScanContext) -> list[CheckResult]:
        outcome = await ctx.get_outcome("/robots.txt")
        if not outcome.ok or outcome.response.status_code != 200:
            return []
        body = outcome.response.text
        matches = _SENSITIVE_DISALLOW_RE.findall(body)
        if not matches:
            return []
        return [self._result(
            sub_id="robots_exposes_sensitive", severity="low", likelihood="medium", status="warning",
            title="robots.txt expone rutas sensibles",
            finding=f"robots.txt declara Disallow hacia rutas potencialmente sensibles: {sorted(set(matches))}",
            business_impact="Documenta públicamente rutas de interés para un atacante (aunque no las indexa).",
            recommendation="Evitar listar rutas sensibles en robots.txt; protegerlas por autenticación/red.",
            evidence=body[:1000], references=("CWE-200",),
        )]

    async def _check_directory_listing(self, ctx: ScanContext) -> list[CheckResult]:
        out: list[CheckResult] = []
        candidate_paths: list[str] = ["/"]
        robots_outcome = await ctx.get_outcome("/robots.txt")
        if robots_outcome.ok and robots_outcome.response.status_code == 200:
            for line in robots_outcome.response.text.splitlines():
                if line.strip().lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path not in candidate_paths:
                        candidate_paths.append(path)
        if ctx.mode == "audit" and ctx.authorized:
            candidate_paths.extend(p for p in ctx.audit_paths if p not in candidate_paths)

        for path in candidate_paths:
            outcome = await ctx.get_outcome(path)
            if not outcome.ok or outcome.response.status_code != 200:
                continue
            body_lower = outcome.response.text.lower()
            if any(sig in body_lower for sig in _DIR_LISTING_SIGNATURES):
                out.append(self._result(
                    sub_id=f"directory_listing_open@{path}", severity="medium", likelihood="medium",
                    status="fail", title=f"Directory listing abierto en {path}",
                    finding=f"La respuesta de {path} contiene una firma de autoindex.",
                    business_impact="Expone estructura de archivos y posiblemente archivos no destinados a ser públicos.",
                    recommendation="Deshabilitar autoindex en el servidor web para ese directorio.",
                    evidence=outcome.response.text[:500], references=("CWE-548",),
                ))
        return out
