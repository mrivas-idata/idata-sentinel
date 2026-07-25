"""Hallazgos derivados del inventario de activos (plan maestro §4 — Módulo 2).

Estos checks no hacen I/O: reciben el `AssetProfile` ya construido por el runner
del módulo y lo evalúan. Eso los vuelve funciones deterministas y testeables
100% offline, y garantiza que cada activo se toca una sola vez en red.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from idata_sentinel.core.check_base import BaseCheck, CheckResult

if TYPE_CHECKING:
    from idata_sentinel.modules.asset_inventory.context import AssetProfile


class SubdomainTakeoverCheck(BaseCheck):
    """Riesgo de apropiación de subdominio por CNAME colgante. Detección pura:
    ver la nota legal en `checks/takeover.py`."""

    id = "subdomain_takeover"
    category = "Superficie de ataque"
    module = "asset_inventory"

    async def run(self, ctx) -> list[CheckResult]:  # pragma: no cover - no aplica
        raise NotImplementedError("Se invoca vía evaluate(profile).")

    def evaluate(self, profile: "AssetProfile") -> list[CheckResult]:
        signal = profile.takeover
        if signal is None:
            return []
        motivo = (
            "el destino del CNAME no resuelve (NXDOMAIN)"
            if signal.reason == "nxdomain"
            else "el proveedor responde con su página de recurso no reclamado"
        )
        return [self._result(
            sub_id=f"subdomain_takeover_risk@{profile.host}",
            severity="high", likelihood="medium", status="fail",
            title=f"Riesgo de apropiación del subdominio {profile.host}",
            finding=(
                f"{profile.host} apunta por CNAME a {signal.cname} ({signal.service}) y "
                f"{motivo}. Un tercero podría registrar ese recurso y servir contenido "
                f"bajo el dominio de la organización."
            ),
            business_impact=(
                "Un atacante podría publicar phishing o malware en un subdominio legítimo "
                "de la empresa, con certificado válido y confianza total del usuario. "
                "El daño reputacional es inmediato y difícil de revertir."
            ),
            recommendation=(
                f"Eliminar el registro CNAME de {profile.host} si el servicio ya no se usa, "
                f"o volver a reclamar el recurso en {signal.service}."
            ),
            evidence=f"CNAME {profile.host} -> {signal.cname}; motivo: {signal.reason}",
            references=("CWE-350", "OWASP WSTG-CONF-10"),
        )]


class AssetExposureCheck(BaseCheck):
    """Exposición del activo: entornos no productivos publicados, ausencia de
    HTTPS, filtración de versión y de la IP de origen tras el CDN."""

    id = "asset_exposure"
    category = "Exposición de activos"
    module = "asset_inventory"

    async def run(self, ctx) -> list[CheckResult]:  # pragma: no cover - no aplica
        raise NotImplementedError("Se invoca vía evaluate(profile).")

    def evaluate(self, profile: "AssetProfile") -> list[CheckResult]:
        from idata_sentinel.modules.asset_inventory.context import is_non_production

        if not profile.reachable:
            return []

        out: list[CheckResult] = []

        marker = is_non_production(profile.host)
        if marker:
            out.append(self._result(
                sub_id=f"non_production_asset_exposed@{profile.host}",
                severity="medium", likelihood="medium", status="fail",
                title=f"Entorno no productivo expuesto a Internet: {profile.host}",
                finding=(
                    f"El activo {profile.host} responde públicamente (HTTP {profile.status_code}) "
                    f"y su nombre indica un entorno '{marker}'."
                ),
                business_impact=(
                    "Los entornos de prueba suelen tener datos reales, credenciales por defecto y "
                    "menos hardening que producción: son la puerta de entrada preferida del atacante."
                ),
                recommendation=(
                    "Restringir el acceso por IP/VPN o autenticación, o retirarlo de Internet si ya no se usa."
                ),
                evidence=f"{profile.scheme}://{profile.host} -> HTTP {profile.status_code}"
                         + (f" — «{profile.title}»" if profile.title else ""),
                references=("OWASP WSTG-CONF-05",),
            ))

        if profile.scheme == "http":
            out.append(self._result(
                sub_id=f"asset_without_https@{profile.host}",
                severity="high", likelihood="high", status="fail",
                title=f"Activo servido sin HTTPS: {profile.host}",
                finding=f"{profile.host} respondió por HTTP y no fue posible establecer HTTPS.",
                business_impact=(
                    "Todo el tráfico viaja en claro: credenciales, sesiones y datos personales "
                    "quedan expuestos a cualquiera en la misma red, con implicancias directas "
                    "para la Ley 21.719."
                ),
                recommendation="Emitir certificado (p. ej. Let's Encrypt) y forzar redirección 301 a HTTPS.",
                evidence=f"http://{profile.host} -> HTTP {profile.status_code}",
                references=("CWE-319",),
            ))

        for detection in profile.technologies:
            if detection.version:
                out.append(self._result(
                    sub_id=f"asset_tech_version_disclosure@{profile.host}:{detection.product}",
                    severity="low", likelihood="medium", status="warning",
                    title=f"{detection.product} {detection.version} expuesto en {profile.host}",
                    finding=(
                        f"El activo revela la versión exacta de {detection.product} "
                        f"({detection.version}) en sus respuestas."
                    ),
                    business_impact=(
                        "Permite al atacante buscar exploits públicos para esa versión concreta "
                        "sin tener que probar nada contra el servidor."
                    ),
                    recommendation="Suprimir las cabeceras/marcas que exponen la versión del producto.",
                    evidence=f"{detection.product} {detection.version} en {profile.host}",
                    references=("CWE-200",),
                ))

        if profile.origin_leak:
            out.append(self._result(
                sub_id=f"origin_ip_leak@{profile.host}",
                severity="medium", likelihood="medium", status="warning",
                title=f"Cabecera revela la infraestructura interna de {profile.host}",
                finding=f"Se observó una cabecera con una IP privada del backend: {profile.origin_leak}",
                business_impact=(
                    "Facilita saltarse el CDN/WAF atacando el origen directamente, anulando la "
                    "inversión en protección perimetral."
                ),
                recommendation="Quitar esas cabeceras de la respuesta pública en el balanceador o proxy.",
                evidence=profile.origin_leak,
                references=("CWE-200",),
            ))

        return out
