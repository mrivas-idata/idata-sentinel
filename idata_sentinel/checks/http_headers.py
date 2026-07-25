"""HTTP Security Headers (plan_implementacion_escaneo_vulnerabilidades.md §2.1)."""
from __future__ import annotations

import re

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.modules.vuln_identification.context import ScanContext

_VERSION_RE = re.compile(r"\d+\.\d+")


def _hsts_max_age(value: str) -> int:
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return int(match.group(1)) if match else 0


class HttpHeadersCheck(BaseCheck):
    id = "http_headers"
    category = "HTTP Headers"
    modes = frozenset({"passive", "audit"})

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        out: list[CheckResult] = []
        for path in ctx.audit_targets():
            outcome = await ctx.get_outcome(path)
            if not outcome.ok:
                if outcome.error is not None:
                    out.append(
                        self._error_result(
                            sub_id=self._suffixed("http_headers_unreachable", path),
                            reason=f"No se pudo obtener {path}: {outcome.error.value}",
                        )
                    )
                continue
            out.extend(self._evaluate(outcome.response, path, ctx))
        return out

    def _suffixed(self, base: str, path: str) -> str:
        return base if path == "/" else f"{base}@{path}"

    def _evaluate(self, resp, path: str, ctx: ScanContext) -> list[CheckResult]:
        h = resp.headers
        out: list[CheckResult] = []
        evidence = "; ".join(f"{k}: {v}" for k, v in h.items())[:2000]

        # Una página de error suele no pasar por el middleware que añade las
        # cabeceras de seguridad: evaluarla produciría hallazgos que no
        # describen el sitio real. Se reportan igual, pero con la advertencia
        # por delante para que nadie lea el score sin este contexto.
        if resp.status_code >= 400:
            out.append(self._result(
                sub_id=self._suffixed("response_is_an_error_page", path),
                severity="info", likelihood="low", status="info",
                title=f"El objetivo respondió HTTP {resp.status_code} en {path}",
                finding=(
                    f"La respuesta analizada es un error HTTP {resp.status_code}, no la página "
                    f"esperada. Los hallazgos de cabeceras de esta ruta describen esa respuesta "
                    f"de error y podrían no reflejar la configuración real del sitio."
                ),
                business_impact=(
                    "El diagnóstico de esta ruta pierde representatividad. Suele indicar un WAF "
                    "que filtra el tráfico automatizado o una restricción del servidor."
                ),
                recommendation=(
                    "Permitir el User-Agent de IDATA Sentinel durante la ventana de escaneo y "
                    "repetir el diagnóstico para obtener resultados representativos."
                ),
                evidence=evidence, references=(),
            ))

        if resp.url.scheme == "https":
            hsts = h.get("strict-transport-security")
            if not hsts:
                out.append(self._result(
                    sub_id=self._suffixed("hsts_missing", path), severity="medium", likelihood="high",
                    status="fail", title="Falta cabecera HSTS",
                    finding=f"El servidor no envía Strict-Transport-Security en {path}.",
                    business_impact="Riesgo de degradación a HTTP y robo de sesión en redes hostiles.",
                    recommendation="Configurar HSTS max-age >= 31536000; includeSubDomains.",
                    evidence=evidence, references=("OWASP HSTS", "CWE-319"),
                ))
            elif _hsts_max_age(hsts) < 31536000 or "includesubdomains" not in hsts.lower():
                out.append(self._result(
                    sub_id=self._suffixed("hsts_weak", path), severity="low", likelihood="medium",
                    status="warning", title="HSTS configurado de forma parcial",
                    finding=f"HSTS presente pero con max-age insuficiente o sin includeSubDomains: {hsts}",
                    business_impact="Ventana de exposición a downgrade HTTP en subdominios o tras expirar.",
                    recommendation="Usar max-age >= 31536000; includeSubDomains.",
                    evidence=hsts, references=("OWASP HSTS",),
                ))

        csp = h.get("content-security-policy")
        if not csp:
            out.append(self._result(
                sub_id=self._suffixed("csp_missing", path), severity="medium", likelihood="medium",
                status="fail", title="Falta Content-Security-Policy",
                finding=f"El servidor no envía CSP en {path}.",
                business_impact="Sin mitigación de XSS/inyección de contenido a nivel de navegador.",
                recommendation="Definir una política CSP restrictiva (default-src 'self' como base).",
                evidence=evidence, references=("OWASP CSP", "CWE-79"),
            ))
        elif re.search(r"unsafe-inline|unsafe-eval", csp, re.IGNORECASE) or "default-src *" in csp:
            out.append(self._result(
                sub_id=self._suffixed("csp_unsafe", path), severity="low", likelihood="medium",
                status="warning", title="CSP presente pero laxa",
                finding=f"La política CSP incluye directivas permisivas: {csp[:300]}",
                business_impact="La CSP no mitiga XSS de forma efectiva con estas directivas.",
                recommendation="Evitar 'unsafe-inline'/'unsafe-eval' y comodines en default-src.",
                evidence=csp[:500], references=("OWASP CSP",),
            ))

        xfo = h.get("x-frame-options")
        frame_ancestors = csp and "frame-ancestors" in csp.lower()
        if not xfo and not frame_ancestors:
            out.append(self._result(
                sub_id=self._suffixed("xfo_missing", path), severity="medium", likelihood="medium",
                status="fail", title="Falta protección contra clickjacking",
                finding=f"Ni X-Frame-Options ni CSP frame-ancestors están presentes en {path}.",
                business_impact="El sitio puede ser embebido en un iframe malicioso (clickjacking).",
                recommendation="Configurar X-Frame-Options: DENY/SAMEORIGIN o CSP frame-ancestors.",
                evidence=evidence, references=("OWASP Clickjacking", "CWE-1021"),
            ))

        if not h.get("x-content-type-options"):
            out.append(self._result(
                sub_id=self._suffixed("xcto_missing", path), severity="low", likelihood="medium",
                status="fail", title="Falta X-Content-Type-Options",
                finding=f"El servidor no envía X-Content-Type-Options: nosniff en {path}.",
                business_impact="El navegador puede interpretar (\"sniff\") contenido de forma insegura.",
                recommendation="Configurar X-Content-Type-Options: nosniff.",
                evidence=evidence, references=("CWE-116",),
            ))

        if not h.get("referrer-policy"):
            out.append(self._result(
                sub_id=self._suffixed("referrer_policy_missing", path), severity="low", likelihood="low",
                status="fail", title="Falta Referrer-Policy",
                finding=f"El servidor no envía Referrer-Policy en {path}.",
                business_impact="Posible fuga de URLs/parámetros sensibles vía el header Referer.",
                recommendation="Configurar Referrer-Policy (p.ej. strict-origin-when-cross-origin).",
                evidence=evidence, references=("OWASP Referrer Policy",),
            ))

        if not h.get("permissions-policy"):
            out.append(self._result(
                sub_id=self._suffixed("permissions_policy_missing", path), severity="info", likelihood="low",
                status="info", title="Falta Permissions-Policy",
                finding=f"El servidor no envía Permissions-Policy en {path}.",
                business_impact="Buena práctica de hardening ausente; impacto directo bajo.",
                recommendation="Configurar Permissions-Policy restringiendo APIs no usadas.",
                evidence=evidence, references=(),
            ))

        server = h.get("server", "")
        if server and _VERSION_RE.search(server):
            out.append(self._result(
                sub_id=self._suffixed("server_version_disclosure", path), severity="low", likelihood="medium",
                status="warning", title="La cabecera Server expone versión",
                finding=f"Server: {server}",
                business_impact="Facilita el reconocimiento dirigido de vulnerabilidades conocidas.",
                recommendation="Ocultar o genericizar la cabecera Server.",
                evidence=server, references=("CWE-200",),
            ))

        for header_name in ("x-powered-by", "x-aspnet-version", "x-generator"):
            value = h.get(header_name)
            if value and (_VERSION_RE.search(value) or header_name != "x-generator"):
                out.append(self._result(
                    sub_id=self._suffixed(f"powered_by_disclosure_{header_name}", path),
                    severity="low", likelihood="medium", status="warning",
                    title=f"La cabecera {header_name} expone información de plataforma",
                    finding=f"{header_name}: {value}",
                    business_impact="Facilita el reconocimiento dirigido de vulnerabilidades conocidas.",
                    recommendation=f"Eliminar o genericizar la cabecera {header_name}.",
                    evidence=value, references=("CWE-200",),
                ))

        return out
