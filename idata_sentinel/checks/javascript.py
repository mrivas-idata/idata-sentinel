"""Análisis pasivo del JavaScript y los recursos servidos.

Todo es lectura de contenido público: el HTML y los scripts que el servidor ya
entrega a cualquier navegador. Cubre cuatro frentes de alto impacto:

- **Mixed content:** una página HTTPS que carga recursos por HTTP.
- **SRI ausente:** scripts/estilos de terceros sin `integrity`.
- **Source maps expuestos:** un `.map` accesible revela el código fuente.
- **Secretos incrustados:** claves de API/tokens dejados en el JS servido.
- **Librerías desactualizadas:** versión de la librería (jQuery, etc.) → capa CVE.

Los dos primeros se leen del HTML ya descargado (cero requests extra). Los demás
requieren descargar el JS del propio sitio, acotado a `_MAX_JS_FETCHES` archivos
y respetando el rate limit y el tope de requests por dominio.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from idata_sentinel.checks.tech_fingerprint import cve_result_kwargs
from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.modules.vuln_identification.context import ScanContext

#: Tope de archivos JS del propio sitio que se descargan para inspección profunda.
_MAX_JS_FETCHES = 8

_SCRIPT_SRC = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*[\"']([^\"']+)[\"'][^>]*>", re.IGNORECASE)
_LINK_TAG = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_INTEGRITY = re.compile(r"\bintegrity\s*=", re.IGNORECASE)
_ATTR_SRC = re.compile(r"\b(?:src|href)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_ACTIVE_HTTP = re.compile(
    r"<(?:script|iframe)\b[^>]*?\b(?:src)\s*=\s*[\"'](http://[^\"']+)[\"']", re.IGNORECASE)
_PASSIVE_HTTP = re.compile(
    r"<(?:img|link|audio|video|source)\b[^>]*?\b(?:src|href)\s*=\s*[\"'](http://[^\"']+)[\"']",
    re.IGNORECASE)
_SOURCEMAP = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)", re.IGNORECASE)

#: Patrones de secretos de alta confianza (proveedor específico). Se excluyen a
#: propósito los valores públicos por diseño (Stripe `pk_live`, client-id de
#: Google OAuth), que darían falsos positivos.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Stripe secret key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}")),
    ("clave privada", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
)

#: Librerías JS reconocibles por nombre de archivo → slug para la capa CVE.
_JS_LIBRARIES: tuple[tuple[str, re.Pattern], ...] = (
    ("jquery", re.compile(r"jquery[.-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("jquery-ui", re.compile(r"jquery[.-]ui[.-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("angular", re.compile(r"angular[.-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("bootstrap", re.compile(r"bootstrap[.-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("vue", re.compile(r"vue[.-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("react", re.compile(r"react[.-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("lodash", re.compile(r"lodash[.-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("moment", re.compile(r"moment[.-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("dompurify", re.compile(r"(?:purify|dompurify)[.-]?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
)


def _same_origin(url: str, page_host: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host == "" or host == page_host.lower()


def _redact_secret(match: str) -> str:
    """Nunca se vuelca el secreto completo: primeros y últimos caracteres."""
    if len(match) <= 12:
        return match[:3] + "…"
    return f"{match[:6]}…{match[-4:]} ({len(match)} chars)"


def detect_js_libraries(url: str) -> list[tuple[str, str]]:
    """(slug, versión) de librerías reconocibles en el nombre del recurso."""
    found: list[tuple[str, str]] = []
    for slug, pattern in _JS_LIBRARIES:
        m = pattern.search(url)
        if m:
            found.append((slug, m.group(1)))
    return found


def find_secrets(text: str) -> list[tuple[str, str]]:
    """(etiqueta, coincidencia redactada) de secretos de alta confianza."""
    out: list[tuple[str, str]] = []
    for label, pattern in _SECRET_PATTERNS:
        m = pattern.search(text)
        if m:
            out.append((label, _redact_secret(m.group(0))))
    return out


class JavaScriptCheck(BaseCheck):
    id = "javascript"
    category = "JavaScript y recursos"
    modes = frozenset({"passive", "audit"})

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        outcome = await ctx.get_outcome("/")
        if not outcome.ok:
            return [self._error_result(
                sub_id="javascript_unreachable",
                reason="No se pudo obtener la página raíz para analizar el JavaScript.",
            )]
        resp = outcome.response
        html = resp.text or ""
        page_url = str(resp.url)
        page_host = urlparse(page_url).hostname or ctx.host
        https_page = urlparse(page_url).scheme == "https"

        out: list[CheckResult] = []
        out.extend(self._mixed_content(html, https_page))
        out.extend(self._sri(html, page_host))
        out.extend(self._library_versions(html))
        out.extend(await self._deep_js(ctx, html, page_url, page_host))
        return out

    # -- desde el HTML (sin requests extra) --------------------------------

    def _mixed_content(self, html: str, https_page: bool) -> list[CheckResult]:
        if not https_page:
            return []
        out: list[CheckResult] = []
        active = sorted({m.group(1) for m in _ACTIVE_HTTP.finditer(html)})
        passive = sorted({m.group(1) for m in _PASSIVE_HTTP.finditer(html)})
        if active:
            out.append(self._result(
                sub_id="mixed_content_active", severity="high", likelihood="medium", status="fail",
                title="Contenido activo mixto (script/iframe por HTTP en página HTTPS)",
                finding=f"La página HTTPS carga {len(active)} recurso(s) activo(s) por HTTP.",
                business_impact="Un atacante en red puede alterar el script/iframe cargado por HTTP y "
                                "ejecutar código en el contexto de la página segura: compromiso total.",
                recommendation="Servir todos los recursos activos por HTTPS.",
                evidence="; ".join(active[:5]), references=("CWE-311", "OWASP Mixed Content"),
            ))
        if passive:
            out.append(self._result(
                sub_id="mixed_content_passive", severity="low", likelihood="low", status="warning",
                title="Contenido pasivo mixto (imágenes/estilos por HTTP en página HTTPS)",
                finding=f"La página HTTPS carga {len(passive)} recurso(s) pasivo(s) por HTTP.",
                business_impact="Rompe el candado de seguridad y permite manipular recursos visuales; "
                                "los navegadores modernos suelen bloquearlos.",
                recommendation="Servir imágenes y estilos por HTTPS.",
                evidence="; ".join(passive[:5]), references=("OWASP Mixed Content",),
            ))
        return out

    def _sri(self, html: str, page_host: str) -> list[CheckResult]:
        missing: list[str] = []
        for m in _SCRIPT_SRC.finditer(html):
            tag, src = m.group(0), m.group(1)
            if not _same_origin(src, page_host) and not _INTEGRITY.search(tag):
                missing.append(src)
        for m in _LINK_TAG.finditer(html):
            tag = m.group(0)
            if "stylesheet" not in tag.lower():
                continue
            src_m = _ATTR_SRC.search(tag)
            if src_m and not _same_origin(src_m.group(1), page_host) and not _INTEGRITY.search(tag):
                missing.append(src_m.group(1))
        if not missing:
            return []
        return [self._result(
            sub_id="sri_missing", severity="low", likelihood="low", status="warning",
            title="Recursos de terceros sin Subresource Integrity (SRI)",
            finding=f"{len(missing)} recurso(s) de terceros se cargan sin atributo 'integrity'.",
            business_impact="Si el CDN o el tercero es comprometido, se ejecuta código arbitrario en "
                            "el sitio sin que el navegador lo detecte.",
            recommendation="Agregar 'integrity' (hash SRI) y 'crossorigin' a scripts/estilos de terceros.",
            evidence="; ".join(sorted(set(missing))[:5]), references=("CWE-353", "OWASP SRI"),
        )]

    def _library_versions(self, html: str) -> list[CheckResult]:
        out: list[CheckResult] = []
        seen: set[tuple[str, str]] = set()
        for m in _SCRIPT_SRC.finditer(html):
            for slug, version in detect_js_libraries(m.group(1)):
                if (slug, version) in seen:
                    continue
                seen.add((slug, version))
                out.append(self._result(
                    sub_id=f"js_library_detected@{slug}:{version}",
                    severity="info", likelihood="low", status="info",
                    title=f"Librería JS detectada: {slug} {version}",
                    finding=f"El sitio carga {slug} {version}.",
                    business_impact="Inventario; una librería desactualizada puede arrastrar CVEs conocidas.",
                    recommendation=f"Verificar que {slug} esté en su última versión soportada.",
                    evidence=m.group(1)[:200], references=(),
                ))
                out.extend(self._cve_for_library(slug, version))
        return out

    def _cve_for_library(self, slug: str, version: str) -> list[CheckResult]:
        return [self._result(**kw) for kw in cve_result_kwargs(slug, version)]

    # -- descargando el JS del propio sitio (acotado) ----------------------

    async def _deep_js(self, ctx: ScanContext, html: str, page_url: str, page_host: str) -> list[CheckResult]:
        same_origin_scripts = [
            urljoin(page_url, m.group(1))
            for m in _SCRIPT_SRC.finditer(html)
            if _same_origin(m.group(1), page_host)
        ]
        out: list[CheckResult] = []
        for js_url in list(dict.fromkeys(same_origin_scripts))[:_MAX_JS_FETCHES]:
            outcome = await ctx.get_outcome(js_url)
            if not outcome.ok:
                continue
            body = outcome.response.text or ""
            out.extend(self._secrets_in(body, js_url))
            out.extend(await self._source_map(ctx, body, js_url))
        return out

    def _secrets_in(self, body: str, js_url: str) -> list[CheckResult]:
        out: list[CheckResult] = []
        for label, redacted in find_secrets(body):
            out.append(self._result(
                sub_id=f"secret_in_javascript@{label}:{js_url.rsplit('/', 1)[-1]}",
                severity="high", likelihood="medium", status="fail",
                title=f"Posible secreto incrustado en JavaScript: {label}",
                finding=f"El script {js_url} contiene un valor con forma de {label}.",
                business_impact="Una credencial servida al navegador es pública: cualquiera la extrae y "
                                "la usa. Puede dar acceso a servicios de pago, datos o infraestructura.",
                recommendation="Revocar y rotar la credencial; moverla al backend y no exponerla en el cliente.",
                evidence=f"{label}: {redacted}", references=("CWE-798", "OWASP Secrets"),
            ))
        return out

    async def _source_map(self, ctx: ScanContext, body: str, js_url: str) -> list[CheckResult]:
        m = _SOURCEMAP.search(body)
        if not m:
            return []
        map_ref = m.group(1).strip()
        if map_ref.startswith("data:"):
            return []  # inline: no expone un archivo adicional
        map_url = urljoin(js_url, map_ref)
        outcome = await ctx.get_outcome(map_url)
        if not outcome.ok or outcome.response.status_code != 200:
            return []
        text = outcome.response.text or ""
        if '"sources"' not in text and '"mappings"' not in text:
            return []
        return [self._result(
            sub_id=f"source_map_exposed@{map_url.rsplit('/', 1)[-1]}",
            severity="medium", likelihood="medium", status="fail",
            title="Source map accesible: código fuente expuesto",
            finding=f"El source map {map_url} responde 200 y expone el código fuente original del script.",
            business_impact="El código fuente sin minificar revela lógica de negocio, rutas internas, "
                            "endpoints y a veces comentarios o credenciales que el bundle ocultaba.",
            recommendation="No publicar los archivos .map en producción, o restringir su acceso.",
            evidence=map_url, references=("CWE-540",),
        )]
